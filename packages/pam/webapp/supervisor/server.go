// Package supervisor is the Web App runner supervisor (CONTRACTS.md section 3): a host process that launches and
// destroys runner containers with a fixed least-privilege spec, driven over HTTP/1.1 on a unix socket.
package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"
)

const (
	DefaultSocketPath = "/tmp/infisical-webapp/supervisor.sock"
	DefaultMaxRunners = 4

	EnvSocket     = "INFISICAL_WEBAPP_SUPERVISOR_SOCKET"
	EnvImages     = "INFISICAL_WEBAPP_RUNNER_IMAGES"
	EnvMaxRunners = "INFISICAL_WEBAPP_MAX_RUNNERS"

	maxBodyBytes = 64 * 1024
)

const (
	codeInvalidRequest    = "invalid_request"
	codeRuntimeError      = "runtime_error"
	codeNotFound          = "not_found"
	codeImageNotAllowed   = "image_not_allowed"
	codeAlreadyExists     = "already_exists"
	codeCapacityExhausted = "capacity_exhausted"
)

type Config struct {
	SocketPath string
	StateDir   string
	Images     []string // allowlist of name@sha256:<id>
	MaxRunners int
	Logger     *log.Logger
}

// ConfigFromEnv reads the supervisor configuration from the environment.
func ConfigFromEnv() (Config, error) {
	cfg := Config{SocketPath: DefaultSocketPath, MaxRunners: DefaultMaxRunners}
	if v := os.Getenv(EnvSocket); v != "" {
		cfg.SocketPath = v
	}
	cfg.StateDir = filepath.Join(filepath.Dir(cfg.SocketPath), "state")
	images, err := parseAllowlist(os.Getenv(EnvImages))
	if err != nil {
		return cfg, err
	}
	cfg.Images = images
	if v := os.Getenv(EnvMaxRunners); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 200 {
			return cfg, fmt.Errorf("%s must be 1..200", EnvMaxRunners)
		}
		cfg.MaxRunners = n
	}
	return cfg, nil
}

type session struct {
	id      string
	short   string
	ip      string
	imageID string
}

type Server struct {
	cfg    Config
	docker dockerRunner
	logger *log.Logger

	mu        sync.Mutex
	pending   map[string]string // sessionId -> reserved IP ("" before one is picked)
	cancels   map[string]context.CancelFunc
	sessions  map[string]*session
	destroyed map[string]bool
}

func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = log.New(os.Stderr, "iwa-supervisor ", log.LstdFlags|log.Lmicroseconds)
	}
	if cfg.MaxRunners <= 0 {
		cfg.MaxRunners = DefaultMaxRunners
	}
	return newServer(cfg, newExecDocker(cfg.Logger))
}

func newServer(cfg Config, d dockerRunner) *Server {
	return &Server{
		cfg: cfg, docker: d, logger: cfg.Logger,
		pending: map[string]string{}, cancels: map[string]context.CancelFunc{}, sessions: map[string]*session{}, destroyed: map[string]bool{},
	}
}

// Prepare creates the runner network and the state files; called once at startup.
func (s *Server) Prepare(ctx context.Context) error {
	if err := s.writeStateFiles(); err != nil {
		return fmt.Errorf("state files: %w", err)
	}
	return ensureNetwork(ctx, s.docker)
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", s.handleHealth)
	mux.HandleFunc("POST /v1/runners", s.handleLaunch)
	mux.HandleFunc("GET /v1/runners/{sessionId}", s.handleStatus)
	mux.HandleFunc("DELETE /v1/runners/{sessionId}", s.handleDestroy)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, codeNotFound, "no such route")
	})
	return s.logRequests(mux)
}

// Listen opens the unix socket: directory 0700, socket 0600, stale socket removed, live one refused.
func Listen(path string) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
			c.Close()
			return nil, fmt.Errorf("another supervisor is listening on %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(code int) {
	w.code = code
	w.ResponseWriter.WriteHeader(code)
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(sw, r)
		s.logger.Printf("api %s %s -> %d in %s", r.Method, r.URL.Path, sw.code, time.Since(start).Round(time.Millisecond))
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, errCode, msg string) {
	writeJSON(w, code, map[string]any{"error": map[string]string{"code": errCode, "message": msg}})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if err := ensureNetwork(r.Context(), s.docker); err != nil {
		s.logger.Printf("health: %v", err)
		writeError(w, http.StatusInternalServerError, codeRuntimeError, "runner network unavailable")
		return
	}
	cs, err := s.listLabeled(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeRuntimeError, "docker unavailable")
		return
	}
	active := activeSessions(cs)
	s.mu.Lock()
	for id := range s.pending {
		active[id] = true
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "network": NetworkName, "hostAddress": HostAddress,
		"maxRunners": s.cfg.MaxRunners, "activeRunners": len(active),
	})
}

func (s *Server) imageAllowed(image string) bool {
	return slices.Contains(s.cfg.Images, image)
}

func (s *Server) handleLaunch(w http.ResponseWriter, r *http.Request) {
	var req LaunchRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "body must be a JSON object under 64 KiB")
		return
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "body must hold one JSON object")
		return
	}
	spec, err := validateLaunch(&req)
	if err != nil {
		s.logger.Printf("launch rejected: %v", err)
		writeError(w, http.StatusBadRequest, codeInvalidRequest, err.Error())
		return
	}
	if !s.imageAllowed(spec.Image) {
		s.logger.Printf("launch %s rejected: image %q not in allowlist", spec.SessionID, spec.Image)
		writeError(w, http.StatusForbidden, codeImageNotAllowed, "image is not in the supervisor allowlist")
		return
	}
	if err := s.reserve(r.Context(), spec); err != nil {
		switch {
		case errors.Is(err, errAlreadyExists):
			writeError(w, http.StatusConflict, codeAlreadyExists, "a runner for this session already exists")
		case errors.Is(err, errCapacity):
			writeError(w, http.StatusTooManyRequests, codeCapacityExhausted, "runner capacity exhausted")
		default:
			s.logger.Printf("launch %s: admission: %v", spec.SessionID, err)
			writeError(w, http.StatusInternalServerError, codeRuntimeError, "docker unavailable")
		}
		return
	}
	// The launch outlives a dropped client connection so rollback always runs to completion.
	res, err := s.launch(context.WithoutCancel(r.Context()), spec)
	if err != nil {
		s.logger.Printf("launch %s failed: %v", spec.SessionID, err)
		writeError(w, http.StatusInternalServerError, codeRuntimeError, "runner launch failed")
		return
	}
	s.logger.Printf("launch %s: %s at %s", spec.SessionID, res.ContainerName, res.IP)
	writeJSON(w, http.StatusCreated, res)
}

func sessionParam(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("sessionId")
	if !validSessionID(id) {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "sessionId must be a lowercase UUID")
		return "", false
	}
	return id, true
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	id, ok := sessionParam(w, r)
	if !ok {
		return
	}
	res, found, err := s.status(r.Context(), id)
	if err != nil {
		s.logger.Printf("status %s: %v", id, err)
		writeError(w, http.StatusInternalServerError, codeRuntimeError, "docker unavailable")
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, codeNotFound, "unknown session")
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleDestroy(w http.ResponseWriter, r *http.Request) {
	id, ok := sessionParam(w, r)
	if !ok {
		return
	}
	// A destroy during a launch aborts it; the launch rolls back whatever it already created.
	s.mu.Lock()
	if cancel, ok := s.cancels[id]; ok {
		cancel()
	}
	s.mu.Unlock()
	if err := s.removeSession(context.WithoutCancel(r.Context()), id); err != nil {
		s.logger.Printf("destroy %s: %v", id, err)
		writeError(w, http.StatusInternalServerError, codeRuntimeError, "destroy failed")
		return
	}
	s.mu.Lock()
	delete(s.sessions, id)
	s.destroyed[id] = true
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"state": stateDestroyed})
}

// ShortID exposes the container-name suffix for a session id (first 12 hex digits).
func ShortID(sessionID string) string {
	if !validSessionID(sessionID) {
		return ""
	}
	return shortID(sessionID)
}
