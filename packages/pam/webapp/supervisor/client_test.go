package supervisor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func serveUnix(t *testing.T, h http.Handler) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "iwa-sup")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s.sock")
	ln, err := net.Listen("unix", sock)
	require.NoError(t, err)
	srv := &http.Server{Handler: h}
	go srv.Serve(ln) //nolint:errcheck
	t.Cleanup(func() { srv.Close() })
	return sock
}

func writeErr(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": code}})
}

func TestLaunchStatusCodes(t *testing.T) {
	var mu sync.Mutex
	var got LaunchRequest
	next := map[string]struct {
		status int
		code   string
	}{
		"s-403": {http.StatusForbidden, CodeImageNotAllowed},
		"s-409": {http.StatusConflict, CodeAlreadyExists},
		"s-429": {http.StatusTooManyRequests, CodeCapacityExhausted},
		"s-500": {http.StatusInternalServerError, CodeRuntimeError},
	}
	destroyed := map[string]int{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/runners", func(w http.ResponseWriter, r *http.Request) {
		var req LaunchRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		mu.Lock()
		got = req
		mu.Unlock()
		if e, ok := next[req.SessionID]; ok {
			writeErr(w, e.status, e.code)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(LaunchResponse{SessionID: req.SessionID, ContainerName: "iwa-runner-x", IP: "172.28.0.11", State: "starting"})
	})
	mux.HandleFunc("DELETE /v1/runners/{id}", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		destroyed[r.PathValue("id")]++
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"state": "destroyed"})
	})
	mux.HandleFunc("GET /v1/runners/{id}", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, http.StatusNotFound, CodeNotFound)
	})
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(HealthResponse{OK: true, Network: "iwa-runners", HostAddress: "172.28.0.1", MaxRunners: 4})
	})
	c := NewClient(serveUnix(t, mux))
	ctx := context.Background()

	token, err := NewRunnerToken()
	require.NoError(t, err)
	raw, err := base64.RawURLEncoding.DecodeString(token)
	require.NoError(t, err)
	require.Len(t, raw, 32)

	resp, err := c.Launch(ctx, LaunchRequest{SessionID: "ok", RunnerToken: token, AllowedHosts: []string{"app.corp.internal"}})
	require.NoError(t, err)
	require.Equal(t, "172.28.0.11", resp.IP)
	mu.Lock()
	require.Equal(t, token, got.RunnerToken)
	mu.Unlock()

	for id, e := range next {
		_, err := c.Launch(ctx, LaunchRequest{SessionID: id})
		require.Error(t, err)
		require.True(t, IsCode(err, e.code), "%s: %v", id, err)
		var se *Error
		require.ErrorAs(t, err, &se)
		require.Equal(t, e.status, se.Status)
	}

	require.NoError(t, c.Destroy(ctx, "ok"))
	require.NoError(t, c.Destroy(ctx, "ok"))
	mu.Lock()
	require.Equal(t, 2, destroyed["ok"])
	mu.Unlock()

	_, err = c.Status(ctx, "missing")
	require.True(t, IsCode(err, CodeNotFound))

	h, err := c.Health(ctx)
	require.NoError(t, err)
	require.Equal(t, "172.28.0.1", h.HostAddress)
}

func TestHealthUnreachable(t *testing.T) {
	c := NewClient(filepath.Join(t.TempDir(), "absent.sock"))
	_, err := c.Health(context.Background())
	require.Error(t, err)
}
