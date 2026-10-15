// Package supervisor is the gateway's client for the Web App runner supervisor (INF-WEBAPP CONTRACTS.md section 3):
// HTTP/1.1 with JSON bodies over a unix socket. The gateway never talks to a container runtime directly (D-09).
package supervisor

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Error codes returned by the supervisor (CONTRACTS.md 3.1).
const (
	CodeInvalidRequest    = "invalid_request"
	CodeImageNotAllowed   = "image_not_allowed"
	CodeAlreadyExists     = "already_exists"
	CodeCapacityExhausted = "capacity_exhausted"
	CodeRuntimeError      = "runtime_error"
	CodeNotFound          = "not_found"
)

// Error is a typed supervisor error: HTTP status plus the contract error code.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("supervisor: %d %s: %s", e.Status, e.Code, e.Message)
}

// IsCode reports whether err is a supervisor error with the given code.
func IsCode(err error, code string) bool {
	var se *Error
	return errors.As(err, &se) && se.Code == code
}

type Policy struct {
	Clipboard string `json:"clipboard"`
	Downloads string `json:"downloads"`
	Uploads   string `json:"uploads"`
	Kiosk     bool   `json:"kiosk"`
}

type Display struct {
	Width     int `json:"width"`
	Height    int `json:"height"`
	Framerate int `json:"framerate"`
}

type Recording struct {
	SegmentSeconds int `json:"segmentSeconds"`
	BitrateKbps    int `json:"bitrateKbps"`
	CRF            int `json:"crf"`
}

type Resources struct {
	CPUs      float64 `json:"cpus"`
	MemoryMb  int     `json:"memoryMb"`
	PidsLimit int     `json:"pidsLimit"`
}

type Watermark struct {
	Text string `json:"text"`
}

// LaunchRequest is the POST /v1/runners body (CONTRACTS.md 3.1).
type LaunchRequest struct {
	SessionID        string    `json:"sessionId"`
	Image            string    `json:"image"`
	RunnerToken      string    `json:"runnerToken"`
	GatewayAgentAddr string    `json:"gatewayAgentAddr"`
	EgressProxyAddr  string    `json:"egressProxyAddr"`
	StartURL         string    `json:"startUrl"`
	AllowedHosts     []string  `json:"allowedHosts"`
	CaPem            string    `json:"caPem"`
	Policy           Policy    `json:"policy"`
	Display          Display   `json:"display"`
	Recording        Recording `json:"recording"`
	Resources        Resources `json:"resources"`
	Watermark        Watermark `json:"watermark"`
}

type LaunchResponse struct {
	SessionID     string `json:"sessionId"`
	ContainerName string `json:"containerName"`
	IP            string `json:"ip"`
	State         string `json:"state"`
}

type StatusResponse struct {
	SessionID     string `json:"sessionId"`
	ContainerName string `json:"containerName"`
	IP            string `json:"ip"`
	State         string `json:"state"`
	StartedAt     string `json:"startedAt"`
	ExitCode      *int   `json:"exitCode"`
	OOMKilled     bool   `json:"oomKilled"`
}

type HealthResponse struct {
	OK            bool   `json:"ok"`
	Network       string `json:"network"`
	HostAddress   string `json:"hostAddress"`
	MaxRunners    int    `json:"maxRunners"`
	ActiveRunners int    `json:"activeRunners"`
}

// Client talks to the supervisor over its unix socket.
type Client struct {
	http *http.Client
}

// NewClient returns a client for the supervisor socket at socketPath.
func NewClient(socketPath string) *Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		},
		MaxIdleConns:    4,
		IdleConnTimeout: 30 * time.Second,
	}
	return &Client{http: &http.Client{Transport: transport, Timeout: 120 * time.Second}}
}

// NewRunnerToken returns 32 random bytes as unpadded URL-safe base64.
func NewRunnerToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (c *Client) Launch(ctx context.Context, req LaunchRequest) (*LaunchResponse, error) {
	var out LaunchResponse
	if err := c.do(ctx, http.MethodPost, "/v1/runners", req, &out, http.StatusCreated); err != nil {
		return nil, err
	}
	return &out, nil
}

// Destroy force-removes a runner. The supervisor answers 200 also when it no longer exists.
func (c *Client) Destroy(ctx context.Context, sessionID string) error {
	return c.do(ctx, http.MethodDelete, "/v1/runners/"+url.PathEscape(sessionID), nil, nil, http.StatusOK)
}

func (c *Client) Status(ctx context.Context, sessionID string) (*StatusResponse, error) {
	var out StatusResponse
	if err := c.do(ctx, http.MethodGet, "/v1/runners/"+url.PathEscape(sessionID), nil, &out, http.StatusOK); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	var out HealthResponse
	if err := c.do(ctx, http.MethodGet, "/v1/health", nil, &out, http.StatusOK); err != nil {
		return nil, err
	}
	if !out.OK {
		return &out, errors.New("supervisor: health reports not ok")
	}
	return &out, nil
}

func (c *Client) do(ctx context.Context, method, path string, body, out any, wantStatus int) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://supervisor"+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("supervisor: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != wantStatus {
		var e struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		return &Error{Status: resp.StatusCode, Code: e.Error.Code, Message: e.Error.Message}
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("supervisor: decode %s %s: %w", method, path, err)
		}
	}
	return nil
}
