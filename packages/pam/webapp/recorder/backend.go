package recorder

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/go-resty/resty/v2"
)

// Backend is the gateway side of CONTRACTS.md 6.8 and 6.9 for one session.
type Backend interface {
	Open(ctx context.Context, req OpenRequest) error
	Presign(ctx context.Context, req PresignRequest) (*PresignResponse, error)
	// Put uploads the stored object with exactly the presigned headers. It returns ErrPreconditionFailed on 412.
	Put(ctx context.Context, p *PresignResponse, stored []byte) (versionID string, err error)
	SubmitCheckpoint(ctx context.Context, req CheckpointRequest) error
	End(ctx context.Context, req EndRequest) error
}

type OpenRequest struct {
	RecordingPublicKey string `json:"recordingPublicKey"`
	Fingerprint        string `json:"fingerprint"`
	KeyCert            string `json:"keyCert"`
	KeyCertSig         string `json:"keyCertSig"`
}

type PresignRequest struct {
	Series           string `json:"series"`
	ObjectIndex      uint32 `json:"objectIndex"`
	Kind             string `json:"kind"`
	CiphertextBytes  int    `json:"ciphertextBytes"`
	CiphertextSha256 string `json:"ciphertextSha256"`
}

type PresignResponse struct {
	URL              string            `json:"url"`
	ObjectKey        string            `json:"objectKey"`
	Method           string            `json:"method"`
	Headers          map[string]string `json:"headers"`
	ExpiresInSeconds int               `json:"expiresInSeconds"`
}

type CheckpointRequest struct {
	Checkpoint string `json:"checkpoint"`
	Signature  string `json:"signature"`
	ObjectKey  string `json:"objectKey"`
	VersionID  string `json:"versionId"`
}

type EndRequest struct {
	FinalSeq uint64 `json:"finalSeq"`
	Reason   string `json:"reason"`
}

// ErrPreconditionFailed is a 412 on PUT: the object key already exists (CONTRACTS.md 6.8).
var ErrPreconditionFailed = errors.New("recorder: object already exists (412)")

// APIError is a non-2xx answer from the backend.
type APIError struct {
	Op     string
	Status int
	Code   string
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("recorder: %s: backend answered %d %s", e.Op, e.Status, e.Code)
}

func statusOf(err error) int {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.Status
	}
	return 0
}

// HTTPBackend calls the Infisical backend with the per-session upload token and PUTs objects to S3.
type HTTPBackend struct {
	BaseURL     string // config.INFISICAL_URL (already ends in /api)
	SessionID   string
	UploadToken string
	API         *resty.Client
	// S3 is a plain client: the gateway's API auth headers must never reach the object store.
	S3 *http.Client
}

func NewHTTPBackend(baseURL, sessionID, uploadToken string, apiClient *resty.Client) *HTTPBackend {
	return &HTTPBackend{
		BaseURL:     baseURL,
		SessionID:   sessionID,
		UploadToken: uploadToken,
		API:         apiClient,
		S3:          &http.Client{Timeout: 2 * time.Minute},
	}
}

func (b *HTTPBackend) post(ctx context.Context, op, path string, body, out any) error {
	req := b.API.R().
		SetContext(ctx).
		SetHeader("User-Agent", api.USER_AGENT).
		SetHeader("X-Gateway-Upload-Token", b.UploadToken).
		SetBody(body)
	resp, err := req.Post(fmt.Sprintf("%s/v1/pam/sessions/%s/web-app/%s", b.BaseURL, b.SessionID, path))
	if err != nil {
		return fmt.Errorf("recorder: %s: %w", op, err)
	}
	if resp.IsError() {
		var e struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(resp.Body(), &e)
		code := e.Code
		if code == "" {
			code = e.Message
		}
		return &APIError{Op: op, Status: resp.StatusCode(), Code: code, Body: truncate(resp.String(), 512)}
	}
	if out != nil {
		if err := json.Unmarshal(resp.Body(), out); err != nil {
			return fmt.Errorf("recorder: %s: decode response: %w", op, err)
		}
	}
	return nil
}

func (b *HTTPBackend) Open(ctx context.Context, req OpenRequest) error {
	return b.post(ctx, "open", "open", req, nil)
}

func (b *HTTPBackend) Presign(ctx context.Context, req PresignRequest) (*PresignResponse, error) {
	var out PresignResponse
	if err := b.post(ctx, "presign", "objects/presign", req, &out); err != nil {
		return nil, err
	}
	if out.URL == "" {
		return nil, errors.New("recorder: presign returned no url")
	}
	return &out, nil
}

func (b *HTTPBackend) SubmitCheckpoint(ctx context.Context, req CheckpointRequest) error {
	return b.post(ctx, "checkpoint", "checkpoints", req, nil)
}

func (b *HTTPBackend) End(ctx context.Context, req EndRequest) error {
	return b.post(ctx, "end", "end", req, nil)
}

func (b *HTTPBackend) Put(ctx context.Context, p *PresignResponse, stored []byte) (string, error) {
	return PutPresigned(ctx, b.S3, p, stored)
}

// PutPresigned PUTs stored bytes to a presigned URL with exactly the returned headers plus Content-Length.
func PutPresigned(ctx context.Context, client *http.Client, p *PresignResponse, stored []byte) (string, error) {
	method := p.Method
	if method == "" {
		method = http.MethodPut
	}
	req, err := http.NewRequestWithContext(ctx, method, p.URL, bytes.NewReader(stored))
	if err != nil {
		return "", err
	}
	req.ContentLength = int64(len(stored))
	for k, v := range p.Headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("recorder: PUT: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusPreconditionFailed {
		return "", ErrPreconditionFailed
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", &APIError{Op: "put", Status: resp.StatusCode, Body: truncate(string(body), 512)}
	}
	return resp.Header.Get("x-amz-version-id"), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
