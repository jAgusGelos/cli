//go:build webapp_minio

package recorder

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/webapp/contract"
	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// TestMinIOPut PUTs one sealed V object to F6's MinIO (Object Lock bucket) through a SigV4 presigned URL that signs
// the checksum and If-None-Match, as the backend presign does (CONTRACTS.md 6.8). Run with:
// IWA_MINIO=1 go test -count=1 -tags webapp_minio -run TestMinIOPut ./packages/pam/webapp/recorder/
func TestMinIOPut(t *testing.T) {
	if os.Getenv("IWA_MINIO") != "1" {
		t.Skip("IWA_MINIO=1 not set")
	}
	envFile := os.Getenv("IWA_MINIO_ENV")
	if envFile == "" {
		envFile = "/home/agus/Escritorio/Infisical/demo/webapp/state/minio.env"
	}
	env := map[string]string{}
	f, err := os.Open(envFile)
	require.NoError(t, err)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok && !strings.HasPrefix(k, "#") {
			env[k] = v
		}
	}
	f.Close()

	key := make([]byte, 32)
	_, _ = rand.Read(key)
	projectID, sessionID := uuid.NewString(), uuid.NewString()
	plaintext := []byte("fake fMP4 init segment for the MinIO check")
	stored, err := contract.SealObject(key, nil, plaintext, contract.BuildAAD(projectID, sessionID, contract.SeriesV, 0))
	require.NoError(t, err)
	sum := sha256.Sum256(stored)
	checksum := base64.StdEncoding.EncodeToString(sum[:])
	objectKey := contract.ObjectKey("", projectID, sessionID, contract.SeriesV, contract.KindVideoInit, 0)
	url := fmt.Sprintf("%s/%s/%s", env["MINIO_ENDPOINT"], env["MINIO_BUCKET"], objectKey)

	req, err := http.NewRequest(http.MethodPut, url, nil)
	require.NoError(t, err)
	req.Header.Set("x-amz-checksum-sha256", checksum)
	req.Header.Set("If-None-Match", "*")
	creds := aws.Credentials{AccessKeyID: env["MINIO_RECORDER_ACCESS_KEY"], SecretAccessKey: env["MINIO_RECORDER_SECRET_KEY"]}
	q := req.URL.Query()
	q.Set("X-Amz-Expires", "300")
	req.URL.RawQuery = q.Encode()
	signed, _, err := v4.NewSigner(func(o *v4.SignerOptions) { o.DisableHeaderHoisting = true }).PresignHTTP(context.Background(), creds, req, "UNSIGNED-PAYLOAD", "s3", env["MINIO_REGION"], time.Now())
	require.NoError(t, err)
	require.Contains(t, strings.ToLower(signed), "if-none-match", "If-None-Match is signed into the URL")

	p := &PresignResponse{URL: signed, Method: http.MethodPut, Headers: map[string]string{"x-amz-checksum-sha256": checksum, "If-None-Match": "*"}}
	client := &http.Client{Timeout: 30 * time.Second}
	version, err := PutPresigned(context.Background(), client, p, stored)
	var ae *APIError
	if errors.As(err, &ae) {
		t.Fatalf("PUT %d: %s", ae.Status, ae.Body)
	}
	require.NoError(t, err)
	require.NotEmpty(t, version, "Object Lock bucket is versioned")
	t.Logf("stored %s version %s", objectKey, version)

	_, err = PutPresigned(context.Background(), client, p, stored)
	require.True(t, errors.Is(err, ErrPreconditionFailed), "second PUT of the same key answers 412: %v", err)
}
