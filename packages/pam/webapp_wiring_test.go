package pam

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/go-resty/resty/v2"
	"github.com/stretchr/testify/require"
)

func TestValidatePAMProxyMode(t *testing.T) {
	require.NoError(t, ValidatePAMProxyMode(PAMProxyModeWebApp, session.ResourceTypeWebApp))
	require.NoError(t, ValidatePAMProxyMode(PAMProxyModeDefault, session.ResourceTypePostgres))
	require.NoError(t, ValidatePAMProxyMode(PAMProxyModeRDPBrowser, session.ResourceTypeWindows))
	require.Error(t, ValidatePAMProxyMode(PAMProxyModeDefault, session.ResourceTypeWebApp))
	require.Error(t, ValidatePAMProxyMode(PAMProxyModeRDPBrowser, session.ResourceTypeWebApp))
	require.Error(t, ValidatePAMProxyMode(PAMProxyModeWebApp, session.ResourceTypePostgres))
	require.True(t, slices.Contains(GetSupportedResourceTypes(), session.ResourceTypeWebApp))
}

// A web-app session returns before the legacy session logger: no legacy .enc recording file is created.
func TestWebAppSessionCreatesNoLegacyRecording(t *testing.T) {
	recDir := t.TempDir()
	session.SetSessionRecordingPath(recDir)
	defer session.SetSessionRecordingPath("")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/gateways/pam-session-key" {
			_, _ = w.Write(make([]byte, 32)) // upload token persistence (existing behavior for every session)
			return
		}
		require.True(t, strings.HasSuffix(r.URL.Path, "/credentials"), r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"credentials":{"webApp":{"connectionDetails":{"url":"https://app.corp.internal/","allowedHosts":["app.corp.internal"]},"credentials":{"authMethod":"none"}}},
			"recording":{"sessionKey":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=","uploadToken":"tok","storageBackend":"aws-s3","projectId":"p","sessionId":"s"}}`))
	}))
	defer srv.Close()
	prev := config.INFISICAL_URL
	config.INFISICAL_URL = srv.URL
	defer func() { config.INFISICAL_URL = prev }()

	a, b := net.Pipe()
	defer b.Close()
	cfg := &GatewayPAMConfig{
		SessionId: "8a0c6a4e-1f7b-4e0e-9a43-5d2a6f0b9c11", ResourceType: session.ResourceTypeWebApp,
		ExpiryTime: time.Now().Add(time.Hour), CredentialsManager: session.NewCredentialsManager(resty.New()),
	}
	defer cfg.CredentialsManager.Shutdown()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := HandlePAMProxy(ctx, tls.Server(a, &tls.Config{}), cfg, resty.New(), PAMProxyModeWebApp)
	require.ErrorContains(t, err, "web app sessions are not enabled")
	require.NotNil(t, cfg.CredentialsManager.GetRecordingSecrets(cfg.SessionId))

	var legacy []string
	require.NoError(t, filepath.WalkDir(recDir, func(path string, d os.DirEntry, err error) error {
		if err == nil && strings.HasPrefix(d.Name(), "pam_session_") {
			legacy = append(legacy, path)
		}
		return err
	}))
	require.Empty(t, legacy, "no legacy session file for a web-app session")

	// The wrong ALPN for a web-app resource is refused before anything else happens.
	err = HandlePAMProxy(ctx, tls.Server(a, &tls.Config{}), cfg, resty.New(), PAMProxyModeDefault)
	require.ErrorContains(t, err, "not allowed")
}

func TestWebAppRecordingFilenameParses(t *testing.T) {
	info, err := session.ParseSessionFilename("pam_session_abc_web-app_expires_1760545800.enc")
	require.NoError(t, err)
	require.Equal(t, session.ResourceTypeWebApp, info.ResourceType)
}
