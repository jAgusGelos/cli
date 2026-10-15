package gatewayv2

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClickhouseTestParamsContract(t *testing.T) {
	cases := []struct {
		name           string
		payload        string
		wantHTTPPort   int
		wantNativePort int
		wantSSL        bool
	}{
		{
			name:           "both interfaces",
			payload:        `{"mode":"clickhouse","username":"default","password":"pw","database":"analytics","httpPort":8123,"nativePort":9000,"sslEnabled":false,"sslRejectUnauthorized":true}`,
			wantHTTPPort:   8123,
			wantNativePort: 9000,
		},
		{
			name:           "native only",
			payload:        `{"mode":"clickhouse","username":"default","password":"pw","database":"analytics","nativePort":9440,"sslEnabled":true,"sslRejectUnauthorized":true}`,
			wantHTTPPort:   0,
			wantNativePort: 9440,
			wantSSL:        true,
		},
		{
			name:           "http only",
			payload:        `{"mode":"clickhouse","username":"default","password":"pw","database":"analytics","httpPort":8443,"sslEnabled":true,"sslRejectUnauthorized":false}`,
			wantHTTPPort:   8443,
			wantNativePort: 0,
			wantSSL:        true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var params clickhouseTestParams
			require.NoError(t, json.Unmarshal([]byte(tc.payload), &params))

			require.Equal(t, tc.wantHTTPPort, params.HttpPort)
			require.Equal(t, tc.wantNativePort, params.NativePort)
			require.Equal(t, "default", params.Username)
			require.Equal(t, "analytics", params.Database)
			require.Equal(t, "pw", params.Password)
			require.Equal(t, tc.wantSSL, params.SslEnabled)
			require.NotNil(t, params.SslRejectUnauthorized)
		})
	}
}

func TestWebAppConnectionTest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer token", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	require.NoError(t, err)
	port, err := strconv.Atoi(parsed.Port())
	require.NoError(t, err)
	require.NoError(t, doWebAppConnectionTest(context.Background(), rpcTarget{host: parsed.Hostname(), port: port}, webAppTestParams{
		URL: server.URL, AllowedHosts: []string{parsed.Hostname()}, AuthMethod: "header", HeaderScheme: "bearer", Token: "token",
	}))
}

func TestWebAppConnectionTestRejectsTargetMismatch(t *testing.T) {
	err := doWebAppConnectionTest(context.Background(), rpcTarget{host: "signed.example", port: 80}, webAppTestParams{
		URL: "http://other.example/", AllowedHosts: []string{"other.example"}, AuthMethod: "none",
	})
	require.EqualError(t, err, "URL host does not match the signed target")
}

func TestRPCTargetAllows(t *testing.T) {
	t.Run("a certificate naming one port authorises only that port", func(t *testing.T) {
		target := rpcTarget{host: "db.internal", port: 8123}
		require.True(t, target.allows(8123))
		require.False(t, target.allows(9000))
		require.False(t, target.allows(22))
	})

	t.Run("a certificate naming several authorises each of them", func(t *testing.T) {
		target := rpcTarget{host: "db.internal", port: 8123, ports: []int{8123, 9000}}
		require.True(t, target.allows(8123))
		require.True(t, target.allows(9000))
		require.False(t, target.allows(22), "a port outside the certificate stays refused")
	})
}
