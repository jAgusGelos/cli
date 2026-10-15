package webapp

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/stretchr/testify/require"
)

func TestInjectedHeader(t *testing.T) {
	cases := []struct {
		name  string
		creds api.PAMWebAppCredentials
		want  string // "name: value"; "" when nothing is injected
		err   bool
	}{
		{"none", api.PAMWebAppCredentials{AuthMethod: "none"}, "", false},
		{"form login", api.PAMWebAppCredentials{AuthMethod: "form-login", Username: "u", Password: "p"}, "", false},
		{"basic", api.PAMWebAppCredentials{AuthMethod: authHeader, HeaderScheme: schemeBasic, Username: "corp-admin", Password: "pw"},
			"Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("corp-admin:pw")), false},
		{"bearer", api.PAMWebAppCredentials{AuthMethod: authHeader, HeaderScheme: schemeBearer, Token: "tok"}, "Authorization: Bearer tok", false},
		{"custom", api.PAMWebAppCredentials{AuthMethod: authHeader, HeaderScheme: schemeCustom, HeaderName: "X-Api-Key", HeaderValue: "k"}, "X-Api-Key: k", false},
		{"basic without password", api.PAMWebAppCredentials{AuthMethod: authHeader, HeaderScheme: schemeBasic, Username: "u"}, "", true},
		{"custom header splitting", api.PAMWebAppCredentials{AuthMethod: authHeader, HeaderScheme: schemeCustom, HeaderName: "X-A", HeaderValue: "v\r\nX-B: w"}, "", true},
		{"unknown scheme", api.PAMWebAppCredentials{AuthMethod: authHeader, HeaderScheme: "digest"}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, err := injectedHeader(tc.creds)
			if tc.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tc.want == "" {
				require.Nil(t, h)
				return
			}
			require.Equal(t, tc.want, h.Name+": "+h.Value)
		})
	}
}

func TestSecretsAndInterception(t *testing.T) {
	creds := api.PAMWebAppCredentials{AuthMethod: authHeader, HeaderScheme: schemeBasic, Username: "corp-admin", Password: "pw", Token: "", HeaderValue: "hv"}
	require.Equal(t, []string{"pw", "hv", "corp-admin:pw"}, secretsOf(creds))

	insecure := false
	wa := &api.PAMWebAppDetails{
		ConnectionDetails: api.PAMWebAppConnectionDetails{URL: "https://app.corp.internal/", AllowedHosts: []string{"app.corp.internal"}, SSLRejectUnauthorized: &insecure},
		Credentials:       creds,
	}
	cfg := resolveSettings(&api.PAMWebAppSettings{MaskedHeaders: []string{"X-Csrf"}, MaskedQueryParams: []string{"code"}})
	sc := newScrubber(wa, cfg)
	require.Equal(t, "***", sc.Headers([][]string{{"x-csrf", "v"}})[0][1])
	require.Equal(t, "/cb?code=***", sc.URL("/cb?code=abc"))

	l1, err := newInterception("s", time.Time{}, wa, cfg, []string{"app.corp.internal"}, sc)
	require.NoError(t, err)
	require.True(t, l1.InsecureUpstream)
	require.Nil(t, l1.UpstreamRoots, "no sslCertificate: system roots")
	require.Equal(t, 65536, l1.BodyCapBytes)
	require.True(t, l1.CA.Certificate().NotAfter.After(time.Now().Add(time.Hour)), "zero expiry falls back to a bounded validity")

	wa.ConnectionDetails.SSLCertificate = "-----BEGIN CERTIFICATE-----\nnot a cert\n-----END CERTIFICATE-----"
	_, err = newInterception("s", time.Now().Add(time.Hour), wa, cfg, []string{"app.corp.internal"}, sc)
	require.Error(t, err)
}
