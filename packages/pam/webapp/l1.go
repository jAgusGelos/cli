package webapp

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/pam/webapp/egress"
	"github.com/Infisical/infisical-merge/packages/pam/webapp/scrub"
)

// The header auth method and its schemes (CONTRACTS.md 8.1).
const (
	authHeader = "header"

	schemeBasic  = "basic"
	schemeBearer = "bearer"
	schemeCustom = "custom"
)

// caValidityFallback bounds the session CA when the session carries no expiry.
const caValidityFallback = 12 * time.Hour

// caExpirySlack keeps the CA valid through the end-of-session teardown.
const caExpirySlack = 5 * time.Minute

// secretsOf lists the vaulted values the scrubber removes (CONTRACTS.md 8.1): password, token, headerValue and the
// username:password pair.
func secretsOf(c api.PAMWebAppCredentials) []string {
	var out []string
	for _, s := range []string{c.Password, c.Token, c.HeaderValue} {
		if s != "" {
			out = append(out, s)
		}
	}
	if c.Username != "" && c.Password != "" {
		out = append(out, c.Username+":"+c.Password)
	}
	return out
}

// injectedHeader is the header credential the egress proxy sets on every request to an allowed host; nil for the
// other auth methods.
func injectedHeader(c api.PAMWebAppCredentials) (*egress.Header, error) {
	if c.AuthMethod != authHeader {
		return nil, nil
	}
	switch c.HeaderScheme {
	case schemeBasic:
		if c.Username == "" || c.Password == "" {
			return nil, errors.New("webapp: basic header credentials need a username and a password")
		}
		return &egress.Header{Name: "Authorization", Value: "Basic " + base64.StdEncoding.EncodeToString([]byte(c.Username+":"+c.Password))}, nil
	case schemeBearer:
		if c.Token == "" {
			return nil, errors.New("webapp: bearer header credentials need a token")
		}
		return &egress.Header{Name: "Authorization", Value: "Bearer " + c.Token}, nil
	case schemeCustom:
		name := strings.TrimSpace(c.HeaderName)
		if name == "" || c.HeaderValue == "" || strings.ContainsAny(name, " :\r\n") || strings.ContainsAny(c.HeaderValue, "\r\n") {
			return nil, errors.New("webapp: custom header credentials need a valid headerName and headerValue")
		}
		return &egress.Header{Name: name, Value: c.HeaderValue}, nil
	default:
		return nil, fmt.Errorf("webapp: unknown header scheme %q", c.HeaderScheme)
	}
}

// newScrubber builds the session scrubber shared by the recorder (every event body) and the egress proxy (L1 bodies
// before hashing, CONTRACTS.md 5.3b).
func newScrubber(wa *api.PAMWebAppDetails, cfg settings) *scrub.Scrubber {
	return scrub.New(scrub.Config{
		Secrets: secretsOf(wa.Credentials), MaskedHeaders: cfg.maskedHeaders, MaskedQueryParams: cfg.maskedQueryParams,
	})
}

// newInterception builds the session's L1 egress configuration: a fresh name-constrained CA for the allowlist, the
// upstream trust from the account sslCertificate, the header credential and the scrubber.
func newInterception(sessionID string, expiresAt time.Time, wa *api.PAMWebAppDetails, cfg settings, allowed []string, sc *scrub.Scrubber) (*egress.Interception, error) {
	inject, err := injectedHeader(wa.Credentials)
	if err != nil {
		return nil, err
	}
	notAfter := expiresAt.Add(caExpirySlack)
	if expiresAt.IsZero() || !notAfter.After(time.Now()) {
		notAfter = time.Now().Add(caValidityFallback)
	}
	ca, err := egress.NewCA(sessionID, allowed, notAfter)
	if err != nil {
		return nil, err
	}
	var roots *x509.CertPool
	if pemText := strings.TrimSpace(wa.ConnectionDetails.SSLCertificate); pemText != "" {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(pemText)) {
			return nil, errors.New("webapp: the account sslCertificate holds no PEM certificate")
		}
	}
	insecure := wa.ConnectionDetails.SSLRejectUnauthorized != nil && !*wa.ConnectionDetails.SSLRejectUnauthorized
	return &egress.Interception{
		CA: ca, Scrub: sc, BodyCapBytes: cfg.bodyCapBytes, UpstreamRoots: roots, InsecureUpstream: insecure, Inject: inject,
	}, nil
}
