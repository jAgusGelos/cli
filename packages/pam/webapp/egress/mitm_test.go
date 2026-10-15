package egress

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/webapp/contract"
	"github.com/Infisical/infisical-merge/packages/pam/webapp/recorder"
	"github.com/Infisical/infisical-merge/packages/pam/webapp/recorder/recordertest"
	"github.com/Infisical/infisical-merge/packages/pam/webapp/scrub"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

const (
	appHost     = "app.corp.internal"
	vaultSecret = `Hunter2&"p/w"+`
	vaultToken  = "tok_9f8e7d6c5b4a3210"
)

// appTLS returns a TLS config serving appHost from a throwaway app CA, and that CA as a pool (the account
// sslCertificate).
func appTLS(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "app ca"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: appHost}, DNSNames: []string{appHost},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &key.PublicKey, caKey)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: key}}}, pool
}

func localPolicy() *Policy {
	return &Policy{
		Override: map[string]netip.Addr{appHost: netip.MustParseAddr("127.0.0.1")},
		Exempt:   []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
	}
}

func newInterception(t *testing.T, roots *x509.CertPool, inject *Header) *Interception {
	t.Helper()
	ca, err := NewCA("8a0c6a4e-1f7b-4e0e-9a43-5d2a6f0b9c11", []string{appHost}, time.Now().Add(time.Hour))
	require.NoError(t, err)
	return &Interception{
		CA: ca, BodyCapBytes: 65536, UpstreamRoots: roots, Inject: inject,
		Scrub: scrub.New(scrub.Config{Secrets: []string{vaultSecret, vaultToken, "corp-admin:" + vaultSecret}, MaskedQueryParams: []string{"sig"}}),
	}
}

func startL1Proxy(t *testing.T, l1 *Interception, record func(contract.EventType, any)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	p := NewProxy(localPolicy(), zerolog.Nop())
	p.Register(netip.MustParseAddr("127.0.0.1"), &Session{SessionID: "s1", AllowedHosts: []string{appHost}, Record: record, L1: l1})
	go p.Serve(ln) //nolint:errcheck
	return ln.Addr().String()
}

// runnerTLS opens a CONNECT through the proxy and a TLS session trusting only the session CA (as Chromium does
// with caPem).
func runnerTLS(t *testing.T, proxyAddr, port string, ca *CA, sni string) (*tls.Conn, error) {
	t.Helper()
	c, br, status := connect(t, proxyAddr, appHost+":"+port)
	if status != 200 {
		c.Close()
		return nil, fmt.Errorf("CONNECT status %d", status)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate())
	tc := tls.Client(&bufConn{Conn: c, r: br}, &tls.Config{RootCAs: pool, ServerName: sni})
	if err := tc.Handshake(); err != nil {
		c.Close()
		return nil, err
	}
	return tc, nil
}

func TestCANameConstraintsAndSingleSAN(t *testing.T) {
	ca, err := NewCA("s", []string{appHost, "10.1.2.3"}, time.Now().Add(time.Hour))
	require.NoError(t, err)
	cert := ca.Certificate()
	require.True(t, cert.IsCA)
	require.True(t, cert.MaxPathLenZero)
	require.Equal(t, []string{appHost}, cert.PermittedDNSDomains)
	require.Len(t, cert.PermittedIPRanges, 1)
	require.NotContains(t, ca.CertPEM(), "PRIVATE KEY")

	leaf, err := ca.Leaf(appHost)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	require.NoError(t, err)
	require.Equal(t, []string{appHost}, parsed.DNSNames)
	require.Empty(t, parsed.IPAddresses)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	_, err = parsed.Verify(x509.VerifyOptions{DNSName: appHost, Roots: roots})
	require.NoError(t, err)

	_, err = ca.Leaf("evil.example")
	require.Error(t, err, "no leaf outside the allowlist")

	// A leaf for a host outside the allowlist, signed by the CA key anyway, must fail chain verification.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(9), DNSNames: []string{"evil.example"}, NotBefore: cert.NotBefore, NotAfter: cert.NotAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, cert, &key.PublicKey, ca.key)
	require.NoError(t, err)
	evil, _ := x509.ParseCertificate(der)
	_, err = evil.Verify(x509.VerifyOptions{DNSName: "evil.example", Roots: roots})
	var inv x509.CertificateInvalidError
	require.ErrorAs(t, err, &inv)
	require.Equal(t, x509.CANotAuthorizedForThisName, inv.Reason)

	only, err := NewCA("s", []string{appHost}, time.Now().Add(time.Hour))
	require.NoError(t, err)
	require.Len(t, only.Certificate().ExcludedIPRanges, 2, "no IP SAN may chain when no IP host is allowed")
}

func TestMITMRecordsMaskedAndInjectsHeader(t *testing.T) {
	srvTLS, roots := appTLS(t)
	var gotAuth []string
	app := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = append(gotAuth, r.Header.Get("Authorization"))
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Set-Cookie", "sid=abc")
		w.Header().Set("X-Echo", vaultToken)
		fmt.Fprintf(w, "echo %s", body)
	}))
	app.TLS = srvTLS
	app.StartTLS()
	defer app.Close()
	_, port, _ := net.SplitHostPort(app.Listener.Addr().String())

	rec := &recorded{}
	l1 := newInterception(t, roots, &Header{Name: "Authorization", Value: "Bearer " + vaultToken})
	addr := startL1Proxy(t, l1, rec.record)
	tc, err := runnerTLS(t, addr, port, l1.CA, appHost)
	require.NoError(t, err)
	defer tc.Close()

	form := "user=corp-admin&password=" + url.QueryEscape(vaultSecret)
	br := bufio.NewReader(tc)
	for i := 0; i < 2; i++ { // two requests on one kept-alive connection
		fmt.Fprintf(tc, "POST /login?next=%%2F&sig=s3&t=%s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nCookie: a=b\r\nContent-Length: %d\r\n\r\n%s",
			url.QueryEscape(vaultSecret), appHost, len(form), form)
		resp, err := http.ReadResponse(br, nil)
		require.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		require.Equal(t, "echo "+form, string(body), "the runner gets the unmasked response")
	}
	require.Equal(t, []string{"Bearer " + vaultToken, "Bearer " + vaultToken}, gotAuth, "credential injected upstream")

	waitEvents(t, rec, 4)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	require.Equal(t, []contract.EventType{contract.EventL1Request, contract.EventL1Response, contract.EventL1Request, contract.EventL1Response}, rec.events)
	req := rec.bodies[0].(l1Request)
	require.Equal(t, "POST", req.Method)
	require.Equal(t, "https://"+appHost+":"+port+"/login?next=%2F&sig=***&t=***", req.URL)
	require.Equal(t, "127.0.0.1", req.DestIP)
	hdr := map[string]string{}
	for _, kv := range req.Headers {
		hdr[kv[0]] = kv[1]
	}
	require.Equal(t, "***", hdr["authorization"], "injected credential recorded masked")
	require.Equal(t, "***", hdr["cookie"])
	require.Equal(t, appHost+":"+port, hdr["host"])
	require.Equal(t, "host", req.Headers[0][0], "wire order kept")
	reqBody, _ := base64.StdEncoding.DecodeString(req.Body)
	require.Equal(t, "user=corp-admin&password=***", string(reqBody))
	sum := sha256.Sum256(reqBody)
	require.Equal(t, hex.EncodeToString(sum[:]), req.BodySha256, "hash over the masked body")
	require.Equal(t, len(form), req.BodyBytes)

	resp := rec.bodies[1].(l1Response)
	require.Equal(t, 200, resp.Status)
	respBody, _ := base64.StdEncoding.DecodeString(resp.Body)
	require.Equal(t, "echo user=corp-admin&password=***", string(respBody))
	for _, kv := range resp.Headers {
		if kv[0] == "set-cookie" || kv[0] == "x-echo" {
			require.Equal(t, "***", kv[1], kv[0])
		}
	}
}

func TestMITMRefusals(t *testing.T) {
	srvTLS, roots := appTLS(t)
	app := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	app.Config.ErrorLog = log.New(io.Discard, "", 0) // the untrusted-upstream case fails the handshake on purpose
	app.TLS = srvTLS
	app.StartTLS()
	defer app.Close()
	_, port, _ := net.SplitHostPort(app.Listener.Addr().String())

	t.Run("sni mismatch", func(t *testing.T) {
		rec := &recorded{}
		l1 := newInterception(t, roots, nil)
		addr := startL1Proxy(t, l1, rec.record)
		_, err := runnerTLS(t, addr, port, l1.CA, "other.internal")
		require.Error(t, err)
		require.Eventually(t, func() bool {
			rec.mu.Lock()
			defer rec.mu.Unlock()
			return len(rec.events) == 1 && rec.events[0] == contract.EventL1Blocked && rec.bodies[0].(l1Blocked).Reason == ReasonSNIMismatch
		}, 2*time.Second, 10*time.Millisecond)
	})
	t.Run("untrusted upstream", func(t *testing.T) {
		l1 := newInterception(t, x509.NewCertPool(), nil)
		addr := startL1Proxy(t, l1, (&recorded{}).record)
		c, _, status := connect(t, addr, appHost+":"+port)
		c.Close()
		require.Equal(t, http.StatusBadGateway, status)
	})
}

func TestPlainHTTPAbsoluteURI(t *testing.T) {
	var gotHost, gotAuth string
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost, gotAuth = r.Host, r.Header.Get("X-Api-Key")
		io.WriteString(w, "plain")
	}))
	defer app.Close()
	_, port, _ := net.SplitHostPort(app.Listener.Addr().String())
	rec := &recorded{}
	l1 := newInterception(t, nil, &Header{Name: "X-Api-Key", Value: vaultToken})
	addr := startL1Proxy(t, l1, rec.record)

	c, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer c.Close()
	fmt.Fprintf(c, "GET http://%s:%s/page HTTP/1.1\r\nHost: %s\r\nProxy-Connection: keep-alive\r\n\r\n", appHost, port, appHost)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, "plain", string(body))
	require.Equal(t, appHost+":"+port, gotHost)
	require.Equal(t, vaultToken, gotAuth)

	waitEvents(t, rec, 2)
	rec.mu.Lock()
	require.Equal(t, []contract.EventType{contract.EventL1Request, contract.EventL1Response}, rec.events)
	req := rec.bodies[0].(l1Request)
	rec.mu.Unlock()
	require.Equal(t, "http://"+appHost+":"+port+"/page", req.URL)
	for _, kv := range req.Headers {
		require.NotEqual(t, "proxy-connection", kv[0])
		if kv[0] == "x-api-key" {
			require.Equal(t, "***", kv[1])
		}
	}

	// A plain request to a host outside the allowlist is refused at once.
	c2, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer c2.Close()
	fmt.Fprintf(c2, "GET http://evil.example/ HTTP/1.1\r\nHost: evil.example\r\n\r\n")
	resp2, err := http.ReadResponse(bufio.NewReader(c2), nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusForbidden, resp2.StatusCode)
}

// wsFrame builds one client (masked) or server (unmasked) text frame.
func wsFrame(payload []byte, masked bool) []byte {
	b := []byte{0x81}
	n := len(payload)
	lenByte := byte(0)
	if masked {
		lenByte = 0x80
	}
	switch {
	case n < 126:
		b = append(b, lenByte|byte(n))
	default:
		b = append(b, lenByte|126, 0, 0)
		binary.BigEndian.PutUint16(b[2:], uint16(n))
	}
	if !masked {
		return append(b, payload...)
	}
	key := []byte{1, 2, 3, 4}
	b = append(b, key...)
	for i, c := range payload {
		b = append(b, c^key[i%4])
	}
	return b
}

// TestSecretNeverReachesSealedPlaintext seeds the vaulted secrets in a URL, a header, a body and a WebSocket payload
// and checks, on the stored and decrypted E chunks, that no encoded form survives (CONTRACTS.md 5.3b, D-06 item 11).
func TestSecretNeverReachesSealedPlaintext(t *testing.T) {
	srvTLS, roots := appTLS(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvTLS)
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				if _, err := http.ReadRequest(br); err != nil {
					return
				}
				io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
				_, _, payload, err := readWSFrame(br)
				if err != nil {
					return
				}
				c.Write(wsFrame(append([]byte("ack "), payload...), false))
			}(c)
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	srv := recordertest.NewServer("6f1c2d3e-4a5b-4c6d-8e7f-90a1b2c3d4e5", "tok")
	defer srv.Close()
	_, recKey, _ := ed25519.GenerateKey(rand.Reader)
	sessKey := make([]byte, 32)
	_, _ = rand.Read(sessKey)
	const sid = "8a0c6a4e-1f7b-4e0e-9a43-5d2a6f0b9c11"
	l1 := newInterception(t, roots, &Header{Name: "Authorization", Value: "Basic " + base64.StdEncoding.EncodeToString([]byte("corp-admin:"+vaultSecret))})
	r, err := recorder.New(recorder.Options{
		SessionID: sid, ProjectID: srv.ProjectID, SessionKey: sessKey, RecordingKey: recKey, ExpiresAt: time.Now().Add(time.Hour),
		Backend: recorder.NewHTTPBackend(srv.URL, sid, "tok", resty.New()), Log: zerolog.Nop(), Retry: time.Millisecond,
		Scrub: l1.Scrub.JSON,
	})
	require.NoError(t, err)
	require.NoError(t, r.Open(recorder.SessionOpen{StartURL: "https://" + appHost + "/", AllowedHosts: []string{appHost}}))
	var wsFrames atomic.Int32
	record := func(et contract.EventType, body any) {
		_, _ = r.Append(et, body)
		if et == contract.EventL1WsFrame {
			wsFrames.Add(1)
		}
	}
	addr := startL1Proxy(t, l1, record)

	tc, err := runnerTLS(t, addr, port, l1.CA, appHost)
	require.NoError(t, err)
	b64 := base64.RawURLEncoding.EncodeToString([]byte(vaultSecret))
	fmt.Fprintf(tc, "GET /ws?p=%s&b=%s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nX-Note: %s\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
		url.QueryEscape(vaultSecret), b64, appHost, vaultToken)
	br := bufio.NewReader(tc)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, 101, resp.StatusCode)
	js, _ := json.Marshal(map[string]string{"password": vaultSecret, "token": vaultToken})
	tc.Write(wsFrame(js, true))
	_, _, echoed, err := readWSFrame(br)
	require.NoError(t, err)
	require.Equal(t, "ack "+string(js), string(echoed), "the app gets and returns the unmasked payload")
	tc.Close()

	require.Eventually(t, func() bool { return wsFrames.Load() == 2 }, 2*time.Second, 5*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, r.Close(ctx, "user_end"))

	res, err := srv.Verify(sessKey, sid, recKey.Public().(ed25519.PublicKey))
	require.NoError(t, err)
	require.Len(t, res.ByType(contract.EventL1WsFrame), 2)
	require.Len(t, res.ByType(contract.EventL1Request), 1)
	var all strings.Builder
	for _, ev := range res.Events {
		all.Write(ev.Body)
		// Decode every base64 body or payload as well: a masked body must not hide a secret inside its encoding.
		var m map[string]any
		if json.Unmarshal(ev.Body, &m) == nil {
			for _, k := range []string{"body", "payload"} {
				if s, ok := m[k].(string); ok {
					d, _ := base64.StdEncoding.DecodeString(s)
					all.Write(d)
				}
			}
		}
	}
	plain := all.String()
	for _, secret := range []string{vaultSecret, vaultToken, "corp-admin:" + vaultSecret} {
		for _, form := range []string{
			secret, url.QueryEscape(secret), url.PathEscape(secret),
			base64.StdEncoding.EncodeToString([]byte(secret)), base64.RawURLEncoding.EncodeToString([]byte(secret)),
			strings.Trim(string(mustMarshal(secret)), `"`),
		} {
			require.NotContains(t, plain, form, "secret form survived in sealed plaintext")
		}
	}
	require.Contains(t, plain, scrub.Mask)
}

// waitEvents waits until n events are recorded: a response is recorded after the runner has read it.
func waitEvents(t *testing.T, rec *recorded, n int) {
	t.Helper()
	require.Eventually(t, func() bool {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		return len(rec.events) >= n
	}, 2*time.Second, 5*time.Millisecond)
}

func mustMarshal(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
