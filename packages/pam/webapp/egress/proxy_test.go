package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/Infisical/infisical-merge/packages/pam/webapp/contract"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

type fakeResolver map[string][]netip.Addr

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if ips, ok := f[host]; ok {
		return ips, nil
	}
	return nil, errors.New("no such host")
}

type recorded struct {
	mu     sync.Mutex
	events []contract.EventType
	bodies []any
}

func (r *recorded) record(t contract.EventType, body any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, t)
	r.bodies = append(r.bodies, body)
}

func startProxy(t *testing.T, pol *Policy, allowed []string) (*Proxy, string, *recorded) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	p := NewProxy(pol, zerolog.Nop())
	rec := &recorded{}
	p.Register(netip.MustParseAddr("127.0.0.1"), &Session{SessionID: "s1", AllowedHosts: allowed, Record: rec.record})
	go p.Serve(ln) //nolint:errcheck
	return p, ln.Addr().String(), rec
}

func connect(t *testing.T, proxyAddr, target string) (net.Conn, *bufio.Reader, int) {
	t.Helper()
	c, err := net.Dial("tcp", proxyAddr)
	require.NoError(t, err)
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	require.NoError(t, err)
	return c, br, resp.StatusCode
}

func TestTunnelToAllowedHost(t *testing.T) {
	app := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hello app") }))
	defer app.Close()
	_, appPort, _ := net.SplitHostPort(app.Listener.Addr().String())
	pol := &Policy{
		Override: map[string]netip.Addr{"app.corp.internal": netip.MustParseAddr("127.0.0.1")},
		Exempt:   []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
	}
	_, addr, rec := startProxy(t, pol, []string{"app.corp.internal"})

	c, br, status := connect(t, addr, "App.Corp.Internal:"+appPort)
	defer c.Close()
	require.Equal(t, 200, status)
	pool := app.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	tc := tls.Client(&bufConn{Conn: c, r: br}, &tls.Config{RootCAs: pool, ServerName: "example.com"})
	fmt.Fprintf(tc, "GET / HTTP/1.1\r\nHost: app.corp.internal\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, "hello app", string(body))

	rec.mu.Lock()
	defer rec.mu.Unlock()
	require.Equal(t, []contract.EventType{contract.EventL1Request}, rec.events)
	req := rec.bodies[0].(l1Request)
	require.Equal(t, "CONNECT", req.Method)
	require.Equal(t, "127.0.0.1", req.DestIP)
}

func TestBlockedDestinations(t *testing.T) {
	pol := &Policy{
		Override: map[string]netip.Addr{
			"loop.internal":   netip.MustParseAddr("127.0.0.1"),
			"meta.internal":   netip.MustParseAddr("169.254.169.254"),
			"runner.internal": netip.MustParseAddr("172.28.0.12"),
			"own.internal":    netip.MustParseAddr("10.9.9.9"),
			"v6ll.internal":   netip.MustParseAddr("fe80::1"),
			"zero.internal":   netip.MustParseAddr("0.1.2.3"),
		},
		Resolver:      fakeResolver{"multi.internal": {netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("224.0.0.1")}},
		OwnAddrs:      []netip.Addr{netip.MustParseAddr("10.9.9.9"), netip.MustParseAddr("172.27.0.1")},
		OwnAddrExempt: DefaultOwnAddrExempt,
	}
	allowed := []string{"loop.internal", "meta.internal", "runner.internal", "own.internal", "v6ll.internal", "zero.internal", "multi.internal", "nxdomain.internal"}
	_, addr, rec := startProxy(t, pol, allowed)
	cases := []struct {
		target string
		status int
		reason string
	}{
		{"evil.example:443", 403, ReasonHostNotAllowed},
		{"loop.internal:443", 403, ReasonIPDenied},
		{"meta.internal:80", 403, ReasonIPDenied},
		{"runner.internal:443", 403, ReasonIPDenied},
		{"own.internal:443", 403, ReasonIPDenied},
		{"v6ll.internal:443", 403, ReasonIPDenied},
		{"zero.internal:443", 403, ReasonIPDenied},
		{"multi.internal:443", 403, ReasonIPDenied},
		{"nxdomain.internal:443", 502, ReasonResolveFailed},
		{"127.0.0.1:443", 403, ReasonHostNotAllowed},
	}
	for i, tc := range cases {
		c, _, status := connect(t, addr, tc.target)
		c.Close()
		require.Equal(t, tc.status, status, tc.target)
		rec.mu.Lock()
		require.Len(t, rec.events, i+1, tc.target)
		require.Equal(t, contract.EventL1Blocked, rec.events[i])
		require.Equal(t, tc.reason, rec.bodies[i].(l1Blocked).Reason, tc.target)
		rec.mu.Unlock()
	}
	require.False(t, pol.Denied(netip.MustParseAddr("172.27.0.1")), "own address inside iwa-apps is exempt")
	require.False(t, pol.Denied(netip.MustParseAddr("172.27.0.10")))
	require.True(t, pol.Denied(netip.MustParseAddr("::ffff:127.0.0.1")))
}

func TestNonConnectAndUnknownSource(t *testing.T) {
	_, addr, _ := startProxy(t, &Policy{}, []string{"app.corp.internal"})
	c, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer c.Close()
	fmt.Fprintf(c, "GET http://app.corp.internal/ HTTP/1.1\r\nHost: app.corp.internal\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)

	p := NewProxy(&Policy{}, zerolog.Nop())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	go p.Serve(ln) //nolint:errcheck
	c2, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer c2.Close()
	line, _ := bufio.NewReader(c2).ReadString('\n')
	require.True(t, strings.HasPrefix(line, "HTTP/1.1 403"), line)
}

func TestParseHostsOverride(t *testing.T) {
	m, err := ParseHostsOverride(" App.Corp.Internal=172.27.0.10 , b=::ffff:10.0.0.1,")
	require.NoError(t, err)
	require.Equal(t, netip.MustParseAddr("172.27.0.10"), m["app.corp.internal"])
	require.Equal(t, netip.MustParseAddr("10.0.0.1"), m["b"])
	_, err = ParseHostsOverride("nonsense")
	require.Error(t, err)
}
