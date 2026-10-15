package egress

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/webapp/contract"
	"github.com/rs/zerolog"
)

// Session is what the proxy knows about the runner behind one source IP.
type Session struct {
	SessionID    string
	AllowedHosts []string
	// Record appends an L1 event to the session recording.
	Record func(t contract.EventType, body any)
}

type l1Blocked struct {
	Method string `json:"method"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Reason string `json:"reason"`
}

type l1Request struct {
	ReqID      string     `json:"reqId"`
	ConnID     string     `json:"connId"`
	Method     string     `json:"method"`
	URL        string     `json:"url"`
	Headers    [][]string `json:"headers"`
	BodyBytes  int        `json:"bodyBytes"`
	BodySha256 string     `json:"bodySha256"`
	Body       string     `json:"body"`
	Truncated  bool       `json:"truncated"`
	DestIP     string     `json:"destIp"`
	DestPort   int        `json:"destPort"`
}

var emptySha = func() string { s := sha256.Sum256(nil); return hex.EncodeToString(s[:]) }()

// Proxy is the egress proxy. In this stage it tunnels CONNECT only (CONTRACTS.md 8b); TLS interception, L1 bodies
// and header injection come with the scrubber.
type Proxy struct {
	policy      *Policy
	log         zerolog.Logger
	DialTimeout time.Duration

	mu       sync.RWMutex
	sessions map[netip.Addr]*Session
	ids      atomic.Uint64
}

func NewProxy(policy *Policy, log zerolog.Logger) *Proxy {
	return &Proxy{policy: policy, log: log, DialTimeout: 10 * time.Second, sessions: map[netip.Addr]*Session{}}
}

// Register attributes connections from ip to a session until the returned function is called.
func (p *Proxy) Register(ip netip.Addr, s *Session) func() {
	ip = ip.Unmap()
	p.mu.Lock()
	p.sessions[ip] = s
	p.mu.Unlock()
	return func() {
		p.mu.Lock()
		if p.sessions[ip] == s {
			delete(p.sessions, ip)
		}
		p.mu.Unlock()
	}
}

func (p *Proxy) session(addr net.Addr) *Session {
	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.sessions[ap.Addr().Unmap()]
}

// Serve accepts connections until ln is closed.
func (p *Proxy) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go p.handle(c)
	}
}

func reply(c net.Conn, status int) {
	fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status, http.StatusText(status))
}

func (p *Proxy) handle(c net.Conn) {
	defer c.Close()
	sess := p.session(c.RemoteAddr())
	if sess == nil {
		p.log.Warn().Str("remote", c.RemoteAddr().String()).Msg("Web App egress: connection from an unknown source, refused")
		reply(c, http.StatusForbidden)
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		reply(c, http.StatusBadRequest)
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	if req.Method != http.MethodConnect {
		reply(c, http.StatusMethodNotAllowed)
		return
	}
	host, portStr, err := net.SplitHostPort(req.Host)
	if err != nil {
		host, portStr = req.Host, "443"
	}
	host = strings.ToLower(host)
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		reply(c, http.StatusBadRequest)
		return
	}
	block := func(reason string, status int) {
		sess.Record(contract.EventL1Blocked, l1Blocked{Method: http.MethodConnect, Host: host, Port: port, Reason: reason})
		p.log.Info().Str("sessionId", sess.SessionID).Str("host", host).Int("port", port).Str("reason", reason).Msg("Web App egress blocked")
		reply(c, status)
	}
	if !HostAllowed(host, sess.AllowedHosts) {
		block(ReasonHostNotAllowed, http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), p.DialTimeout)
	defer cancel()
	ip, err := p.policy.Resolve(ctx, host)
	if err != nil {
		reason := blockReason(err)
		status := http.StatusForbidden
		if reason == ReasonResolveFailed {
			status = http.StatusBadGateway
		}
		block(reason, status)
		return
	}
	dest := netip.AddrPortFrom(ip, uint16(port)).String()
	up, err := (&net.Dialer{}).DialContext(ctx, "tcp", dest)
	if err != nil {
		p.log.Warn().Err(err).Str("sessionId", sess.SessionID).Str("dest", dest).Msg("Web App egress: upstream dial failed")
		reply(c, http.StatusBadGateway)
		return
	}
	defer up.Close()
	n := p.ids.Add(1)
	sess.Record(contract.EventL1Request, l1Request{
		ReqID: fmt.Sprintf("r-%d", n), ConnID: fmt.Sprintf("c-%d", n), Method: http.MethodConnect,
		URL: net.JoinHostPort(host, strconv.Itoa(port)), Headers: [][]string{}, BodySha256: emptySha,
		DestIP: ip.String(), DestPort: port,
	})
	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, br); closeWrite(up); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); closeWrite(c); done <- struct{}{} }()
	<-done
	// One direction ended: give the other a bounded drain so a half-open peer cannot pin the tunnel.
	deadline := time.Now().Add(30 * time.Second)
	_ = c.SetDeadline(deadline)
	_ = up.SetDeadline(deadline)
	<-done
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}
