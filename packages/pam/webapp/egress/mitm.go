package egress

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/webapp/contract"
	"github.com/Infisical/infisical-merge/packages/pam/webapp/scrub"
)

// Interception is the per-session L1 configuration of the proxy (CONTRACTS.md 5.3, 8.1).
type Interception struct {
	CA    *CA
	Scrub *scrub.Scrubber
	// BodyCapBytes truncates recorded bodies and WebSocket payloads (template bodyCapBytes).
	BodyCapBytes int
	// UpstreamRoots verifies the app certificate (the account sslCertificate); nil uses the system roots.
	UpstreamRoots *x509.CertPool
	// InsecureUpstream skips upstream verification (account sslRejectUnauthorized false).
	InsecureUpstream bool
	// Inject is the header credential set on every request to an allowed host; nil injects nothing.
	Inject *Header
}

// Header is one injected request header.
type Header struct{ Name, Value string }

// Limits and timeouts of the interception loop; variables so tests can shorten them.
var (
	maxHeadBytes     = 64 * 1024
	scanLimitBytes   = 8 * 1024 * 1024 // bodies are buffered up to this size for masking and hashing
	maxWSFrameBytes  = 32 * 1024 * 1024
	handshakeTimeout = 15 * time.Second
	idleTimeout      = 2 * time.Minute
)

var errSNIMismatch = errors.New("egress: SNI does not match the CONNECT host")

type l1Response struct {
	ReqID      string     `json:"reqId"`
	Status     int        `json:"status"`
	Headers    [][]string `json:"headers"`
	BodyBytes  int        `json:"bodyBytes"`
	BodySha256 string     `json:"bodySha256"`
	Body       string     `json:"body"`
	Truncated  bool       `json:"truncated"`
	DurationMs int64      `json:"durationMs"`
}

type l1WsFrame struct {
	ConnID    string `json:"connId"`
	ReqID     string `json:"reqId"`
	Dir       string `json:"dir"`
	Opcode    int    `json:"opcode"`
	Bytes     int    `json:"bytes"`
	Payload   string `json:"payload"`
	Truncated bool   `json:"truncated"`
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// exchangeConn is one client connection whose requests all go to the same pinned upstream.
type exchangeConn struct {
	p      *Proxy
	sess   *Session
	t      target
	scheme string
	connID string

	client   net.Conn
	clientBr *bufio.Reader
	up       net.Conn
	upBr     *bufio.Reader
}

// intercept terminates the runner's TLS with a leaf of the session CA and records every request on the connection.
// The upstream TLS handshake runs first so an untrusted app answers the CONNECT with 502 instead of a broken page.
func (p *Proxy) intercept(c net.Conn, up net.Conn, sess *Session, t target) {
	l1 := sess.L1
	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	defer cancel()
	upTLS := tls.Client(up, &tls.Config{
		ServerName: t.host, RootCAs: l1.UpstreamRoots, InsecureSkipVerify: l1.InsecureUpstream, //nolint:gosec // account sslRejectUnauthorized=false
		NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12,
	})
	if err := upTLS.HandshakeContext(ctx); err != nil {
		p.log.Warn().Err(err).Str("sessionId", sess.SessionID).Str("host", t.host).Msg("Web App egress: upstream TLS refused")
		reply(c, http.StatusBadGateway)
		return
	}
	defer upTLS.Close()
	leaf, err := l1.CA.Leaf(t.host)
	if err != nil {
		p.log.Error().Err(err).Str("sessionId", sess.SessionID).Msg("Web App egress: leaf certificate")
		reply(c, http.StatusInternalServerError)
		return
	}
	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	clientTLS := tls.Server(c, &tls.Config{
		GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if !sniMatches(hi.ServerName, t.host) {
				return nil, errSNIMismatch
			}
			return leaf, nil
		},
		NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12,
	})
	if err := clientTLS.HandshakeContext(ctx); err != nil {
		if errors.Is(err, errSNIMismatch) {
			sess.Record(contract.EventL1Blocked, l1Blocked{Method: http.MethodConnect, Host: t.host, Port: t.port, Reason: ReasonSNIMismatch})
			p.log.Info().Str("sessionId", sess.SessionID).Str("host", t.host).Msg("Web App egress blocked: SNI mismatch")
		}
		return
	}
	defer clientTLS.Close()
	ex := &exchangeConn{
		p: p, sess: sess, t: t, scheme: "https", connID: fmt.Sprintf("c-%d", p.ids.Add(1)),
		client: clientTLS, clientBr: bufio.NewReaderSize(clientTLS, maxHeadBytes),
		up: upTLS, upBr: bufio.NewReaderSize(upTLS, maxHeadBytes),
	}
	ex.serve()
}

// sniMatches: the SNI must equal the CONNECT host; an absent SNI is accepted only for an IP literal host.
func sniMatches(sni, host string) bool {
	if sni == "" {
		return net.ParseIP(host) != nil
	}
	return strings.EqualFold(strings.TrimSuffix(sni, "."), host)
}

// plainHTTP forwards one absolute-URI http request (CONTRACTS.md section 2) and closes the connection after it.
func (p *Proxy) plainHTTP(c net.Conn, br *bufio.Reader, sess *Session, req *http.Request, names []string) {
	host := strings.ToLower(req.URL.Hostname())
	port := 80
	if ps := req.URL.Port(); ps != "" {
		n, err := strconv.Atoi(ps)
		if err != nil || n <= 0 || n > 65535 {
			reply(c, http.StatusBadRequest)
			return
		}
		port = n
	}
	t, ok := p.authorize(c, sess, req.Method, host, port)
	if !ok {
		return
	}
	up, err := p.dial(sess, t)
	if err != nil {
		reply(c, http.StatusBadGateway)
		return
	}
	defer up.Close()
	ex := &exchangeConn{
		p: p, sess: sess, t: t, scheme: "http", connID: fmt.Sprintf("c-%d", p.ids.Add(1)),
		client: c, clientBr: br, up: up, upBr: bufio.NewReaderSize(up, maxHeadBytes),
	}
	req.Close = true
	ex.exchange(req, names)
}

func (ex *exchangeConn) serve() {
	for {
		_ = ex.client.SetReadDeadline(time.Now().Add(idleTimeout))
		names, err := headerNames(ex.clientBr)
		if err != nil {
			return
		}
		req, err := http.ReadRequest(ex.clientBr)
		if err != nil {
			return
		}
		_ = ex.client.SetReadDeadline(time.Time{})
		if !ex.exchange(req, names) {
			return
		}
	}
}

func (ex *exchangeConn) authority() string {
	if (ex.scheme == "https" && ex.t.port == 443) || (ex.scheme == "http" && ex.t.port == 80) {
		return ex.t.host
	}
	return net.JoinHostPort(ex.t.host, strconv.Itoa(ex.t.port))
}

// exchange forwards one request and its response, recording l1_request and l1_response (and the WebSocket frames
// after an upgrade). It reports whether the connection can carry another request.
func (ex *exchangeConn) exchange(req *http.Request, names []string) bool {
	l1 := ex.sess.L1
	reqID := fmt.Sprintf("r-%d", ex.p.ids.Add(1))
	start := time.Now()

	// The pinned upstream serves exactly the CONNECT (or absolute-URI) host.
	req.Host = ex.authority()
	req.URL.Scheme, req.URL.Host = ex.scheme, req.Host
	for _, h := range []string{"Proxy-Authorization", "Proxy-Connection", "Sec-Websocket-Extensions"} {
		req.Header.Del(h)
	}
	if l1.Inject != nil {
		req.Header.Set(l1.Inject.Name, l1.Inject.Value)
		names = appendName(names, l1.Inject.Name)
	}
	if _, ok := req.Header["User-Agent"]; !ok {
		req.Header["User-Agent"] = []string{} // keep Request.Write from adding Go's default
	}
	reqBody := &capture{limit: scanLimitBytes}
	if req.Body != nil {
		req.Body = &captureBody{ReadCloser: req.Body, c: reqBody}
	}
	recordReq := func() {
		sha, b64, truncated := ex.maskBody(reqBody)
		ex.sess.Record(contract.EventL1Request, l1Request{
			ReqID: reqID, ConnID: ex.connID, Method: req.Method, URL: l1.Scrub.URL(req.URL.String()),
			Headers: l1.Scrub.Headers(orderedHeaders(names, req.Header, req.Host)), BodyBytes: reqBody.total,
			BodySha256: sha, Body: b64, Truncated: truncated, DestIP: ex.t.ip.String(), DestPort: ex.t.port,
		})
	}
	if err := req.Write(ex.up); err != nil {
		recordReq()
		ex.p.log.Debug().Err(err).Str("sessionId", ex.sess.SessionID).Msg("Web App egress: upstream write failed")
		reply(ex.client, http.StatusBadGateway)
		return false
	}
	recordReq()

	respNames, err := headerNames(ex.upBr)
	if err != nil {
		reply(ex.client, http.StatusBadGateway)
		return false
	}
	resp, err := http.ReadResponse(ex.upBr, req)
	if err != nil {
		reply(ex.client, http.StatusBadGateway)
		return false
	}
	respHeaders := l1.Scrub.Headers(orderedHeaders(respNames, resp.Header, ""))
	if resp.StatusCode == http.StatusSwitchingProtocols {
		ex.sess.Record(contract.EventL1Response, l1Response{
			ReqID: reqID, Status: resp.StatusCode, Headers: respHeaders, BodySha256: emptySha, DurationMs: time.Since(start).Milliseconds(),
		})
		if err := writeHead(ex.client, resp); err != nil {
			return false
		}
		if strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
			ex.websocket(reqID)
		} else {
			pipe(ex.client, ex.clientBr, ex.up, ex.upBr)
		}
		return false
	}
	respBody := &capture{limit: scanLimitBytes}
	resp.Body = &captureBody{ReadCloser: resp.Body, c: respBody}
	if ex.scheme == "http" {
		resp.Close = true
	}
	werr := resp.Write(ex.client)
	resp.Body.Close()
	sha, b64, truncated := ex.maskBody(respBody)
	ex.sess.Record(contract.EventL1Response, l1Response{
		ReqID: reqID, Status: resp.StatusCode, Headers: respHeaders, BodyBytes: respBody.total, BodySha256: sha,
		Body: b64, Truncated: truncated, DurationMs: time.Since(start).Milliseconds(),
	})
	return werr == nil && !req.Close && !resp.Close
}

// maskBody scrubs a captured body and returns the hash of the masked untruncated body, the recorded (truncated) part
// in base64 and whether it was truncated (CONTRACTS.md 5.3). A body larger than the scan limit is hashed over its
// masked first scanLimitBytes and always marked truncated.
func (ex *exchangeConn) maskBody(c *capture) (string, string, bool) {
	masked := ex.sess.L1.Scrub.Bytes(c.buf.Bytes())
	sum := sha256.Sum256(masked)
	rec := masked
	truncated := c.total > c.buf.Len()
	if bodyCap := ex.sess.L1.BodyCapBytes; len(rec) > bodyCap {
		rec, truncated = rec[:bodyCap], true
	}
	return hex.EncodeToString(sum[:]), base64.StdEncoding.EncodeToString(rec), truncated
}

// websocket relays frames in both directions after a 101 and records each one as l1_ws_frame.
func (ex *exchangeConn) websocket(reqID string) {
	done := make(chan struct{}, 2)
	relay := func(src *bufio.Reader, dst net.Conn, dir string) {
		defer func() { closeWrite(dst); done <- struct{}{} }()
		for {
			raw, opcode, payload, err := readWSFrame(src)
			if err != nil {
				return
			}
			if _, err := dst.Write(raw); err != nil {
				return
			}
			masked := ex.sess.L1.Scrub.Bytes(payload)
			rec, truncated := masked, false
			if bodyCap := ex.sess.L1.BodyCapBytes; len(rec) > bodyCap {
				rec, truncated = rec[:bodyCap], true
			}
			ex.sess.Record(contract.EventL1WsFrame, l1WsFrame{
				ConnID: ex.connID, ReqID: reqID, Dir: dir, Opcode: opcode, Bytes: len(payload),
				Payload: base64.StdEncoding.EncodeToString(rec), Truncated: truncated,
			})
		}
	}
	go relay(ex.clientBr, ex.up, "c2s")
	go relay(ex.upBr, ex.client, "s2c")
	<-done
	deadline := time.Now().Add(30 * time.Second)
	_ = ex.client.SetDeadline(deadline)
	_ = ex.up.SetDeadline(deadline)
	<-done
}

// readWSFrame reads one RFC 6455 frame and returns its raw bytes (forwarded unchanged), its opcode and its unmasked
// payload (recorded).
func readWSFrame(r *bufio.Reader) (raw []byte, opcode int, payload []byte, err error) {
	var hdr [14]byte
	if _, err = io.ReadFull(r, hdr[:2]); err != nil {
		return nil, 0, nil, err
	}
	opcode = int(hdr[0] & 0x0f)
	masked := hdr[1]&0x80 != 0
	n := uint64(hdr[1] & 0x7f)
	off := 2
	switch n {
	case 126:
		if _, err = io.ReadFull(r, hdr[2:4]); err != nil {
			return nil, 0, nil, err
		}
		n, off = uint64(binary.BigEndian.Uint16(hdr[2:4])), 4
	case 127:
		if _, err = io.ReadFull(r, hdr[2:10]); err != nil {
			return nil, 0, nil, err
		}
		n, off = binary.BigEndian.Uint64(hdr[2:10]), 10
	}
	if n > uint64(maxWSFrameBytes) {
		return nil, 0, nil, fmt.Errorf("egress: WebSocket frame of %d bytes exceeds the limit", n)
	}
	var key []byte
	if masked {
		if _, err = io.ReadFull(r, hdr[off:off+4]); err != nil {
			return nil, 0, nil, err
		}
		key = hdr[off : off+4]
		off += 4
	}
	raw = make([]byte, off+int(n))
	copy(raw, hdr[:off])
	if _, err = io.ReadFull(r, raw[off:]); err != nil {
		return nil, 0, nil, err
	}
	payload = append([]byte(nil), raw[off:]...)
	for i := range payload {
		if key != nil {
			payload[i] ^= key[i%4]
		}
	}
	return raw, opcode, payload, nil
}

// headerNames peeks the message head (without consuming it) and returns its header names in wire order, lowercase.
func headerNames(br *bufio.Reader) ([]string, error) {
	for {
		buf, _ := br.Peek(br.Buffered())
		if i := bytes.Index(buf, []byte("\r\n\r\n")); i >= 0 {
			return parseNames(buf[:i]), nil
		}
		if br.Buffered() >= maxHeadBytes {
			return nil, errors.New("egress: message head too large")
		}
		if _, err := br.Peek(br.Buffered() + 1); err != nil {
			return nil, err
		}
	}
}

func parseNames(head []byte) []string {
	lines := strings.Split(string(head), "\r\n")
	var out []string
	for _, line := range lines[1:] {
		if line == "" || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		if name, _, ok := strings.Cut(line, ":"); ok {
			out = appendName(out, strings.TrimSpace(name))
		}
	}
	return out
}

func appendName(names []string, name string) []string {
	name = strings.ToLower(name)
	for _, n := range names {
		if n == name {
			return names
		}
	}
	return append(names, name)
}

// orderedHeaders lists [name, value] pairs in wire order; names absent from the head (added by the proxy) follow.
func orderedHeaders(names []string, h http.Header, host string) [][]string {
	out := [][]string{}
	seen := map[string]bool{}
	add := func(name string) {
		if seen[name] {
			return
		}
		seen[name] = true
		if name == "host" && host != "" {
			out = append(out, []string{"host", host})
			return
		}
		for _, v := range h[http.CanonicalHeaderKey(name)] {
			out = append(out, []string{name, v})
		}
	}
	for _, n := range names {
		add(n)
	}
	extra := make([]string, 0, len(h))
	for k := range h {
		extra = append(extra, strings.ToLower(k))
	}
	sort.Strings(extra)
	for _, n := range extra {
		add(n)
	}
	return out
}

// writeHead writes a bodiless response head (the 101 of an upgrade) as received.
func writeHead(w io.Writer, resp *http.Response) error {
	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/1.1 %s\r\n", resp.Status)
	if err := resp.Header.Write(&b); err != nil {
		return err
	}
	b.WriteString("\r\n")
	_, err := w.Write(b.Bytes())
	return err
}

// capture keeps the first limit bytes of a body and counts all of them.
type capture struct {
	buf   bytes.Buffer
	limit int
	total int
}

func (c *capture) add(p []byte) {
	c.total += len(p)
	if room := c.limit - c.buf.Len(); room > 0 {
		if len(p) > room {
			p = p[:room]
		}
		c.buf.Write(p)
	}
}

type captureBody struct {
	io.ReadCloser
	c *capture
}

func (b *captureBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.c.add(p[:n])
	return n, err
}
