// Command iwa-harness is the standalone F1 fake gateway: it launches a runner through the supervisor socket, speaks
// the agent link with F0's contract codec, serves a CONNECT-only allowlist proxy, drives input, and verifies the live
// stream, the recording segments, the netns lockdown and the cleanup. It exits non-zero on any failed check.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/webapp/contract"
)

const (
	hostAddress    = "172.28.0.1"
	sessionLabel   = "infisical.webapp.session"
	defaultImage   = "infisical-webapp-runner:dev"
	demoAppName    = "iwa-demo-app"
	typedText      = "iwa harness 123"
	keyframeAt     = 5 * time.Second
	inputAt        = 8 * time.Second
	agentWait      = 90 * time.Second
	shutdownWait   = 30 * time.Second
	segmentSeconds = 10
)

type options struct {
	socket       string
	image        string
	agentPort    int
	proxyPort    int
	out          string
	startDemoApp bool
	duration     time.Duration
	startURL     string
	caPath       string
	hostsOverr   string
	demoAppImage string
	spikeAppDir  string
	supLog       string
}

func parseFlags() options {
	var o options
	flag.StringVar(&o.socket, "socket", envOr("INFISICAL_WEBAPP_SUPERVISOR_SOCKET", "/tmp/infisical-webapp/supervisor.sock"), "supervisor unix socket")
	flag.StringVar(&o.image, "image", "", "allowlisted image ref name@sha256:<id> (default: resolved from "+defaultImage+")")
	flag.IntVar(&o.agentPort, "agent-port", 17701, "agent link port on 172.28.0.1 (never 7701)")
	flag.IntVar(&o.proxyPort, "proxy-port", 13128, "CONNECT proxy port on 172.28.0.1 (never 3128)")
	flag.StringVar(&o.out, "out", "", "output directory (required)")
	flag.BoolVar(&o.startDemoApp, "start-demo-app", false, "start "+demoAppName+" on iwa-apps if it is not running")
	flag.DurationVar(&o.duration, "duration", 25*time.Second, "collection time after live_start")
	flag.StringVar(&o.startURL, "start-url", "https://app.corp.internal/input", "runner start URL")
	flag.StringVar(&o.caPath, "ca", "/home/agus/Escritorio/Infisical/spikes/rbi-runner/pki/app-ca.crt", "CA certificate passed as caPem")
	flag.StringVar(&o.hostsOverr, "hosts-override", "app.corp.internal=172.27.0.10", "comma-separated host=ip for the proxy resolver")
	flag.StringVar(&o.demoAppImage, "demo-app-image", "mitmproxy/mitmproxy:11.1.3", "image for -start-demo-app")
	flag.StringVar(&o.spikeAppDir, "spike-app-dir", "/home/agus/Escritorio/Infisical/spikes/rbi-runner/app", "spike app dir for -start-demo-app")
	flag.StringVar(&o.supLog, "supervisor-log", "", "optional supervisor log file to scan for the runner token")
	flag.Parse()
	return o
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

type check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Fatal  bool   `json:"fatal"`
	Detail string `json:"detail"`
}

type chunkInfo struct {
	Index     int    `json:"index"`
	Keyframe  bool   `json:"keyframe"`
	PtsUs     uint64 `json:"ptsUs"`
	Bytes     int    `json:"bytes"`
	ArrivalMs int64  `json:"arrivalMs"`
}

type segInfo struct {
	Meta     contract.RecSegmentMeta `json:"meta"`
	File     string                  `json:"file"`
	ShaOK    bool                    `json:"sha256Ok"`
	Bytes    int                     `json:"bytes"`
	Received time.Time               `json:"-"`
}

type harness struct {
	o      options
	logger *log.Logger

	sessionID string
	short     string
	token     string
	imageRef  string
	imageID   string
	runnerIP  string
	launchAt  time.Time
	client    *http.Client
	calls     *os.File

	mu          sync.Mutex
	checks      []check
	hello       *contract.AgentHello
	videoConfig *contract.VideoConfig
	configCount int
	chunks      []chunkInfo
	firstChunk  []byte
	liveFile    *os.File
	recInit     *contract.RecInitMeta
	segs        []segInfo
	losses      []contract.RecLoss
	events      []json.RawMessage
	proxyLog    []string
	kfRequestAt int // chunk count when the keyframe request went out, -1 before
	inputChunk  int
	startClock  time.Time
	netns       []map[string]any
}

func main() {
	o := parseFlags()
	if o.out == "" {
		fmt.Fprintln(os.Stderr, "-out is required")
		os.Exit(2)
	}
	if o.agentPort == 7701 || o.proxyPort == 3128 {
		fmt.Fprintln(os.Stderr, "ports 7701 and 3128 belong to the live gateway; use 17701 and 13128")
		os.Exit(2)
	}
	os.Exit(run(o))
}

func run(o options) int {
	if err := os.MkdirAll(o.out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	logFile, err := os.Create(filepath.Join(o.out, "harness.log"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	defer logFile.Close()
	calls, err := os.Create(filepath.Join(o.out, "supervisor-calls.log"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	defer calls.Close()

	h := &harness{
		o:           o,
		logger:      log.New(io.MultiWriter(os.Stdout, logFile), "iwa-harness ", log.LstdFlags|log.Lmicroseconds),
		calls:       calls,
		kfRequestAt: -1,
		inputChunk:  -1,
		client: &http.Client{Timeout: 120 * time.Second, Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", o.socket)
			},
		}},
	}
	h.execute()
	h.writeSummary()
	return h.report()
}

func (h *harness) add(name string, ok bool, detail string, args ...any) {
	h.addCheck(name, ok, true, detail, args...)
}

func (h *harness) addCheck(name string, ok, fatal bool, detail string, args ...any) {
	if len(args) > 0 {
		detail = fmt.Sprintf(detail, args...)
	}
	h.mu.Lock()
	h.checks = append(h.checks, check{Name: name, OK: ok, Fatal: fatal, Detail: detail})
	h.mu.Unlock()
	state := "PASS"
	if !ok {
		state = "FAIL"
		if !fatal {
			state = "WARN"
		}
	}
	h.logger.Printf("check %s: %s (%s)", state, name, detail)
}

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func (h *harness) execute() {
	h.sessionID = newUUID()
	h.short = strings.ReplaceAll(h.sessionID, "-", "")[:12]
	tok := make([]byte, 32)
	_, _ = rand.Read(tok)
	h.token = base64.RawURLEncoding.EncodeToString(tok)
	h.logger.Printf("session %s (containers *-%s)", h.sessionID, h.short)

	if err := h.resolveImage(); err != nil {
		h.add("image ref resolved", false, "%v", err)
		return
	}
	h.add("image ref resolved", true, "%s", h.imageRef)

	code, body, err := h.call("GET", "/v1/health", nil)
	if err != nil || code != http.StatusOK {
		h.add("supervisor health", false, "status %d err %v body %s", code, err, body)
		return
	}
	h.add("supervisor health", true, "%s", strings.TrimSpace(string(body)))

	h.ensureDemoApp()

	agentLn, err := net.Listen("tcp", net.JoinHostPort(hostAddress, strconv.Itoa(h.o.agentPort)))
	if err != nil {
		h.add("bind agent endpoint", false, "%v", err)
		return
	}
	defer agentLn.Close()
	proxyLn, err := net.Listen("tcp", net.JoinHostPort(hostAddress, strconv.Itoa(h.o.proxyPort)))
	if err != nil {
		h.add("bind proxy", false, "%v", err)
		return
	}
	defer proxyLn.Close()
	h.add("bind agent endpoint and proxy", true, "%s, %s", agentLn.Addr(), proxyLn.Addr())

	allowed, overrides, err := h.proxyConfig()
	if err != nil {
		h.add("proxy config", false, "%v", err)
		return
	}
	go h.serveProxy(proxyLn, allowed, overrides)

	caPem, err := os.ReadFile(h.o.caPath)
	if err != nil {
		h.add("read CA", false, "%v", err)
		return
	}
	req := map[string]any{
		"sessionId":        h.sessionID,
		"image":            h.imageRef,
		"runnerToken":      h.token,
		"gatewayAgentAddr": net.JoinHostPort(hostAddress, strconv.Itoa(h.o.agentPort)),
		"egressProxyAddr":  net.JoinHostPort(hostAddress, strconv.Itoa(h.o.proxyPort)),
		"startUrl":         h.o.startURL,
		"allowedHosts":     allowed,
		"caPem":            string(caPem),
		"policy":           map[string]any{"clipboard": "off", "downloads": "quarantine", "uploads": "block", "kiosk": true},
		"display":          map[string]int{"width": 1280, "height": 720, "framerate": 30},
		"recording":        map[string]int{"segmentSeconds": segmentSeconds, "bitrateKbps": 1500, "crf": 26},
		"resources":        map[string]any{"cpus": 1.5, "memoryMb": 1536, "pidsLimit": 512},
		"watermark":        map[string]string{"text": "iwa-harness " + h.short},
	}

	// The supervisor must refuse a bare tag even though it names the same image.
	bad := cloneMap(req)
	bad["sessionId"] = newUUID()
	bad["image"] = defaultImage
	code, body, _ = h.call("POST", "/v1/runners", bad)
	h.add("bare tag refused with 403 image_not_allowed", code == http.StatusForbidden && bytes.Contains(body, []byte("image_not_allowed")),
		"status %d", code)

	h.launchAt = time.Now()
	code, body, err = h.call("POST", "/v1/runners", req)
	if err != nil || code != http.StatusCreated {
		h.add("launch runner", false, "status %d err %v body %s", code, err, body)
		return
	}
	defer h.destroy()
	var launched struct {
		ContainerName string `json:"containerName"`
		IP            string `json:"ip"`
	}
	_ = json.Unmarshal(body, &launched)
	h.runnerIP = launched.IP
	h.add("launch runner", launched.ContainerName == "iwa-runner-"+h.short && net.ParseIP(h.runnerIP) != nil,
		"%s at %s", launched.ContainerName, launched.IP)

	conn, err := h.acceptAgent(agentLn)
	if err != nil {
		h.add("agent connected and authenticated", false, "%v", err)
		h.captureRunnerLogs()
		return
	}
	defer conn.Close()
	h.drive(conn)
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func (h *harness) resolveImage() error {
	if h.o.image != "" {
		at := strings.LastIndex(h.o.image, "@")
		if at < 0 || !strings.HasPrefix(h.o.image[at+1:], "sha256:") {
			return fmt.Errorf("-image must be name@sha256:<id>")
		}
		h.imageRef, h.imageID = h.o.image, h.o.image[at+1:]
		return nil
	}
	out, err := exec.Command("docker", "image", "inspect", "--format", "{{.Id}}", defaultImage).Output()
	if err != nil {
		return fmt.Errorf("docker image inspect %s: %v", defaultImage, err)
	}
	h.imageID = strings.TrimSpace(string(out))
	h.imageRef = "infisical-webapp-runner@" + h.imageID
	return nil
}

// call talks to the supervisor and appends a redacted line to supervisor-calls.log.
func (h *harness) call(method, path string, body any) (int, []byte, error) {
	var rd io.Reader
	logged := ""
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(b)
		if m, ok := body.(map[string]any); ok {
			red := cloneMap(m)
			if _, ok := red["runnerToken"]; ok {
				red["runnerToken"] = "<redacted>"
			}
			if ca, ok := red["caPem"].(string); ok {
				red["caPem"] = fmt.Sprintf("<%d bytes>", len(ca))
			}
			rb, _ := json.Marshal(red)
			logged = string(rb)
		}
	}
	req, err := http.NewRequest(method, "http://supervisor"+path, rd)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	start := time.Now()
	resp, err := h.client.Do(req)
	if err != nil {
		fmt.Fprintf(h.calls, "%s %s %s -> error %v\n", time.Now().Format(time.RFC3339Nano), method, path, err)
		return 0, nil, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	fmt.Fprintf(h.calls, "%s %s %s %s -> %d in %s %s\n", time.Now().Format(time.RFC3339Nano), method, path, logged,
		resp.StatusCode, time.Since(start).Round(time.Millisecond), strings.TrimSpace(string(rb)))
	return resp.StatusCode, rb, nil
}

func (h *harness) ensureDemoApp() {
	out, err := exec.Command("docker", "inspect", "--format", "{{.State.Running}}", demoAppName).Output()
	if err == nil && strings.TrimSpace(string(out)) == "true" {
		h.add("demo app running", true, "%s already running", demoAppName)
		return
	}
	if !h.o.startDemoApp {
		h.add("demo app running", false, "%s is not running; pass -start-demo-app", demoAppName)
		return
	}
	if err := exec.Command("docker", "network", "inspect", "iwa-apps").Run(); err != nil {
		if out, err := exec.Command("docker", "network", "create", "--subnet", "172.27.0.0/24", "iwa-apps").CombinedOutput(); err != nil {
			h.add("demo app running", false, "create iwa-apps: %v %s", err, out)
			return
		}
	}
	_ = exec.Command("docker", "rm", "-f", demoAppName).Run()
	out, err = exec.Command("docker", "run", "-d", "--name", demoAppName, "--network", "iwa-apps", "--ip", "172.27.0.10",
		"--network-alias", "app.corp.internal", "-v", h.o.spikeAppDir+":/app:ro", "--entrypoint", "python3",
		h.o.demoAppImage, "-u", "/app/app.py", "/app/app.crt", "/app/app.key").CombinedOutput()
	if err != nil {
		h.add("demo app running", false, "docker run: %v %s", err, out)
		return
	}
	time.Sleep(2 * time.Second)
	h.add("demo app running", true, "started %s", demoAppName)
}

func (h *harness) proxyConfig() ([]string, map[string]string, error) {
	u, err := url.Parse(h.o.startURL)
	if err != nil || u.Hostname() == "" {
		return nil, nil, fmt.Errorf("bad -start-url")
	}
	overrides := map[string]string{}
	for _, kv := range strings.Split(h.o.hostsOverr, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if !ok || net.ParseIP(v) == nil {
			if strings.TrimSpace(kv) == "" {
				continue
			}
			return nil, nil, fmt.Errorf("bad -hosts-override entry %q", kv)
		}
		overrides[strings.ToLower(k)] = v
	}
	return []string{strings.ToLower(u.Hostname())}, overrides, nil
}

// serveProxy is a CONNECT-only proxy: port 443 only, host allowlist, resolution through the override map.
func (h *harness) serveProxy(ln net.Listener, allowed []string, overrides map[string]string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go h.handleProxyConn(c, allowed, overrides)
	}
}

func (h *harness) proxyDecision(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	h.mu.Lock()
	h.proxyLog = append(h.proxyLog, line)
	h.mu.Unlock()
	h.logger.Printf("proxy %s", line)
}

func (h *harness) handleProxyConn(c net.Conn, allowed []string, overrides map[string]string) {
	defer c.Close()
	src := c.RemoteAddr().String()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		h.proxyDecision("deny src=%s: no request (%v)", src, err)
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	deny := func(code int, why string) {
		h.proxyDecision("deny src=%s %s %s: %s", src, req.Method, req.Host, why)
		fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", code, http.StatusText(code))
	}
	if req.Method != http.MethodConnect {
		deny(http.StatusMethodNotAllowed, "only CONNECT")
		return
	}
	host, port, err := net.SplitHostPort(req.Host)
	if err != nil || port != "443" {
		deny(http.StatusForbidden, "port must be 443")
		return
	}
	host = strings.ToLower(host)
	ok := false
	for _, a := range allowed {
		ok = ok || host == a
	}
	if !ok {
		deny(http.StatusForbidden, "host not in allowlist")
		return
	}
	ip, found := overrides[host]
	if !found {
		addrs, err := net.LookupHost(host)
		if err != nil || len(addrs) == 0 {
			deny(http.StatusBadGateway, "cannot resolve")
			return
		}
		ip = addrs[0]
	}
	up, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), 10*time.Second)
	if err != nil {
		deny(http.StatusBadGateway, "upstream dial failed")
		return
	}
	defer up.Close()
	h.proxyDecision("allow src=%s CONNECT %s -> %s:443", src, req.Host, ip)
	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if n := br.Buffered(); n > 0 {
		b, _ := br.Peek(n)
		if _, err := up.Write(b); err != nil {
			return
		}
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
	<-done
}

// acceptAgent waits for the runner's AGENT_HELLO, checks source IP and token, and answers AGENT_WELCOME. Other
// connections (the netns probe dials this port too) are read for a hello and dropped.
func (h *harness) acceptAgent(ln net.Listener) (net.Conn, error) {
	type result struct {
		conn  net.Conn
		hello *contract.AgentHello
	}
	got := make(chan result, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				src, _, _ := net.SplitHostPort(c.RemoteAddr().String())
				_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
				f, err := contract.ReadFrame(c, contract.MaxAgentPayload)
				if err != nil {
					h.logger.Printf("agent endpoint: connection from %s closed without a frame (%v)", src, err)
					c.Close()
					return
				}
				var hello contract.AgentHello
				if f.Type != contract.FrameAgentHello || json.Unmarshal(f.Payload, &hello) != nil {
					h.logger.Printf("agent endpoint: %s sent frame 0x%02x first, closing", src, f.Type)
					c.Close()
					return
				}
				tokOK := subtle.ConstantTimeCompare([]byte(hello.RunnerToken), []byte(h.token)) == 1
				if src != h.runnerIP || hello.SessionID != h.sessionID || !tokOK {
					h.logger.Printf("agent endpoint: refusing %s (ip ok %v, session ok %v, token ok %v)",
						src, src == h.runnerIP, hello.SessionID == h.sessionID, tokOK)
					w, _ := json.Marshal(contract.AgentWelcome{OK: false, Error: "unauthorized"})
					_ = contract.WriteFrame(c, &contract.Frame{Type: contract.FrameAgentWelcome, Payload: w})
					c.Close()
					return
				}
				_ = c.SetReadDeadline(time.Time{})
				select {
				case got <- result{conn: c, hello: &hello}:
				default:
					h.logger.Printf("agent endpoint: second authenticated link from %s, closing it", src)
					c.Close()
				}
			}(c)
		}
	}()
	select {
	case r := <-got:
		h.mu.Lock()
		h.hello = r.hello
		h.mu.Unlock()
		hello := r.hello
		h.add("agent connected and authenticated", true, "source %s, token and session match", h.runnerIP)
		h.add("AGENT_HELLO fields", contains(hello.LiveCodecs, "h264") && hello.RecordingCodec == "h264" &&
			hello.EncoderMode == "dual" && hello.ImageDigest == h.imageID,
			"liveCodecs %v recordingCodec %s encoderMode %s imageDigest %s display %dx%d@%d",
			hello.LiveCodecs, hello.RecordingCodec, hello.EncoderMode, hello.ImageDigest,
			hello.Display.Width, hello.Display.Height, hello.Display.Framerate)
		return r.conn, nil
	case <-time.After(agentWait):
		return nil, fmt.Errorf("no authenticated AGENT_HELLO within %s", agentWait)
	}
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

type agentLink struct {
	conn  net.Conn
	mu    sync.Mutex
	seq   uint32
	start time.Time
}

func (l *agentLink) send(t contract.FrameType, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	f := &contract.Frame{Type: t, Seq: l.seq, TimestampUs: uint64(time.Since(l.start).Microseconds()), Payload: payload}
	l.seq++
	_ = l.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	return contract.WriteFrame(l.conn, f)
}

func (h *harness) drive(conn net.Conn) {
	link := &agentLink{conn: conn, start: time.Now()}
	live, err := os.Create(filepath.Join(h.o.out, "live.h264"))
	if err != nil {
		h.add("create live.h264", false, "%v", err)
		return
	}
	h.liveFile = live
	defer live.Close()

	welcome := map[string]any{"ok": true, "recording": map[string]int{"segmentSeconds": segmentSeconds}}
	if err := link.send(contract.FrameAgentWelcome, welcome); err != nil {
		h.add("send AGENT_WELCOME", false, "%v", err)
		return
	}
	readDone := make(chan error, 1)
	go func() { readDone <- h.readLoop(conn) }()

	if err := link.send(contract.FrameAgentControl, contract.AgentControl{Kind: "live_start", Codec: "h264"}); err != nil {
		h.add("send live_start", false, "%v", err)
		return
	}
	h.mu.Lock()
	h.startClock = time.Now()
	h.mu.Unlock()
	h.logger.Printf("live_start sent; collecting for %s", h.o.duration)

	kf := time.After(keyframeAt)
	in := time.After(inputAt)
	end := time.After(h.o.duration)
	inputDone := make(chan struct{})
	var readErr error
	ended := false
collect:
	for {
		select {
		case <-kf:
			h.mu.Lock()
			h.kfRequestAt = len(h.chunks)
			h.mu.Unlock()
			h.logger.Printf("sending AGENT_CONTROL keyframe at chunk %d", h.kfRequestAt)
			_ = link.send(contract.FrameAgentControl, contract.AgentControl{Kind: "keyframe"})
		case <-in:
			go func() {
				h.waitForStartPage(time.Until(h.startClock.Add(h.o.duration - 3*time.Second)))
				h.injectInput(link)
				close(inputDone)
			}()
		case <-end:
			break collect
		case readErr = <-readDone:
			ended = true
			break collect
		}
	}
	if ended {
		h.add("agent link stays up for the collection window", false, "link closed early: %v", readErr)
	} else {
		select {
		case <-inputDone:
		case <-time.After(10 * time.Second):
		}
		h.netnsCheck()
		h.statusCheck("running")
		h.logger.Printf("sending AGENT_CONTROL shutdown")
		_ = link.send(contract.FrameAgentControl, contract.AgentControl{Kind: "shutdown", Reason: "harness_done"})
		select {
		case readErr = <-readDone:
			h.add("agent closes the link after shutdown", true, "read loop ended: %v", readErr)
		case <-time.After(shutdownWait):
			h.add("agent closes the link after shutdown", false, "still open after %s", shutdownWait)
		}
	}
	h.captureRunnerLogs()
}

func (h *harness) readLoop(conn net.Conn) error {
	for {
		_ = conn.SetReadDeadline(time.Now().Add(45 * time.Second))
		f, err := contract.ReadFrame(conn, contract.MaxAgentPayload)
		if err != nil {
			return err
		}
		switch f.Type {
		case contract.FrameVideoConfig:
			var vc contract.VideoConfig
			if err := json.Unmarshal(f.Payload, &vc); err != nil {
				h.logger.Printf("bad VIDEO_CONFIG: %v", err)
				continue
			}
			h.mu.Lock()
			if h.videoConfig == nil {
				h.videoConfig = &vc
			}
			h.configCount++
			h.mu.Unlock()
			h.logger.Printf("VIDEO_CONFIG %s", f.Payload)
		case contract.FrameVideoChunk:
			h.mu.Lock()
			ci := chunkInfo{Index: len(h.chunks), Keyframe: f.Flags&contract.FlagKeyframe != 0, PtsUs: f.TimestampUs,
				Bytes: len(f.Payload)}
			if !h.startClock.IsZero() {
				ci.ArrivalMs = time.Since(h.startClock).Milliseconds()
			}
			if ci.Index == 0 {
				h.firstChunk = append([]byte(nil), f.Payload...)
			}
			h.chunks = append(h.chunks, ci)
			_, werr := h.liveFile.Write(f.Payload)
			h.mu.Unlock()
			if werr != nil {
				return werr
			}
		case contract.FrameRecInit:
			var meta contract.RecInitMeta
			body, err := contract.UnmarshalMetaPrefixed(f.Payload, &meta)
			if err != nil {
				h.logger.Printf("bad REC_INIT: %v", err)
				continue
			}
			if err := os.WriteFile(filepath.Join(h.o.out, "rec-init.mp4"), body, 0o644); err != nil {
				return err
			}
			h.mu.Lock()
			h.recInit = &meta
			h.mu.Unlock()
			h.logger.Printf("REC_INIT %d bytes codec %s", len(body), meta.Codec)
		case contract.FrameRecSegment:
			var meta contract.RecSegmentMeta
			body, err := contract.UnmarshalMetaPrefixed(f.Payload, &meta)
			if err != nil {
				h.logger.Printf("bad REC_SEGMENT: %v", err)
				continue
			}
			sum := sha256.Sum256(body)
			name := fmt.Sprintf("rec-seg-%04d.mp4", meta.SegmentIndex)
			if err := os.WriteFile(filepath.Join(h.o.out, name), body, 0o644); err != nil {
				return err
			}
			si := segInfo{Meta: meta, File: name, ShaOK: hex.EncodeToString(sum[:]) == meta.SHA256, Bytes: len(body),
				Received: time.Now()}
			h.mu.Lock()
			h.segs = append(h.segs, si)
			h.mu.Unlock()
			h.logger.Printf("REC_SEGMENT %d: %d bytes, frames %d, pts %d..%d, sha256 ok %v", meta.SegmentIndex,
				len(body), meta.FrameCount, meta.StartPtsUs, meta.EndPtsUs, si.ShaOK)
		case contract.FrameRecLoss:
			var loss contract.RecLoss
			_ = json.Unmarshal(f.Payload, &loss)
			h.mu.Lock()
			h.losses = append(h.losses, loss)
			h.mu.Unlock()
			h.logger.Printf("REC_LOSS %s", f.Payload)
		case contract.FrameAgentEvent:
			h.mu.Lock()
			h.events = append(h.events, append(json.RawMessage(nil), f.Payload...))
			h.mu.Unlock()
			h.logger.Printf("AGENT_EVENT %s", f.Payload)
		default:
			h.logger.Printf("unexpected frame 0x%02x (%d bytes) from agent", f.Type, len(f.Payload))
		}
	}
}

// Page geometry of /input in a 1280x720 kiosk (body margin 24px, font 18px): h1 to about y=90, #txt 24px font on
// y 90..124 and 606px wide, #btn block below at y 132..166, #scroller 300px tall below it.
var (
	txtPoint      = [2]int{300, 107}
	btnPoint      = [2]int{70, 149}
	scrollerPoint = [2]int{640, 320}
)

func keyCode(r rune) string {
	switch {
	case r >= 'a' && r <= 'z':
		return "Key" + strings.ToUpper(string(r))
	case r >= '0' && r <= '9':
		return "Digit" + string(r)
	case r == ' ':
		return "Space"
	}
	return ""
}

func (h *harness) injectInput(link *agentLink) {
	ts := func() float64 { return float64(time.Since(link.start).Microseconds()) / 1000 }
	send := func(evs ...contract.InputEvent) {
		if err := link.send(contract.FrameInputInject, contract.InputBatch{Events: evs}); err != nil {
			h.logger.Printf("INPUT_INJECT send: %v", err)
		}
		time.Sleep(40 * time.Millisecond)
	}
	click := func(p [2]int) {
		send(contract.InputEvent{T: "move", X: p[0], Y: p[1], Ts: ts()})
		send(contract.InputEvent{T: "button", Action: "down", Button: 0, X: p[0], Y: p[1], Ts: ts()})
		send(contract.InputEvent{T: "button", Action: "up", Button: 0, X: p[0], Y: p[1], Ts: ts()})
	}
	h.mu.Lock()
	h.inputChunk = len(h.chunks)
	h.mu.Unlock()
	h.logger.Printf("injecting input: click #txt, type %q, Enter, click #btn, wheel", typedText)

	click(txtPoint)
	for _, r := range typedText {
		k := string(r)
		send(contract.InputEvent{T: "key", Action: "down", Code: keyCode(r), Key: k, Ts: ts()},
			contract.InputEvent{T: "key", Action: "up", Code: keyCode(r), Key: k, Ts: ts()})
	}
	send(contract.InputEvent{T: "key", Action: "down", Code: "Enter", Key: "Enter", Ts: ts()},
		contract.InputEvent{T: "key", Action: "up", Code: "Enter", Key: "Enter", Ts: ts()})
	time.Sleep(300 * time.Millisecond)
	click(btnPoint)
	time.Sleep(300 * time.Millisecond)
	send(contract.InputEvent{T: "move", X: scrollerPoint[0], Y: scrollerPoint[1], Ts: ts()})
	for i := 0; i < 5; i++ {
		send(contract.InputEvent{T: "wheel", DY: 120, X: scrollerPoint[0], Y: scrollerPoint[1], Ts: ts()})
	}
	h.logger.Printf("input injected")
}

// waitForStartPage polls the demo app log until it served the start URL path, then leaves the page a moment to
// render, so input is not typed into a blank tab. It gives up after max and injects anyway.
func (h *harness) waitForStartPage(max time.Duration) {
	u, err := url.Parse(h.o.startURL)
	if err != nil {
		return
	}
	needle := fmt.Sprintf(`"method": "GET", "path": %q`, u.RequestURI())
	since := h.launchAt.Add(-2 * time.Second).UTC().Format(time.RFC3339)
	deadline := time.Now().Add(max)
	for {
		out, _ := exec.Command("docker", "logs", "--since", since, demoAppName).CombinedOutput()
		if bytes.Contains(out, []byte(needle)) {
			loaded := time.Since(h.launchAt)
			h.addCheck("start page served within 10 s of launch", loaded <= 10*time.Second, false,
				"served %s after launch", loaded.Round(100*time.Millisecond))
			time.Sleep(1500 * time.Millisecond)
			return
		}
		if time.Now().After(deadline) {
			h.addCheck("start page served within 10 s of launch", false, false, "not served after %s; injecting anyway",
				time.Since(h.launchAt).Round(100*time.Millisecond))
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// netnsCheck runs the image's probe inside the runner netns: host ports 80/8080 and DNS must fail, the two gateway
// ports must connect.
func (h *harness) netnsCheck() {
	agent := fmt.Sprintf("tcp:%s:%d", hostAddress, h.o.agentPort)
	proxy := fmt.Sprintf("tcp:%s:%d", hostAddress, h.o.proxyPort)
	want := map[string]bool{
		"tcp:172.28.0.1:80": false, "tcp:172.28.0.1:8080": false, agent: true, proxy: true, "dns:iwa-demo-app": false,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	args := []string{"run", "--rm", "--network", "container:iwa-netns-" + h.short, "--label", sessionLabel + "=" + h.sessionID,
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "1000:1000",
		"--entrypoint", "python3", h.imageID, "/opt/iwa/netprobe.py",
		"tcp:172.28.0.1:80", "tcp:172.28.0.1:8080", agent, proxy, "dns:iwa-demo-app"}
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	results := []map[string]any{}
	got := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		var r map[string]any
		if json.Unmarshal([]byte(strings.TrimSpace(line)), &r) != nil {
			continue
		}
		results = append(results, r)
		if c, ok := r["check"].(string); ok {
			okv, _ := r["ok"].(bool)
			got[c] = okv
		}
	}
	h.mu.Lock()
	h.netns = results
	h.mu.Unlock()
	doc := map[string]any{"command": "docker " + strings.Join(args, " "), "results": results, "expected": want}
	if err != nil {
		doc["error"] = fmt.Sprintf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	_ = os.WriteFile(filepath.Join(h.o.out, "netns-check.json"), b, 0o644)
	var bad []string
	for c, w := range want {
		if g, ok := got[c]; !ok || g != w {
			bad = append(bad, fmt.Sprintf("%s ok=%v want %v", c, g, w))
		}
	}
	sort.Strings(bad)
	h.add("netns reachability (80/8080/dns fail, agent/proxy ok)", err == nil && len(bad) == 0, "%s",
		orDefault(strings.Join(bad, "; "), fmt.Sprintf("%d probes as expected", len(want))))
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func (h *harness) statusCheck(want string) {
	code, body, err := h.call("GET", "/v1/runners/"+h.sessionID, nil)
	var st struct {
		State string `json:"state"`
		IP    string `json:"ip"`
	}
	_ = json.Unmarshal(body, &st)
	h.add("supervisor status "+want, err == nil && code == http.StatusOK && st.State == want && st.IP == h.runnerIP,
		"status %d state %s ip %s", code, st.State, st.IP)
}

// captureRunnerLogs saves the runner's docker logs (redacted) and checks the token never appears.
func (h *harness) captureRunnerLogs() {
	name := "iwa-runner-" + h.short
	out, err := exec.Command("docker", "logs", name).CombinedOutput()
	if err != nil {
		h.add("runner logs captured", false, "%v", err)
		return
	}
	leak := bytes.Contains(out, []byte(h.token))
	if leak {
		out = bytes.ReplaceAll(out, []byte(h.token), []byte("<REDACTED-TOKEN>"))
	}
	_ = os.WriteFile(filepath.Join(h.o.out, "runner.log"), out, 0o644)
	h.add("runner token absent from runner logs", !leak, "%d bytes of docker logs", len(out))

	img, err := exec.Command("docker", "inspect", "--format", "{{.Image}}", name).Output()
	h.add("runner image ID equals pinned digest", err == nil && strings.TrimSpace(string(img)) == h.imageID,
		"running %s, pinned %s", strings.TrimSpace(string(img)), h.imageID)
}

func (h *harness) destroy() {
	for i := 0; i < 2; i++ {
		code, body, err := h.call("DELETE", "/v1/runners/"+h.sessionID, nil)
		h.add(fmt.Sprintf("DELETE runner (call %d) returns 200 destroyed", i+1),
			err == nil && code == http.StatusOK && bytes.Contains(body, []byte(`"destroyed"`)), "status %d", code)
	}
	out, err := exec.Command("docker", "ps", "-a", "--filter", "label="+sessionLabel+"="+h.sessionID,
		"--format", "{{.Names}}").Output()
	left := strings.Fields(string(out))
	h.add("no containers left for the session", err == nil && len(left) == 0, "leftover %v", left)
}

func (h *harness) writeSummary() {
	h.verifyOutputs()
	h.mu.Lock()
	defer h.mu.Unlock()
	summary := map[string]any{
		"sessionId":       h.sessionID,
		"containerSuffix": h.short,
		"runnerIp":        h.runnerIP,
		"imageRef":        h.imageRef,
		"imageId":         h.imageID,
		"launchAt":        h.launchAt.Format(time.RFC3339Nano),
		"agentHello":      redactHello(h.hello),
		"videoConfig":     h.videoConfig,
		"videoConfigs":    h.configCount,
		"liveChunks":      len(h.chunks),
		"liveKeyframes":   keyframeIndexes(h.chunks),
		"keyframeRequest": h.kfRequestAt,
		"inputAtChunk":    h.inputChunk,
		"recInit":         h.recInit,
		"recSegments":     h.segs,
		"recLosses":       h.losses,
		"agentEvents":     h.events,
		"proxy":           h.proxyLog,
		"netns":           h.netns,
		"checks":          h.checks,
	}
	b, _ := json.MarshalIndent(summary, "", "  ")
	_ = os.WriteFile(filepath.Join(h.o.out, "summary.json"), b, 0o644)
}

func redactHello(hello *contract.AgentHello) any {
	if hello == nil {
		return nil
	}
	c := *hello
	c.RunnerToken = "<redacted>"
	return c
}

func keyframeIndexes(chunks []chunkInfo) []int {
	var out []int
	for _, c := range chunks {
		if c.Keyframe {
			out = append(out, c.Index)
		}
	}
	return out
}

func (h *harness) report() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	failed := 0
	fmt.Println()
	fmt.Printf("%-6s %-58s %s\n", "RESULT", "CHECK", "DETAIL")
	for _, c := range h.checks {
		state := "PASS"
		if !c.OK {
			state = "WARN"
			if c.Fatal {
				state = "FAIL"
				failed++
			}
		}
		fmt.Printf("%-6s %-58s %s\n", state, c.Name, c.Detail)
	}
	fmt.Printf("\n%d checks, %d failed; outputs in %s\n", len(h.checks), failed, h.o.out)
	if failed > 0 || len(h.checks) == 0 {
		return 1
	}
	return 0
}

// nalTypes lists the H.264 NAL unit types of an Annex B buffer.
func nalTypes(b []byte) []int {
	var out []int
	for i := 0; i+3 < len(b); i++ {
		if b[i] == 0 && b[i+1] == 0 && b[i+2] == 1 {
			out = append(out, int(b[i+3]&0x1f))
			i += 3
		}
	}
	return out
}

// spsCodec derives the WebCodecs avc1 string from the first SPS in an Annex B buffer.
func spsCodec(b []byte) string {
	for i := 0; i+6 < len(b); i++ {
		if b[i] == 0 && b[i+1] == 0 && b[i+2] == 1 && b[i+3]&0x1f == 7 {
			return fmt.Sprintf("avc1.%02X%02X%02X", b[i+4], b[i+5], b[i+6])
		}
	}
	return "none"
}

func codecOf(vc *contract.VideoConfig) string {
	if vc == nil {
		return "none"
	}
	return vc.Codec
}

func hasInt(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func ffprobeJSON(args ...string) (map[string]any, error) {
	out, err := exec.Command("ffprobe", append([]string{"-v", "error", "-of", "json"}, args...)...).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, err
	}
	var m map[string]any
	return m, json.Unmarshal(out, &m)
}

func firstStream(m map[string]any) map[string]any {
	ss, _ := m["streams"].([]any)
	if len(ss) == 0 {
		return map[string]any{}
	}
	s, _ := ss[0].(map[string]any)
	return s
}

func (h *harness) verifyOutputs() {
	h.mu.Lock()
	vc, chunks, first, kfAt, inputChunk := h.videoConfig, append([]chunkInfo(nil), h.chunks...), h.firstChunk, h.kfRequestAt, h.inputChunk
	recInit, segs := h.recInit, append([]segInfo(nil), h.segs...)
	h.mu.Unlock()
	if h.launchAt.IsZero() {
		return
	}

	// CONTRACTS 1.6: codec is the exact WebCodecs string of the stream, so it must be an H.264 Constrained Baseline
	// avc1 string (profile 0x42, the family the viewer probes with avc1.42E01F) equal to what the first SPS says.
	h.add("VIDEO_CONFIG avc1.42xxxx annexb", vc != nil && strings.HasPrefix(strings.ToLower(vc.Codec), "avc1.42") && vc.Format == "annexb",
		"%+v", vc)
	h.add("VIDEO_CONFIG codec matches the stream SPS", vc != nil && strings.EqualFold(vc.Codec, spsCodec(first)),
		"config %v, SPS says %s", codecOf(vc), spsCodec(first))
	nals := nalTypes(first)
	h.add("first VIDEO_CHUNK is a keyframe (flag and IDR with SPS/PPS)",
		len(chunks) > 0 && chunks[0].Keyframe && hasInt(nals, 5) && hasInt(nals, 7) && hasInt(nals, 8),
		"chunks %d, first NAL types %v", len(chunks), nals)

	if kfAt >= 0 {
		idx := -1
		for _, c := range chunks {
			if c.Index >= kfAt && c.Keyframe {
				idx = c.Index
				break
			}
		}
		h.add("AGENT_CONTROL keyframe answered within 2 frames", idx >= 0 && idx-kfAt <= 3,
			"requested at chunk %d, keyframe chunk %d (delta %d; one chunk of slack for frames already in flight)",
			kfAt, idx, idx-kfAt)
	} else {
		h.add("AGENT_CONTROL keyframe answered within 2 frames", false, "keyframe never requested")
	}

	livePath := filepath.Join(h.o.out, "live.h264")
	if m, err := ffprobeJSON("-f", "h264", "-count_frames", "-select_streams", "v:0",
		"-show_entries", "stream=codec_name,profile,width,height,nb_read_frames", livePath); err != nil {
		h.add("ffprobe decodes live.h264", false, "%v", err)
	} else {
		s := firstStream(m)
		n, _ := strconv.Atoi(fmt.Sprint(s["nb_read_frames"]))
		h.add("ffprobe decodes live.h264", s["codec_name"] == "h264" && n > 0,
			"codec %v profile %v %vx%v, %d frames decoded of %d chunks", s["codec_name"], s["profile"], s["width"], s["height"], n, len(chunks))
	}
	_ = exec.Command("ffmpeg", "-v", "error", "-y", "-f", "h264", "-i", livePath, "-update", "1",
		filepath.Join(h.o.out, "frame-live-last.png")).Run()
	if inputChunk > 0 {
		_ = exec.Command("ffmpeg", "-v", "error", "-y", "-f", "h264", "-i", livePath, "-vf",
			fmt.Sprintf("select=eq(n\\,%d)", inputChunk), "-frames:v", "1", filepath.Join(h.o.out, "frame-live-before-input.png")).Run()
	}

	h.add("REC_INIT received", recInit != nil, "%+v", recInit)
	shaBad := []int{}
	for _, s := range segs {
		if !s.ShaOK {
			shaBad = append(shaBad, s.Meta.SegmentIndex)
		}
	}
	h.add("every REC_SEGMENT sha256 matches", len(segs) > 0 && len(shaBad) == 0, "%d segments, mismatches %v", len(segs), shaBad)
	for i, s := range segs {
		if s.Meta.SegmentIndex != i+1 {
			h.add("REC_SEGMENT indexes 1..n", false, "position %d has index %d", i, s.Meta.SegmentIndex)
			break
		}
	}
	if recInit != nil {
		for _, s := range segs {
			h.verifySegment(s, s.Meta.SegmentIndex == 1)
		}
		if len(segs) == 0 || segs[0].Meta.SegmentIndex != 1 {
			h.add("segment 1 is H.264 High, 10 s +/- 1 frame, starts with IDR", false, "segment 1 missing")
		}
	}

	h.verifyDemoApp()
	h.scanHarnessLogs()
}

func (h *harness) verifySegment(s segInfo, strict bool) {
	initB, err1 := os.ReadFile(filepath.Join(h.o.out, "rec-init.mp4"))
	segB, err2 := os.ReadFile(filepath.Join(h.o.out, s.File))
	name := fmt.Sprintf("segment %d is H.264 High, %d s +/- 1 frame, starts with IDR", s.Meta.SegmentIndex, segmentSeconds)
	if !strict {
		name = fmt.Sprintf("segment %d is H.264 High, starts with IDR", s.Meta.SegmentIndex)
	}
	if err1 != nil || err2 != nil {
		h.addCheck(name, false, strict, "read: %v %v", err1, err2)
		return
	}
	concat := filepath.Join(h.o.out, fmt.Sprintf("rec-concat-%04d.mp4", s.Meta.SegmentIndex))
	if err := os.WriteFile(concat, append(append([]byte(nil), initB...), segB...), 0o644); err != nil {
		h.addCheck(name, false, strict, "%v", err)
		return
	}
	m, err := ffprobeJSON("-count_frames", "-select_streams", "v:0",
		"-show_entries", "stream=codec_name,profile,nb_read_frames,r_frame_rate:format=duration", concat)
	if err != nil {
		h.addCheck(name, false, strict, "ffprobe: %v", err)
		return
	}
	st := firstStream(m)
	format, _ := m["format"].(map[string]any)
	dur, _ := strconv.ParseFloat(fmt.Sprint(format["duration"]), 64)
	frames, _ := strconv.Atoi(fmt.Sprint(st["nb_read_frames"]))
	fps := 30.0
	if num, den, ok := strings.Cut(fmt.Sprint(st["r_frame_rate"]), "/"); ok {
		n, _ := strconv.ParseFloat(num, 64)
		d, _ := strconv.ParseFloat(den, 64)
		if n > 0 && d > 0 {
			fps = n / d
		}
	}
	// fMP4 fragments carry their absolute decode time, so the probed format duration is the end time; the segment
	// length is its frame count over the frame rate (and the meta PTS span as a cross-check).
	segDur := float64(frames) / fps
	tol := 1/fps + 0.001
	durOK := math.Abs(segDur-segmentSeconds) <= tol &&
		math.Abs(float64(s.Meta.EndPtsUs-s.Meta.StartPtsUs)/1e6-segmentSeconds) <= tol

	fm, ferr := ffprobeJSON("-select_streams", "v:0", "-read_intervals", "%+#1", "-show_frames",
		"-show_entries", "frame=key_frame,pict_type", concat)
	firstKey, firstPict := "", ""
	if ferr == nil {
		if fs, _ := fm["frames"].([]any); len(fs) > 0 {
			f0, _ := fs[0].(map[string]any)
			firstKey, firstPict = fmt.Sprint(f0["key_frame"]), fmt.Sprint(f0["pict_type"])
		}
	}
	annexb, _ := exec.Command("ffmpeg", "-v", "error", "-i", concat, "-frames:v", "1", "-c:v", "copy",
		"-bsf:v", "h264_mp4toannexb", "-f", "h264", "-").Output()
	nals := nalTypes(annexb)
	idr := firstKey == "1" && firstPict == "I" && hasInt(nals, 5)

	ok := st["codec_name"] == "h264" && st["profile"] == "High" && idr && (durOK || !strict)
	h.addCheck(name, ok, strict, "codec %v profile %v length %.3fs (%d frames @ %.2f fps, meta %d frames, pts %d..%d us, probed end %.3fs) first frame key=%s pict=%s NALs %v",
		st["codec_name"], st["profile"], segDur, frames, fps, s.Meta.FrameCount, s.Meta.StartPtsUs, s.Meta.EndPtsUs, dur,
		firstKey, firstPict, nals)
	if s.Meta.SegmentIndex == 1 {
		_ = exec.Command("ffmpeg", "-v", "error", "-y", "-i", concat, "-frames:v", "1",
			filepath.Join(h.o.out, "frame-rec-0001.png")).Run()
	}
}

// verifyDemoApp reads the demo app's JSON log since launch for the input probe events.
func (h *harness) verifyDemoApp() {
	since := h.launchAt.Add(-2 * time.Second).UTC().Format(time.RFC3339)
	out, err := exec.Command("docker", "logs", "--since", since, demoAppName).CombinedOutput()
	if err != nil {
		h.add("demo app saw typed text", false, "docker logs: %v", err)
		return
	}
	_ = os.WriteFile(filepath.Join(h.o.out, "demo-app.log"), out, 0o644)
	var typed, clicked, scrolled, pageLoaded bool
	var seen []string
	for _, line := range strings.Split(string(out), "\n") {
		var entry struct {
			Method string `json:"method"`
			Path   string `json:"path"`
			Body   string `json:"body"`
		}
		if json.Unmarshal([]byte(strings.TrimSpace(line)), &entry) != nil {
			continue
		}
		if entry.Method == "GET" && strings.HasPrefix(entry.Path, "/input") {
			pageLoaded = true
		}
		if entry.Method != "POST" || entry.Path != "/event" {
			continue
		}
		var ev struct {
			Probe string `json:"probe"`
			Type  string `json:"type"`
			Value string `json:"value"`
		}
		if json.Unmarshal([]byte(entry.Body), &ev) != nil || ev.Probe != "input" {
			continue
		}
		seen = append(seen, ev.Type)
		switch ev.Type {
		case "enter", "text":
			typed = typed || strings.Contains(ev.Value, typedText)
		case "click":
			clicked = true
		case "scroll":
			scrolled = true
		}
	}
	h.add("runner loaded the start page through the proxy", pageLoaded, "GET /input in demo app log")
	h.add("demo app saw typed text", typed, "input events %v", seen)
	h.add("demo app saw the button click", clicked, "input events %v", seen)
	h.addCheck("demo app saw the wheel scroll", scrolled, false, "input events %v", seen)
}

func (h *harness) scanHarnessLogs() {
	files := []string{filepath.Join(h.o.out, "harness.log"), filepath.Join(h.o.out, "supervisor-calls.log")}
	if h.o.supLog != "" {
		files = append(files, h.o.supLog)
	}
	var leaks []string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err == nil && h.token != "" && bytes.Contains(b, []byte(h.token)) {
			leaks = append(leaks, filepath.Base(f))
		}
	}
	h.add("runner token absent from harness and supervisor logs", len(leaks) == 0, "scanned %d files, leaks in %v", len(files), leaks)
}
