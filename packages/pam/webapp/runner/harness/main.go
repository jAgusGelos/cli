// Command iwa-harness is the standalone F1 fake gateway: it launches a runner through the supervisor socket, speaks
// the agent link with F0's contract codec, serves a CONNECT-only allowlist proxy, drives input, and verifies the live
// stream, the recording segments, the netns lockdown and the cleanup. It exits non-zero on any failed check.
//
// Optional scenarios: -codec vp9 (VP9 live), -lockdown (kiosk escape smoke, AD-7), -measure N (docker stats under
// scroll motion), -stall-test (SIGSTOP Xvfb, expects one REC_LOSS capture_stall), -reconnect-test (agent re-dial).
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/webapp/contract"
	"github.com/Infisical/infisical-merge/packages/pam/webapp/supervisor"
)

const (
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
	socket        string
	image         string
	agentPort     int
	proxyPort     int
	out           string
	startDemoApp  bool
	duration      time.Duration
	startURL      string
	caPath        string
	hostsOverr    string
	demoAppImage  string
	spikeAppDir   string
	supLog        string
	codec         string
	lockdown      bool
	measure       int
	stallTest     bool
	reconnectTest bool
}

func parseFlags() options {
	var o options
	flag.StringVar(&o.socket, "socket", envOr(supervisor.EnvSocket, supervisor.DefaultSocketPath), "supervisor unix socket")
	flag.StringVar(&o.image, "image", "", "allowlisted image ref name@sha256:<id> (default: resolved from "+defaultImage+")")
	flag.IntVar(&o.agentPort, "agent-port", 17701, "agent link port on 172.28.0.1 (never 7701)")
	flag.IntVar(&o.proxyPort, "proxy-port", 13128, "CONNECT proxy port on 172.28.0.1 (never 3128)")
	flag.StringVar(&o.out, "out", "", "output directory (required)")
	flag.BoolVar(&o.startDemoApp, "start-demo-app", false, "start "+demoAppName+" on iwa-apps if it is not running")
	flag.DurationVar(&o.duration, "duration", 25*time.Second, "minimum collection time after live_start")
	flag.StringVar(&o.startURL, "start-url", "https://app.corp.internal/input", "runner start URL (-lockdown default: /login)")
	flag.StringVar(&o.caPath, "ca", "/home/agus/Escritorio/Infisical/spikes/rbi-runner/pki/app-ca.crt", "CA certificate passed as caPem")
	flag.StringVar(&o.hostsOverr, "hosts-override", "app.corp.internal=172.27.0.10", "comma-separated host=ip for the proxy resolver")
	flag.StringVar(&o.demoAppImage, "demo-app-image", "mitmproxy/mitmproxy:11.1.3", "image for -start-demo-app")
	flag.StringVar(&o.spikeAppDir, "spike-app-dir", "/home/agus/Escritorio/Infisical/spikes/rbi-runner/app", "spike app dir for -start-demo-app")
	flag.StringVar(&o.supLog, "supervisor-log", "", "optional supervisor log file to scan for the runner token")
	flag.StringVar(&o.codec, "codec", "h264", "live codec sent in live_start: h264 or vp9")
	flag.BoolVar(&o.lockdown, "lockdown", false, "run the lockdown smoke (F12, Ctrl+Shift+I, Ctrl+N, chrome://settings, Shift+Esc, Ctrl+P, rogue CRX)")
	flag.IntVar(&o.measure, "measure", 0, "seconds of docker stats sampling under scroll motion (0: off)")
	flag.BoolVar(&o.stallTest, "stall-test", false, "SIGSTOP Xvfb for 2 s and expect one REC_LOSS capture_stall")
	flag.BoolVar(&o.reconnectTest, "reconnect-test", false, "close the agent link mid-run and expect a re-dial with continued segments")
	flag.Parse()
	urlSet := false
	flag.Visit(func(f *flag.Flag) { urlSet = urlSet || f.Name == "start-url" })
	if o.lockdown && !urlSet {
		o.startURL = "https://app.corp.internal/login"
	}
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
	Epoch     int    `json:"epoch"`
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
	Link     int                     `json:"link"`
	Received time.Time               `json:"-"`
}

type agentEvent struct {
	AtMs    int64           `json:"atMs"`
	Payload json.RawMessage `json:"payload"`
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

	mu           sync.Mutex
	checks       []check
	hello        *contract.AgentHello
	hellos       []contract.AgentHello
	videoConfig  *contract.VideoConfig
	videoConfigs []contract.VideoConfig
	chunks       []chunkInfo
	firstChunk   []byte
	live         liveWriter
	recInit      *contract.RecInitMeta
	recInits     int
	segs         []segInfo
	losses       []contract.RecLoss
	events       []agentEvent
	proxyLog     []string
	kfRequestAt  int // chunk count when the keyframe request went out, -1 before
	inputChunk   int
	inputRan     bool
	startClock   time.Time
	netns        []map[string]any
	link         *agentLink
	linkGen      int
	lockdownRun  *lockdownRun
	measureRes   *measureResult
	faults       map[string]any
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
	if o.codec != "h264" && o.codec != "vp9" {
		fmt.Fprintln(os.Stderr, "-codec must be h264 or vp9")
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
		faults:      map[string]any{},
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
	h.logger.Printf("check %s: %s (%s)", checkState(ok, fatal), name, detail)
}

func checkState(ok, fatal bool) string {
	switch {
	case ok:
		return "PASS"
	case fatal:
		return "FAIL"
	default:
		return "WARN"
	}
}

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func (h *harness) runnerName() string { return supervisor.RunnerName(h.short) }

func (h *harness) execute() {
	h.sessionID = newUUID()
	h.short = supervisor.ShortID(h.sessionID)
	tok := make([]byte, 32)
	_, _ = rand.Read(tok)
	h.token = base64.RawURLEncoding.EncodeToString(tok)
	h.logger.Printf("session %s (containers *-%s), codec %s, lockdown %v, measure %ds, stall %v, reconnect %v",
		h.sessionID, h.short, h.o.codec, h.o.lockdown, h.o.measure, h.o.stallTest, h.o.reconnectTest)

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

	agentLn, err := net.Listen("tcp", net.JoinHostPort(supervisor.HostAddress, strconv.Itoa(h.o.agentPort)))
	if err != nil {
		h.add("bind agent endpoint", false, "%v", err)
		return
	}
	defer agentLn.Close()
	proxyLn, err := net.Listen("tcp", net.JoinHostPort(supervisor.HostAddress, strconv.Itoa(h.o.proxyPort)))
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
	req := h.launchRequest(allowed, caPem)

	// The supervisor must refuse a bare tag even though it names the same image.
	bad := maps.Clone(req)
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
	h.add("launch runner", launched.ContainerName == h.runnerName() && net.ParseIP(h.runnerIP) != nil,
		"%s at %s", launched.ContainerName, launched.IP)

	links := h.acceptAgents(agentLn)
	select {
	case a := <-links:
		h.checkHello(a.hello, 1)
		h.drive(a, links)
	case <-time.After(agentWait):
		h.add("agent connected and authenticated", false, "no authenticated AGENT_HELLO within %s", agentWait)
		h.captureRunnerLogs()
	}
}

func (h *harness) launchRequest(allowed []string, caPem []byte) map[string]any {
	return map[string]any{
		"sessionId":        h.sessionID,
		"image":            h.imageRef,
		"runnerToken":      h.token,
		"gatewayAgentAddr": net.JoinHostPort(supervisor.HostAddress, strconv.Itoa(h.o.agentPort)),
		"egressProxyAddr":  net.JoinHostPort(supervisor.HostAddress, strconv.Itoa(h.o.proxyPort)),
		"startUrl":         h.o.startURL,
		"allowedHosts":     allowed,
		"caPem":            string(caPem),
		"policy":           map[string]any{"clipboard": "off", "downloads": "quarantine", "uploads": "block", "kiosk": true},
		"display":          map[string]int{"width": 1280, "height": 720, "framerate": 30},
		"recording":        map[string]int{"segmentSeconds": segmentSeconds, "bitrateKbps": 1500, "crf": 26},
		"resources":        map[string]any{"cpus": 1.5, "memoryMb": 1536, "pidsLimit": 512},
		"watermark":        map[string]string{"text": "iwa-harness " + h.short},
	}
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
			red := maps.Clone(m)
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
	if !slices.Contains(allowed, host) {
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
		"codec":           h.o.codec,
		"scenarios":       map[string]any{"lockdown": h.o.lockdown, "measure": h.o.measure, "stallTest": h.o.stallTest, "reconnectTest": h.o.reconnectTest},
		"launchAt":        h.launchAt.Format(time.RFC3339Nano),
		"agentHello":      redactHello(h.hello),
		"agentHellos":     len(h.hellos),
		"videoConfig":     h.videoConfig,
		"videoConfigs":    h.videoConfigs,
		"liveChunks":      len(h.chunks),
		"liveKeyframes":   keyframeIndexes(h.chunks),
		"keyframeRequest": h.kfRequestAt,
		"inputAtChunk":    h.inputChunk,
		"recInit":         h.recInit,
		"recInits":        h.recInits,
		"recSegments":     h.segs,
		"recLosses":       h.losses,
		"agentEvents":     h.events,
		"proxy":           h.proxyLog,
		"netns":           h.netns,
		"faults":          h.faults,
		"checks":          h.checks,
	}
	if h.lockdownRun != nil {
		summary["lockdown"] = h.lockdownRun
	}
	if h.measureRes != nil {
		summary["measure"] = h.measureRes
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
	fmt.Printf("%-6s %-62s %s\n", "RESULT", "CHECK", "DETAIL")
	for _, c := range h.checks {
		state := checkState(c.OK, c.Fatal)
		if state == "FAIL" {
			failed++
		}
		fmt.Printf("%-6s %-62s %s\n", state, c.Name, c.Detail)
	}
	fmt.Printf("\n%d checks, %d failed; outputs in %s\n", len(h.checks), failed, h.o.out)
	if failed > 0 || len(h.checks) == 0 {
		return 1
	}
	return 0
}
