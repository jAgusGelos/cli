package supervisor

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testImageID  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	testImageRef = "infisical-webapp-runner@" + testImageID
)

// fakeDocker simulates just enough of the docker CLI for the supervisor: containers by name and label, the runner
// network, one local image and the netns helper output.
type fakeDocker struct {
	mu         sync.Mutex
	calls      [][]string
	envs       map[string][]string // container name -> env passed to the client
	containers map[string]string   // name -> session label
	ips        map[string]string   // pause name -> ip
	network    bool
	rules      string
	failOn     string        // fail the first call whose argv contains this container name
	holdOn     string        // block the run of this container name until the caller's context ends
	held       chan struct{} // closed when the held run starts waiting
}

func newFakeDocker() *fakeDocker {
	return &fakeDocker{
		envs: map[string][]string{}, containers: map[string]string{}, ips: map[string]string{},
		rules: "-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT DROP\n" +
			"-A OUTPUT -d 127.0.0.1/32 -o lo -j ACCEPT\n" +
			"-A OUTPUT -d 172.28.0.1/32 -p tcp -m tcp --dport 7701 -j ACCEPT\n" +
			"-A OUTPUT -d 172.28.0.1/32 -p tcp -m tcp --dport 3128 -j ACCEPT\n",
	}
}

func (f *fakeDocker) Run(ctx context.Context, args ...string) (string, error) {
	return f.RunEnv(ctx, nil, args...)
}

func argAfter(args []string, flag string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag {
			return args[i+1]
		}
	}
	return ""
}

func (f *fakeDocker) RunEnv(ctx context.Context, env []string, args ...string) (string, error) {
	if f.holdOn != "" && len(args) > 0 && args[0] == "run" && argAfter(args, "--name") == f.holdOn {
		close(f.held)
		<-ctx.Done()
		return "", &dockerError{args: args, msg: "killed", err: ctx.Err()}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, append([]string(nil), args...))
	fail := func(msg string) error { return &dockerError{args: args, msg: msg, err: errors.New("exit status 1")} }
	if f.failOn != "" {
		for _, a := range args {
			if a == f.failOn {
				f.failOn = ""
				return "", fail("boom")
			}
		}
	}
	switch {
	case args[0] == "network" && args[1] == "inspect":
		if !f.network {
			return "", fail("network not found")
		}
		if strings.Contains(args[3], "Containers") {
			var b strings.Builder
			for _, ip := range f.ips {
				b.WriteString(ip + "/24\n")
			}
			return b.String(), nil
		}
		return "true 172.28.0.0/24 iwa-runners0\n", nil
	case args[0] == "network" && args[1] == "create":
		f.network = true
		return "netid\n", nil
	case args[0] == "image" && args[1] == "inspect":
		ref := args[len(args)-1]
		if ref == testImageRef || ref == testImageID {
			return testImageID + "\n", nil
		}
		return "", fail("No such image: " + ref)
	case args[0] == "ps":
		filter := argAfter(args, "--filter")
		var b strings.Builder
		for name, sess := range f.containers {
			if filter == "label="+SessionLabel || filter == "label="+SessionLabel+"="+sess {
				if args[1] == "-aq" {
					b.WriteString(name + "\n")
				} else {
					b.WriteString(name + "\t" + sess + "\n")
				}
			}
		}
		return b.String(), nil
	case args[0] == "run":
		name := argAfter(args, "--name")
		if _, ok := f.containers[name]; ok {
			return "", fail("Conflict. The container name is already in use")
		}
		if args[1] == "--rm" {
			return f.rules, nil
		}
		f.containers[name] = strings.TrimPrefix(argAfter(args, "--label"), SessionLabel+"=")
		if ip := argAfter(args, "--ip"); ip != "" {
			f.ips[name] = ip
		}
		f.envs[name] = env
		return "cid\n", nil
	case args[0] == "rm":
		for _, name := range args[2:] {
			if _, ok := f.containers[name]; !ok {
				return "", fail("Error response from daemon: No such container: " + name)
			}
			delete(f.containers, name)
			delete(f.ips, name)
		}
		return "", nil
	case args[0] == "container" && args[1] == "inspect":
		name := args[len(args)-1]
		sess, ok := f.containers[name]
		if !ok {
			return "", fail("Error: No such container: " + name)
		}
		if strings.HasPrefix(name, "iwa-netns-") {
			return f.ips[name] + "\n", nil
		}
		return sess + "|running|2026-10-15T17:00:00Z|0|false\n", nil
	}
	return "", fail("unexpected docker call " + strings.Join(args, " "))
}

func (f *fakeDocker) runCall(name string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c[0] == "run" && argAfter(c, "--name") == name {
			return c
		}
	}
	return nil
}

func (f *fakeDocker) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.containers)
}

func testCAPem(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

var caPemOnce struct {
	sync.Once
	pem string
}

func validRequest(t *testing.T, sessionID string) map[string]any {
	caPemOnce.Do(func() { caPemOnce.pem = testCAPem(t) })
	return map[string]any{
		"sessionId":        sessionID,
		"image":            testImageRef,
		"runnerToken":      base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)),
		"gatewayAgentAddr": "172.28.0.1:7701",
		"egressProxyAddr":  "172.28.0.1:3128",
		"startUrl":         "https://app.corp.internal/",
		"allowedHosts":     []string{"app.corp.internal"},
		"caPem":            caPemOnce.pem,
		"watermark":        map[string]string{"text": "admin@infisical.local 8a0c6a4e"},
	}
}

func sessionN(n int) string { return fmt.Sprintf("8a0c6a4e-1f7b-4e0e-9a43-%012d", n) }

func testServer(t *testing.T, maxRunners int) (*Server, *fakeDocker, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	fd := newFakeDocker()
	s := newServer(Config{
		StateDir: t.TempDir(), Images: []string{testImageRef}, MaxRunners: maxRunners,
		Logger: log.New(&logs, "", 0),
	}, fd)
	return s, fd, &logs
}

func do(t *testing.T, s *Server, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, r)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func errCode(out map[string]any) string {
	e, _ := out["error"].(map[string]any)
	c, _ := e["code"].(string)
	return c
}

func TestLaunchHappyPathAndArgv(t *testing.T) {
	s, fd, logs := testServer(t, 4)
	id := sessionN(1)
	req := validRequest(t, id)
	code, out := do(t, s, "POST", "/v1/runners", req)
	if code != http.StatusCreated {
		t.Fatalf("launch: %d %v", code, out)
	}
	if out["containerName"] != "iwa-runner-8a0c6a4e1f7b" || out["ip"] != "172.28.0.10" || out["state"] != "starting" {
		t.Fatalf("unexpected launch response %v", out)
	}

	runner := fd.runCall("iwa-runner-8a0c6a4e1f7b")
	if runner == nil {
		t.Fatal("runner not started")
	}
	joined := " " + strings.Join(runner, " ") + " "
	for _, want := range []string{
		" --read-only ", " --cap-drop ALL ", " --cap-add SYS_CHROOT ",
		" --security-opt seccomp=" + s.seccompPath() + " ", " --security-opt no-new-privileges ",
		" --network container:iwa-netns-8a0c6a4e1f7b ", " --label " + SessionLabel + "=" + id + " ",
		" --user 1000:1000 ", " --shm-size 1g ", " --pids-limit 512 ", " --memory 1536m ", " --cpus 1.5 ",
		" --tmpfs /tmp:rw,nosuid,nodev,exec,size=512m,uid=1000,gid=1000,mode=0700 ",
		" -e IWA_RUNNER_TOKEN ", " -e IWA_CA_PEM ", " -e IWA_IMAGE_DIGEST ",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("runner argv lacks %q", strings.TrimSpace(want))
		}
	}
	if runner[len(runner)-1] != testImageID {
		t.Errorf("runner must run the image ID, got %q", runner[len(runner)-1])
	}
	for i, a := range runner {
		switch {
		case a == "--privileged", strings.Contains(a, "NET_ADMIN"), strings.Contains(a, "apparmor"),
			strings.Contains(a, "docker.sock"), a == "-v", a == "--volume", strings.HasPrefix(a, "--mount"):
			t.Errorf("runner argv holds forbidden %q", a)
		case a == "-e" && strings.Contains(runner[i+1], "="):
			t.Errorf("runner argv carries an env value: %q", runner[i+1])
		}
	}
	if strings.Count(joined, " --cap-add ") != len(runnerCapAdd) {
		t.Errorf("unexpected --cap-add count in %s", joined)
	}

	pause := fd.runCall("iwa-netns-8a0c6a4e1f7b")
	pj := " " + strings.Join(pause, " ") + " "
	for _, want := range []string{" --network iwa-runners ", " --ip 172.28.0.10 ", " --dns 192.0.2.53 ",
		" --read-only ", " --cap-drop ALL ", " -v " + s.resolvConfPath() + ":/etc/resolv.conf:ro ",
		" --sysctl net.ipv6.conf.all.disable_ipv6=1 "} {
		if !strings.Contains(pj, want) {
			t.Errorf("pause argv lacks %q", strings.TrimSpace(want))
		}
	}
	if strings.Count(pj, " -v ") != 1 || strings.Contains(pj, "--cap-add") {
		t.Errorf("pause argv: %s", pj)
	}

	helper := " " + strings.Join(fd.calls[indexOfRun(fd, "iwa-nethelper-8a0c6a4e1f7b")], " ") + " "
	for _, want := range []string{" --cap-drop ALL --cap-add NET_ADMIN ", " --network container:iwa-netns-8a0c6a4e1f7b ",
		" --entrypoint /opt/iwa/netns-rules.sh ", " 172.28.0.1 7701 3128 "} {
		if !strings.Contains(helper, want) {
			t.Errorf("helper argv lacks %q", strings.TrimSpace(want))
		}
	}

	env := strings.Join(fd.envs["iwa-runner-8a0c6a4e1f7b"], "\n")
	for _, want := range []string{"IWA_SESSION_ID=" + id, "IWA_GATEWAY_AGENT_ADDR=172.28.0.1:7701",
		"IWA_PROXY_ADDR=172.28.0.1:3128", `IWA_ALLOWED_HOSTS=["app.corp.internal"]`, "IWA_DISPLAY=1280x720@30",
		`IWA_RECORDING={"segmentSeconds":10,"bitrateKbps":1500,"crf":26}`, "IWA_IMAGE_DIGEST=" + testImageID,
		"IWA_WATERMARK=admin@infisical.local 8a0c6a4e", "IWA_CA_PEM=-----BEGIN CERTIFICATE-----"} {
		if !strings.Contains(env, want) {
			t.Errorf("runner env lacks %q", want)
		}
	}

	tok := req["runnerToken"].(string)
	if strings.Contains(logs.String(), tok) || strings.Contains(logs.String(), "BEGIN CERTIFICATE") {
		t.Error("logs leak the runner token or the CA PEM")
	}

	code, out = do(t, s, "GET", "/v1/runners/"+id, nil)
	if code != http.StatusOK || out["state"] != "running" || out["ip"] != "172.28.0.10" {
		t.Fatalf("status: %d %v", code, out)
	}
	code, out = do(t, s, "GET", "/v1/health", nil)
	if code != http.StatusOK || out["activeRunners"] != float64(1) || out["hostAddress"] != "172.28.0.1" {
		t.Fatalf("health: %d %v", code, out)
	}
}

func indexOfRun(fd *fakeDocker, name string) int {
	for i, c := range fd.calls {
		if c[0] == "run" && argAfter(c, "--name") == name {
			return i
		}
	}
	return 0
}

func TestImageAllowlist(t *testing.T) {
	s, fd, _ := testServer(t, 4)
	for i, image := range []string{
		"infisical-webapp-runner:dev",
		"infisical-webapp-runner@sha256:2222222222222222222222222222222222222222222222222222222222222222",
		testImageID,
		"other@" + testImageID,
	} {
		req := validRequest(t, sessionN(10+i))
		req["image"] = image
		code, out := do(t, s, "POST", "/v1/runners", req)
		if code != http.StatusForbidden || errCode(out) != "image_not_allowed" {
			t.Errorf("image %q: got %d %v", image, code, out)
		}
	}
	if fd.count() != 0 {
		t.Error("rejected launches created containers")
	}
}

func TestAllowlistedImageMissingLocally(t *testing.T) {
	s, fd, _ := testServer(t, 4)
	missing := "infisical-webapp-runner@sha256:3333333333333333333333333333333333333333333333333333333333333333"
	s.cfg.Images = append(s.cfg.Images, missing)
	req := validRequest(t, sessionN(20))
	req["image"] = missing
	code, out := do(t, s, "POST", "/v1/runners", req)
	if code != http.StatusInternalServerError || errCode(out) != "runtime_error" || fd.count() != 0 {
		t.Fatalf("got %d %v with %d containers", code, out, fd.count())
	}
}

func TestDuplicateSession(t *testing.T) {
	s, _, _ := testServer(t, 4)
	id := sessionN(30)
	if code, out := do(t, s, "POST", "/v1/runners", validRequest(t, id)); code != http.StatusCreated {
		t.Fatalf("first launch: %d %v", code, out)
	}
	code, out := do(t, s, "POST", "/v1/runners", validRequest(t, id))
	if code != http.StatusConflict || errCode(out) != "already_exists" {
		t.Fatalf("second launch: %d %v", code, out)
	}
}

func TestCapacity(t *testing.T) {
	s, _, _ := testServer(t, 5)
	for i := 0; i < 5; i++ {
		// Distinct first 12 hex so container names do not clash.
		id := fmt.Sprintf("%08x-1f7b-4e0e-9a43-5d2a6f0b9c11", 0x10+i)
		if code, out := do(t, s, "POST", "/v1/runners", validRequest(t, id)); code != http.StatusCreated {
			t.Fatalf("launch %d: %d %v", i, code, out)
		}
	}
	code, out := do(t, s, "POST", "/v1/runners", validRequest(t, "000000ff-1f7b-4e0e-9a43-5d2a6f0b9c11"))
	if code != http.StatusTooManyRequests || errCode(out) != "capacity_exhausted" {
		t.Fatalf("sixth launch: %d %v", code, out)
	}
	if code, _ := do(t, s, "DELETE", "/v1/runners/00000010-1f7b-4e0e-9a43-5d2a6f0b9c11", nil); code != http.StatusOK {
		t.Fatalf("destroy: %d", code)
	}
	if code, out := do(t, s, "POST", "/v1/runners", validRequest(t, "000000ff-1f7b-4e0e-9a43-5d2a6f0b9c11")); code != http.StatusCreated {
		t.Fatalf("launch after destroy: %d %v", code, out)
	}
}

func TestDistinctIPs(t *testing.T) {
	s, _, _ := testServer(t, 4)
	_, a := do(t, s, "POST", "/v1/runners", validRequest(t, "00000001-1f7b-4e0e-9a43-5d2a6f0b9c11"))
	_, b := do(t, s, "POST", "/v1/runners", validRequest(t, "00000002-1f7b-4e0e-9a43-5d2a6f0b9c11"))
	if a["ip"] == b["ip"] || a["ip"] == nil {
		t.Fatalf("IPs not distinct: %v %v", a["ip"], b["ip"])
	}
}

func TestBadRequests(t *testing.T) {
	keyPem := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1, 2, 3}}))
	cases := map[string]func(m map[string]any){
		"session not uuid":      func(m map[string]any) { m["sessionId"] = "not-a-uuid" },
		"session uppercase":     func(m map[string]any) { m["sessionId"] = "8A0C6A4E-1F7B-4E0E-9A43-5D2A6F0B9C11" },
		"token padded":          func(m map[string]any) { m["runnerToken"] = "YWJj=" },
		"token short":           func(m map[string]any) { m["runnerToken"] = "YWJj" },
		"token std alphabet":    func(m map[string]any) { m["runnerToken"] = strings.Repeat("a+/b", 11) },
		"agent host":            func(m map[string]any) { m["gatewayAgentAddr"] = "10.0.0.1:7701" },
		"agent port":            func(m map[string]any) { m["gatewayAgentAddr"] = "172.28.0.1:0" },
		"proxy no port":         func(m map[string]any) { m["egressProxyAddr"] = "172.28.0.1" },
		"same ports":            func(m map[string]any) { m["egressProxyAddr"] = "172.28.0.1:7701" },
		"http start url":        func(m map[string]any) { m["startUrl"] = "http://app.corp.internal/" },
		"start url host":        func(m map[string]any) { m["startUrl"] = "https://evil.example/" },
		"start url creds":       func(m map[string]any) { m["startUrl"] = "https://u:p@app.corp.internal/" },
		"start url control":     func(m map[string]any) { m["startUrl"] = "https://app.corp.internal/\n" },
		"no allowed hosts":      func(m map[string]any) { m["allowedHosts"] = []string{} },
		"ip allowed host":       func(m map[string]any) { m["allowedHosts"] = []string{"10.0.0.1"} },
		"wildcard allowed host": func(m map[string]any) { m["allowedHosts"] = []string{"*.corp.internal"} },
		"flag in allowed host":  func(m map[string]any) { m["allowedHosts"] = []string{"--privileged"} },
		"ca missing":            func(m map[string]any) { m["caPem"] = "" },
		"ca private key":        func(m map[string]any) { m["caPem"] = m["caPem"].(string) + keyPem },
		"ca two certs":          func(m map[string]any) { m["caPem"] = m["caPem"].(string) + m["caPem"].(string) },
		"ca junk":               func(m map[string]any) { m["caPem"] = "not pem" },
		"display too big":       func(m map[string]any) { m["display"] = map[string]int{"width": 4096, "height": 720, "framerate": 30} },
		"framerate too high":    func(m map[string]any) { m["display"] = map[string]int{"width": 1280, "height": 720, "framerate": 120} },
		"memory too big": func(m map[string]any) {
			m["resources"] = map[string]any{"cpus": 1.5, "memoryMb": 65536, "pidsLimit": 512}
		},
		"cpus too many": func(m map[string]any) {
			m["resources"] = map[string]any{"cpus": 64, "memoryMb": 1536, "pidsLimit": 512}
		},
		"segment too long": func(m map[string]any) {
			m["recording"] = map[string]int{"segmentSeconds": 600, "bitrateKbps": 1500, "crf": 26}
		},
		"watermark control chars": func(m map[string]any) { m["watermark"] = map[string]string{"text": "a\x1b[2Jb"} },
		"watermark too long":      func(m map[string]any) { m["watermark"] = map[string]string{"text": strings.Repeat("x", 300)} },
		"policy unknown value": func(m map[string]any) {
			m["policy"] = map[string]any{"clipboard": "all", "downloads": "block", "uploads": "block"}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s, fd, _ := testServer(t, 4)
			req := validRequest(t, sessionN(40))
			mutate(req)
			code, out := do(t, s, "POST", "/v1/runners", req)
			if code != http.StatusBadRequest || errCode(out) != "invalid_request" {
				t.Fatalf("got %d %v", code, out)
			}
			if fd.count() != 0 {
				t.Fatal("rejected request created containers")
			}
		})
	}

	s, _, _ := testServer(t, 4)
	for _, body := range []string{"", "{", "[]", `{"sessionId":1}`, `{} {}`} {
		req := httptest.NewRequest("POST", "/v1/runners", strings.NewReader(body))
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %q: got %d", body, rec.Code)
		}
	}
	if code, _ := do(t, s, "DELETE", "/v1/runners/nope", nil); code != http.StatusBadRequest {
		t.Errorf("destroy with bad id: %d", code)
	}
}

func TestDestroyIdempotent(t *testing.T) {
	s, fd, _ := testServer(t, 4)
	id := sessionN(50)
	if code, out := do(t, s, "POST", "/v1/runners", validRequest(t, id)); code != http.StatusCreated {
		t.Fatalf("launch: %d %v", code, out)
	}
	// A stray labeled container (for example a leftover helper under another name) goes with the label sweep.
	fd.containers["stray"] = id
	for i := 0; i < 2; i++ {
		code, out := do(t, s, "DELETE", "/v1/runners/"+id, nil)
		if code != http.StatusOK || out["state"] != "destroyed" {
			t.Fatalf("destroy %d: %d %v", i, code, out)
		}
	}
	if fd.count() != 0 {
		t.Fatalf("leftover containers: %v", fd.containers)
	}
	code, out := do(t, s, "GET", "/v1/runners/"+id, nil)
	if code != http.StatusOK || out["state"] != "destroyed" {
		t.Fatalf("status after destroy: %d %v", code, out)
	}
	if code, _ := do(t, s, "DELETE", "/v1/runners/"+sessionN(51), nil); code != http.StatusOK {
		t.Fatalf("destroy unknown: %d", code)
	}
	if code, _ := do(t, s, "GET", "/v1/runners/"+sessionN(52), nil); code != http.StatusNotFound {
		t.Fatalf("status unknown: %d", code)
	}
}

func TestRollback(t *testing.T) {
	for _, step := range []string{"iwa-runner-8a0c6a4e1f7b", "iwa-nethelper-8a0c6a4e1f7b"} {
		t.Run(step, func(t *testing.T) {
			s, fd, _ := testServer(t, 4)
			fd.failOn = step
			code, out := do(t, s, "POST", "/v1/runners", validRequest(t, sessionN(60)))
			if code != http.StatusInternalServerError || errCode(out) != "runtime_error" {
				t.Fatalf("got %d %v", code, out)
			}
			if fd.count() != 0 {
				t.Fatalf("rollback left %v", fd.containers)
			}
			if len(s.pending) != 0 {
				t.Fatal("reservation not released")
			}
		})
	}
}

func TestDestroyAbortsPendingLaunch(t *testing.T) {
	s, fd, _ := testServer(t, 4)
	id := sessionN(80)
	fd.holdOn = "iwa-runner-" + ShortID(id)
	fd.held = make(chan struct{})
	done := make(chan int, 1)
	go func() {
		code, _ := do(t, s, "POST", "/v1/runners", validRequest(t, id))
		done <- code
	}()
	<-fd.held
	if code, _ := do(t, s, "DELETE", "/v1/runners/"+id, nil); code != http.StatusOK {
		t.Fatalf("destroy: %d", code)
	}
	if code := <-done; code != http.StatusInternalServerError {
		t.Fatalf("aborted launch returned %d", code)
	}
	if fd.count() != 0 {
		t.Fatalf("aborted launch left %v", fd.containers)
	}
	if code, out := do(t, s, "GET", "/v1/runners/"+id, nil); code != http.StatusOK || out["state"] != "destroyed" {
		t.Fatalf("status after abort: %d %v", code, out)
	}
}

func TestRollbackOnWeakRules(t *testing.T) {
	s, fd, _ := testServer(t, 4)
	fd.rules = "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n"
	code, _ := do(t, s, "POST", "/v1/runners", validRequest(t, sessionN(70)))
	if code != http.StatusInternalServerError || fd.count() != 0 {
		t.Fatalf("got %d with %v", code, fd.containers)
	}
}

func TestCheckRules(t *testing.T) {
	ok := "-P OUTPUT DROP\n-A OUTPUT -d 172.28.0.1/32 -p tcp -m tcp --dport 17701 -j ACCEPT\n" +
		"-A OUTPUT -d 172.28.0.1/32 -p tcp -m tcp --dport 13128 -j ACCEPT\n"
	if err := checkRules(ok, 17701, 13128); err != nil {
		t.Fatal(err)
	}
	if err := checkRules(ok, 7701, 13128); err == nil {
		t.Fatal("wrong agent port accepted")
	}
	if err := checkRules(strings.Replace(ok, "-P OUTPUT DROP", "-P OUTPUT ACCEPT", 1), 17701, 13128); err == nil {
		t.Fatal("OUTPUT ACCEPT accepted")
	}
}

func TestParseAllowlist(t *testing.T) {
	got, err := parseAllowlist(" " + testImageRef + " ,")
	if err != nil || len(got) != 1 || got[0] != testImageRef {
		t.Fatalf("got %v %v", got, err)
	}
	for _, bad := range []string{"infisical-webapp-runner:dev", "x@sha256:abc", testImageID} {
		if _, err := parseAllowlist(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestListenSocketPermissions(t *testing.T) {
	dir := t.TempDir() + "/sock"
	ln, err := Listen(dir + "/s.sock")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	// net.UnixListener.Close removes the socket file; recreate a stale one and check Listen replaces it.
	ln, err = Listen(dir + "/s.sock")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	for path, want := range map[string]string{dir: "drwx------", dir + "/s.sock": "Srw-------"} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().String(); got != want {
			t.Errorf("%s mode %s, want %s", path, got, want)
		}
	}
	if _, err := Listen(dir + "/s.sock"); err == nil {
		t.Error("second Listen on a live socket succeeded")
	}
}
