package webapp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/Infisical/infisical-merge/packages/pam/webapp/contract"
	"github.com/Infisical/infisical-merge/packages/pam/webapp/recorder"
	"github.com/Infisical/infisical-merge/packages/pam/webapp/recorder/recordertest"
	"github.com/Infisical/infisical-merge/packages/pam/webapp/supervisor"
	"github.com/go-resty/resty/v2"
	"github.com/stretchr/testify/require"
)

const (
	hProject = "6f1c2d3e-4a5b-4c6d-8e7f-90a1b2c3d4e5"
	hSession = "8a0c6a4e-1f7b-4e0e-9a43-5d2a6f0b9c11"
)

// fakeSupervisor implements CONTRACTS.md section 3 on a unix socket. On launch it starts a fake agent that dials the
// gateway like the real runner agent (section 4).
type fakeSupervisor struct {
	t         *testing.T
	sock      string
	mu        sync.Mutex
	launches  []supervisor.LaunchRequest
	destroyed int
	agent     *fakeAgent
	mode      string // encoder mode the fake agent reports
	token     string // overrides the runner token the agent sends, when set
}

func newFakeSupervisor(t *testing.T) *fakeSupervisor {
	dir, err := os.MkdirTemp("", "iwa-h")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	fs := &fakeSupervisor{t: t, sock: filepath.Join(dir, "s.sock"), mode: "dual"}
	ln, err := net.Listen("unix", fs.sock)
	require.NoError(t, err)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(supervisor.HealthResponse{OK: true, Network: "iwa-runners", HostAddress: "127.0.0.1"})
	})
	mux.HandleFunc("POST /v1/runners", func(w http.ResponseWriter, r *http.Request) {
		var req supervisor.LaunchRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		fs.mu.Lock()
		fs.launches = append(fs.launches, req)
		token := req.RunnerToken
		if fs.token != "" {
			token = fs.token
		}
		fs.agent = startFakeAgent(t, req.GatewayAgentAddr, req.SessionID, token, fs.mode)
		fs.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(supervisor.LaunchResponse{SessionID: req.SessionID, ContainerName: "iwa-runner-8a0c6a4e1f7b", IP: "127.0.0.1", State: "starting"})
	})
	mux.HandleFunc("DELETE /v1/runners/{id}", func(w http.ResponseWriter, r *http.Request) {
		fs.mu.Lock()
		fs.destroyed++
		fs.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"state": "destroyed"})
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln) //nolint:errcheck
	t.Cleanup(func() { srv.Close() })
	return fs
}

type fakeAgent struct {
	mu       sync.Mutex
	conn     net.Conn
	welcome  chan contract.AgentWelcome
	controls chan contract.AgentControl
	injected chan contract.InputBatch
	initBody []byte
	segBody  []byte
}

// startFakeAgent dials the gateway, says AGENT_HELLO and, on live_start, sends REC_INIT, REC_SEGMENT, VIDEO_CONFIG and
// one keyframe (recording first, so the recorder has both V objects before the viewer sees video).
func startFakeAgent(t *testing.T, addr, sessionID, token, mode string) *fakeAgent {
	a := &fakeAgent{
		welcome: make(chan contract.AgentWelcome, 1), controls: make(chan contract.AgentControl, 16),
		injected: make(chan contract.InputBatch, 16),
		initBody: []byte("\x00\x00\x00\x18ftypiso5 fake init moov"), segBody: []byte("\x00\x00\x00\x10moof fake mdat segment"),
	}
	go func() {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Errorf("agent dial: %v", err)
			return
		}
		a.conn = c
		hello := contract.AgentHello{SessionID: sessionID, RunnerToken: token, AgentVersion: "test", LiveCodecs: []string{"h264"}, RecordingCodec: "h264", EncoderMode: mode}
		hello.Display.Width, hello.Display.Height, hello.Display.Framerate = 1280, 720, 30
		b, _ := json.Marshal(hello)
		_ = contract.WriteFrame(c, &contract.Frame{Type: contract.FrameAgentHello, Payload: b})
		var seq uint32 = 100 // deliberately not 0: the gateway must rewrite seq on the viewer link
		send := func(ft contract.FrameType, flags uint16, payload []byte) {
			a.mu.Lock()
			_ = contract.WriteFrame(c, &contract.Frame{Type: ft, Flags: flags, Seq: seq, TimestampUs: 33000, Payload: payload})
			seq++
			a.mu.Unlock()
		}
		for {
			f, err := contract.ReadFrame(c, contract.MaxAgentPayload)
			if err != nil {
				return
			}
			switch f.Type {
			case contract.FrameAgentWelcome:
				var w contract.AgentWelcome
				_ = json.Unmarshal(f.Payload, &w)
				a.welcome <- w
			case contract.FrameAgentControl:
				var ac contract.AgentControl
				_ = json.Unmarshal(f.Payload, &ac)
				a.controls <- ac
				if ac.Kind == "live_start" {
					initP, _ := contract.MarshalMetaPrefixed(contract.RecInitMeta{Codec: contract.CodecStringH264Rec, Mime: `video/mp4; codecs="avc1.64001f"`, Width: 1280, Height: 720, Timescale: 90000, PtsZeroUnixMs: time.Now().UnixMilli()}, a.initBody)
					send(contract.FrameRecInit, 0, initP)
					sum := sha256.Sum256(a.segBody)
					segP, _ := contract.MarshalMetaPrefixed(contract.RecSegmentMeta{SegmentIndex: 1, StartPtsUs: 0, EndPtsUs: 10_000_000, FrameCount: 300, FramesCaptured: 300, SHA256: hex.EncodeToString(sum[:])}, a.segBody)
					send(contract.FrameRecSegment, 0, segP)
					// An upstream-range frame from the agent must never reach the viewer.
					send(contract.FrameInput, 0, []byte(`{"events":[]}`))
					vc, _ := json.Marshal(contract.VideoConfig{Codec: contract.CodecStringH264Live, Format: "annexb", Width: 1280, Height: 720, Framerate: 30, Epoch: 1})
					send(contract.FrameVideoConfig, 0, vc)
					send(contract.FrameVideoChunk, contract.FlagKeyframe, []byte{0, 0, 0, 1, 0x65, 0x88})
				}
				if ac.Kind == "shutdown" {
					c.Close()
					return
				}
			case contract.FrameInputInject:
				var ib contract.InputBatch
				_ = json.Unmarshal(f.Payload, &ib)
				a.injected <- ib
			}
		}
	}()
	return a
}

func (a *fakeAgent) write(ft contract.FrameType, payload []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	_ = contract.WriteFrame(a.conn, &contract.Frame{Type: ft, Payload: payload})
}

// waitControl returns the next AGENT_CONTROL of the given kind.
func (a *fakeAgent) waitControl(t *testing.T, kind string) contract.AgentControl {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case c := <-a.controls:
			if c.Kind == kind {
				return c
			}
		case <-deadline:
			t.Fatalf("no AGENT_CONTROL %s", kind)
		}
	}
}

type harness struct {
	svc     *Service
	sup     *fakeSupervisor
	backend *recordertest.Server
	key     []byte
}

func newHarness(t *testing.T) *harness {
	sup := newFakeSupervisor(t)
	backend := recordertest.NewServer(hProject, "upload-token")
	t.Cleanup(backend.Close)
	svc, err := NewService(Config{
		SupervisorSocket: sup.sock, RunnerImage: "infisical-webapp-runner@sha256:" + hex.EncodeToString(make([]byte, 32)),
		AgentAddr: "127.0.0.1:0", ProxyAddr: "127.0.0.1:0", StateDir: t.TempDir(), GatewayID: "gw-1",
		HealthInterval: 50 * time.Millisecond, HealthTimeout: 2 * time.Second, AgentWaitTimeout: 5 * time.Second, HelloTimeout: 5 * time.Second,
	}, resty.New())
	require.NoError(t, err)
	svc.newBackend = func(sessionID, token string) recorder.Backend {
		return recorder.NewHTTPBackend(backend.URL, sessionID, token, resty.New())
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	svc.Start(ctx)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return &harness{svc: svc, sup: sup, backend: backend, key: key}
}

func (h *harness) params() SessionParams {
	return SessionParams{
		SessionID: hSession, ExpiresAt: time.Now().Add(time.Hour),
		Credentials: &session.PAMCredentials{WebApp: &api.PAMWebAppDetails{
			ConnectionDetails: api.PAMWebAppConnectionDetails{URL: "https://app.corp.internal/", AllowedHosts: []string{"App.Corp.Internal"}, SSLCertificate: "-----BEGIN CERTIFICATE-----\nAPP CA\n-----END CERTIFICATE-----\n"},
			Credentials:       api.PAMWebAppCredentials{AuthMethod: "none"},
		}},
		Recording: &session.PAMRecordingSecrets{SessionKey: h.key, UploadToken: "upload-token", ProjectId: hProject, SessionId: hSession},
	}
}

type viewerSide struct {
	conn   net.Conn
	frames chan *contract.Frame
	seq    uint32
}

func newViewer(conn net.Conn) *viewerSide {
	v := &viewerSide{conn: conn, frames: make(chan *contract.Frame, 64)}
	go func() {
		defer close(v.frames)
		for {
			f, err := contract.ReadFrame(conn, contract.MaxDownstreamPayload)
			if err != nil {
				return
			}
			v.frames <- f
		}
	}()
	return v
}

func (v *viewerSide) send(t *testing.T, ft contract.FrameType, payload []byte) {
	require.NoError(t, contract.WriteFrame(v.conn, &contract.Frame{Type: ft, Seq: v.seq, Payload: payload}))
	v.seq++
}

func (v *viewerSide) next(t *testing.T) *contract.Frame {
	select {
	case f, ok := <-v.frames:
		require.True(t, ok, "viewer link closed")
		return f
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for a viewer frame")
		return nil
	}
}

func (v *viewerSide) nextControl(t *testing.T) contract.ControlDown {
	f := v.next(t)
	require.Equal(t, contract.FrameControl, f.Type)
	var c contract.ControlDown
	require.NoError(t, json.Unmarshal(f.Payload, &c))
	return c
}

func TestVS1Harness(t *testing.T) {
	h := newHarness(t)
	gwSide, viewerConn := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- h.svc.HandleSession(context.Background(), gwSide, h.params()) }()
	v := newViewer(viewerConn)

	v.send(t, contract.FrameHello, []byte(`{"protocol":1,"client":"test","decoders":{"vp9":true,"h264":true},"viewport":{"width":1280,"height":720,"devicePixelRatio":1}}`))

	ready := v.nextControl(t)
	require.Equal(t, contract.ControlSessionReady, ready.Kind)
	require.Equal(t, hSession, ready.SessionID)
	require.True(t, *ready.InputEnabled)
	require.Equal(t, "off", ready.Policy.Clipboard)
	require.Equal(t, contract.ControlTimeLeft, v.nextControl(t).Kind)

	cfgFrame := v.next(t)
	require.Equal(t, contract.FrameVideoConfig, cfgFrame.Type)
	require.Equal(t, uint32(2), cfgFrame.Seq)
	chunk := v.next(t)
	require.Equal(t, contract.FrameVideoChunk, chunk.Type)
	require.Equal(t, uint32(3), chunk.Seq, "gateway owns the viewer-link seq")
	require.NotZero(t, chunk.Flags&contract.FlagKeyframe)
	ack := contract.Ack{AckSeq: chunk.Seq}
	v.send(t, contract.FrameAck, ack.Marshal())

	h.sup.mu.Lock()
	agent := h.sup.agent
	launch := h.sup.launches[0]
	h.sup.mu.Unlock()
	require.Equal(t, []string{"app.corp.internal"}, launch.AllowedHosts)
	require.Contains(t, launch.CaPem, "APP CA")
	require.Equal(t, h.svc.cfg.ProxyAddr, launch.EgressProxyAddr)
	require.True(t, (<-agent.welcome).OK)
	start := <-agent.controls
	require.Equal(t, "live_start", start.Kind)
	require.Equal(t, "h264", start.Codec, "vp9 is not offered by the agent")

	// Input: KeyA passes, Ctrl+N down/up is dropped and recorded, a frame from outside the upstream range is ignored.
	v.send(t, contract.FrameInput, []byte(`{"events":[{"t":"key","action":"down","code":"KeyA","key":"a","mods":0,"ts":1},{"t":"key","action":"down","code":"KeyN","key":"n","mods":2,"ts":2},{"t":"key","action":"up","code":"KeyN","key":"n","ts":3},{"t":"button","action":"down","button":0,"x":10,"y":20,"ts":4}]}`))
	v.send(t, contract.FrameAgentControl, []byte(`{"kind":"shutdown"}`))
	select {
	case inj := <-agent.injected:
		require.Len(t, inj.Events, 2)
		require.Equal(t, "KeyA", inj.Events[0].Code)
		require.Equal(t, "button", inj.Events[1].T)
	case <-time.After(5 * time.Second):
		t.Fatal("no INPUT_INJECT")
	}
	v.send(t, contract.FrameControlUp, []byte(`{"kind":"end_session"}`))
	ending := v.nextControl(t)
	require.Equal(t, contract.ControlSessionEnding, ending.Kind)
	require.Equal(t, "user_end", ending.Reason)

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(30 * time.Second):
		t.Fatal("session did not end")
	}
	h.sup.mu.Lock()
	require.Equal(t, 1, h.sup.destroyed)
	h.sup.mu.Unlock()

	res, err := h.backend.Verify(h.key, hSession, h.svc.RecordingPublicKey())
	require.NoError(t, err)
	require.Len(t, res.VInits, 1)
	require.Equal(t, agent.initBody, res.VInits[0])
	require.Len(t, res.VMedia, 1)
	require.Equal(t, agent.segBody, res.VMedia[0])

	var open map[string]any
	require.NoError(t, json.Unmarshal(res.Events[0].Body, &open))
	require.Equal(t, "web-app", open["resourceType"])
	require.Equal(t, "127.0.0.1", open["runner"].(map[string]any)["ip"])
	require.Len(t, res.ByType(contract.EventLiveCodec), 1)

	l3 := res.ByType(contract.EventL3Input)
	require.Len(t, l3, 1)
	var in l3Input
	require.NoError(t, json.Unmarshal(l3[0].Body, &in))
	require.Len(t, in.Events, 2)
	require.Len(t, in.Dropped, 2)
	require.Equal(t, "Ctrl+N", in.Dropped[0].Rule)
	require.Equal(t, "up", in.Dropped[1].Action)

	last := res.Events[len(res.Events)-1]
	require.Equal(t, contract.EventSessionEnd, last.Type)
	var end map[string]any
	require.NoError(t, json.Unmarshal(last.Body, &end))
	require.Equal(t, "user_end", end["reason"])
	require.Equal(t, float64(last.Seq), end["finalSeq"])
	require.NotEmpty(t, h.backend.Opens)
	require.Equal(t, "end", h.backend.Order[len(h.backend.Order)-1])
}

func TestAgentHelloRefused(t *testing.T) {
	for _, tc := range []struct {
		name, mode, token, want string
	}{
		{"wrong token", "dual", "not-the-token", "unauthorized"},
		{"shared encoder", "shared", "", "encoder_mode_not_allowed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.sup.mode, h.sup.token = tc.mode, tc.token
			h.svc.cfg.AgentWaitTimeout = 500 * time.Millisecond
			gwSide, viewerConn := net.Pipe()
			done := make(chan error, 1)
			go func() { done <- h.svc.HandleSession(context.Background(), gwSide, h.params()) }()
			v := newViewer(viewerConn)
			v.send(t, contract.FrameHello, []byte(`{"protocol":1,"decoders":{"h264":true}}`))
			c := v.nextControl(t)
			require.Equal(t, contract.ControlError, c.Kind)
			require.Equal(t, contract.ErrCodeRunnerUnavailable, c.Code)
			require.Error(t, <-done)
			h.sup.mu.Lock()
			agent := h.sup.agent
			require.Equal(t, 1, h.sup.destroyed, "runner destroyed on failure")
			h.sup.mu.Unlock()
			require.Equal(t, contract.AgentWelcome{OK: false, Error: tc.want}, <-agent.welcome)
		})
	}
}

func TestAgentWrongSourceIPRefused(t *testing.T) {
	h := newHarness(t)
	p, unregister := h.svc.registerPending(hSession, "tok")
	defer unregister()
	p.setIP(netip.MustParseAddr("10.1.2.3"))
	require.True(t, h.svc.Ready(context.Background()))
	agentAddr, _ := h.svc.addrs()
	a := startFakeAgent(t, agentAddr, hSession, "tok", "dual")
	select {
	case w := <-a.welcome:
		require.False(t, w.OK)
		require.Equal(t, "unauthorized", w.Error)
	case <-time.After(5 * time.Second):
		t.Fatal("no AGENT_WELCOME")
	}
}

func TestServiceDisabledWithoutSupervisor(t *testing.T) {
	svc, err := NewService(Config{
		SupervisorSocket: filepath.Join(t.TempDir(), "absent.sock"), AgentAddr: "127.0.0.1:0", ProxyAddr: "127.0.0.1:0",
		StateDir: t.TempDir(), HealthInterval: 20 * time.Millisecond, HealthTimeout: 100 * time.Millisecond,
	}, resty.New())
	require.NoError(t, err)
	svc.Start(context.Background())
	require.False(t, svc.Ready(context.Background()))
	require.Nil(t, svc.agentLn, "listeners never bind before supervisor health is ok")

	gwSide, viewerConn := net.Pipe()
	v := newViewer(viewerConn)
	go func() { _ = svc.HandleSession(context.Background(), gwSide, SessionParams{SessionID: hSession}) }()
	c := v.nextControl(t)
	require.Equal(t, contract.ErrCodeRunnerUnavailable, c.Code)
	require.True(t, *c.Fatal)
}

const helloJSON = `{"protocol":1,"client":"test","decoders":{"vp9":false,"h264":true}}`

// startSession runs a session to session_ready and the first keyframe; it returns the viewer and the done channel.
func startSession(t *testing.T, h *harness, p SessionParams) (*viewerSide, *fakeAgent, chan error) {
	t.Helper()
	gwSide, viewerConn := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- h.svc.HandleSession(context.Background(), gwSide, p) }()
	v := newViewer(viewerConn)
	v.send(t, contract.FrameHello, []byte(helloJSON))
	require.Equal(t, contract.ControlSessionReady, v.nextControl(t).Kind)
	require.Equal(t, contract.ControlTimeLeft, v.nextControl(t).Kind)
	require.Equal(t, contract.FrameVideoConfig, v.next(t).Type)
	require.Equal(t, contract.FrameVideoChunk, v.next(t).Type)
	h.sup.mu.Lock()
	a := h.sup.agent
	h.sup.mu.Unlock()
	a.waitControl(t, "live_start")
	return v, a, done
}

func (v *viewerSide) endSession(t *testing.T, done chan error) {
	t.Helper()
	v.send(t, contract.FrameControlUp, []byte(`{"kind":"end_session"}`))
	for {
		f := v.next(t)
		if f.Type != contract.FrameControl {
			continue
		}
		var c contract.ControlDown
		require.NoError(t, json.Unmarshal(f.Payload, &c))
		if c.Kind == contract.ControlSessionEnding {
			require.Equal(t, "user_end", c.Reason)
			break
		}
	}
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(30 * time.Second):
		t.Fatal("session did not end")
	}
}

func l3Bodies(t *testing.T, res *recordertest.Result) []l3Input {
	var out []l3Input
	for _, e := range res.ByType(contract.EventL3Input) {
		var in l3Input
		require.NoError(t, json.Unmarshal(e.Body, &in))
		out = append(out, in)
	}
	return out
}

// Viewer reattach within the grace period keeps the session: same runner, fresh session_ready, cached VIDEO_CONFIG,
// a forced keyframe, held keys released (synthetic), and a second concurrent viewer is refused with session_in_use.
func TestViewerReattach(t *testing.T) {
	h := newHarness(t)
	v1, agent, done := startSession(t, h, h.params())
	v1.send(t, contract.FrameInput, []byte(`{"events":[{"t":"key","action":"down","code":"ShiftLeft","key":"Shift","mods":1}]}`))
	select {
	case <-agent.injected:
	case <-time.After(5 * time.Second):
		t.Fatal("no INPUT_INJECT")
	}
	v1.conn.Close()
	select {
	case rel := <-agent.injected:
		require.Equal(t, []contract.InputEvent{{T: "key", Action: "up", Code: "ShiftLeft", Key: "Shift"}}, rel.Events)
	case <-time.After(5 * time.Second):
		t.Fatal("no synthetic release on viewer disconnect")
	}

	gw2, c2 := net.Pipe()
	attachDone := make(chan error, 1)
	go func() { attachDone <- h.svc.HandleSession(context.Background(), gw2, h.params()) }()
	v2 := newViewer(c2)
	v2.send(t, contract.FrameHello, []byte(helloJSON))
	ready := v2.nextControl(t)
	require.Equal(t, contract.ControlSessionReady, ready.Kind)
	require.Equal(t, contract.ControlTimeLeft, v2.nextControl(t).Kind)
	cfg := v2.next(t)
	require.Equal(t, contract.FrameVideoConfig, cfg.Type)
	require.Equal(t, uint32(2), cfg.Seq, "seq restarts at 0 on the new viewer link")
	agent.waitControl(t, "keyframe")

	gw3, c3 := net.Pipe()
	go func() { _ = h.svc.HandleSession(context.Background(), gw3, h.params()) }()
	v3 := newViewer(c3)
	v3.send(t, contract.FrameHello, []byte(helloJSON))
	busy := v3.nextControl(t)
	require.Equal(t, contract.ErrCodeSessionInUse, busy.Code)
	require.True(t, *busy.Fatal)

	v2.endSession(t, done)
	require.NoError(t, <-attachDone)
	h.sup.mu.Lock()
	require.Len(t, h.sup.launches, 1, "one runner for the whole session")
	require.Equal(t, 1, h.sup.destroyed)
	h.sup.mu.Unlock()
	res, err := h.backend.Verify(h.key, hSession, h.svc.RecordingPublicKey())
	require.NoError(t, err)
	var synthetic bool
	for _, in := range l3Bodies(t, res) {
		for _, ev := range in.Events {
			synthetic = synthetic || (ev.Synthetic && ev.Code == "ShiftLeft" && ev.Action == "up")
		}
	}
	require.True(t, synthetic, "synthetic release recorded in L3")
}

func TestViewerLostAfterGrace(t *testing.T) {
	viewerGrace = 200 * time.Millisecond
	defer func() { viewerGrace = 60 * time.Second }()
	h := newHarness(t)
	v, _, done := startSession(t, h, h.params())
	v.conn.Close()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("session did not end after the grace period")
	}
	res, err := h.backend.Verify(h.key, hSession, h.svc.RecordingPublicKey())
	require.NoError(t, err)
	var end map[string]any
	require.NoError(t, json.Unmarshal(res.Events[len(res.Events)-1].Body, &end))
	require.Equal(t, "viewer_lost", end["reason"])
}

// A runner agent reconnecting with the same token replaces the link; the gap is recorded as continuity_unknown.
func TestAgentReconnect(t *testing.T) {
	h := newHarness(t)
	v, agent, done := startSession(t, h, h.params())
	h.sup.mu.Lock()
	token := h.sup.launches[0].RunnerToken
	h.sup.mu.Unlock()
	agent.conn.Close()
	agentAddr, _ := h.svc.addrs()
	a2 := startFakeAgent(t, agentAddr, hSession, token, "dual")
	require.True(t, (<-a2.welcome).OK)
	a2.waitControl(t, "live_start")
	// The new link streams again: the viewer gets its VIDEO_CONFIG and keyframe.
	for {
		if f := v.next(t); f.Type == contract.FrameVideoChunk {
			break
		}
	}
	v.endSession(t, done)
	res, err := h.backend.Verify(h.key, hSession, h.svc.RecordingPublicKey())
	require.NoError(t, err)
	cu := res.ByType(contract.EventContinuityUnknown)
	require.Len(t, cu, 1)
	var body map[string]any
	require.NoError(t, json.Unmarshal(cu[0].Body, &body))
	require.Equal(t, "agent_disconnected", body["reason"])
	require.Len(t, res.VInits, 2, "the restarted encoder sends a new init")
}

// REC_LOSS becomes a signed loss event and CONTROL recording_state; with onRecorderOverflow=terminate the session ends
// with recording_failed.
func TestRecLossTerminatePolicy(t *testing.T) {
	h := newHarness(t)
	p := h.params()
	p.Credentials.WebApp.Settings = &api.PAMWebAppSettings{OnRecorderOverflow: "terminate"}
	v, agent, done := startSession(t, h, p)
	agent.write(contract.FrameRecLoss, []byte(`{"fromPtsUs":1000000,"toPtsUs":3000000,"framesLost":60,"reason":"encoder_overflow"}`))
	var sawState, sawEnding bool
	for !sawEnding {
		f := v.next(t)
		if f.Type != contract.FrameControl {
			continue
		}
		var c contract.ControlDown
		require.NoError(t, json.Unmarshal(f.Payload, &c))
		switch c.Kind {
		case contract.ControlRecordingState:
			sawState = true
			require.Equal(t, "loss", c.State)
			require.Equal(t, int64(2000), *c.LostMs)
		case contract.ControlSessionEnding:
			sawEnding = true
			require.Equal(t, "recording_failed", c.Reason)
		}
	}
	require.True(t, sawState)
	require.NoError(t, <-done)
	res, err := h.backend.Verify(h.key, hSession, h.svc.RecordingPublicKey())
	require.NoError(t, err)
	losses := res.ByType(contract.EventLoss)
	require.Len(t, losses, 1)
	var l recorder.LossBody
	require.NoError(t, json.Unmarshal(losses[0].Body, &l))
	require.Equal(t, recorder.LossBody{Stream: "V", FromUs: l.FromUs, ToUs: l.FromUs + 2_000_000, Count: 60, Reason: "encoder_overflow"}, l)
	var end map[string]any
	require.NoError(t, json.Unmarshal(res.Events[len(res.Events)-1].Body, &end))
	require.Equal(t, "recording_failed", end["reason"])
}

// Over the live window the gateway drops to the next keyframe, asks for one and reports viewer_degraded; the
// recording is unaffected.
func TestLiveWindowDegraded(t *testing.T) {
	liveWindowFrames = 3
	defer func() { liveWindowFrames = 60 }()
	h := newHarness(t)
	v, agent, done := startSession(t, h, h.params())
	for i := 0; i < 6; i++ { // no ACKs: the window fills after 3 frames (1 already in flight)
		agent.write(contract.FrameVideoChunk, []byte{0, 0, 0, 1, 0x41})
	}
	var degraded bool
	for !degraded {
		f := v.next(t)
		if f.Type == contract.FrameControl {
			var c contract.ControlDown
			require.NoError(t, json.Unmarshal(f.Payload, &c))
			degraded = c.Kind == contract.ControlViewerDegraded && *c.Active
		}
	}
	agent.waitControl(t, "keyframe")
	v.endSession(t, done)
	res, err := h.backend.Verify(h.key, hSession, h.svc.RecordingPublicKey())
	require.NoError(t, err)
	require.Len(t, res.ByType(contract.EventViewerDegraded), 1)
	require.Len(t, res.VMedia, 1)
}
