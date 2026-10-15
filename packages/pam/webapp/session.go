package webapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/Infisical/infisical-merge/packages/pam/webapp/contract"
	"github.com/Infisical/infisical-merge/packages/pam/webapp/egress"
	"github.com/Infisical/infisical-merge/packages/pam/webapp/recorder"
	"github.com/Infisical/infisical-merge/packages/pam/webapp/supervisor"
	"github.com/rs/zerolog"
)

// SessionParams is what the PAM proxy hands to a Web App session.
type SessionParams struct {
	SessionID   string
	ExpiresAt   time.Time
	Credentials *session.PAMCredentials
	Recording   *session.PAMRecordingSecrets
	OnActivity  func()
}

// settings are the template webApp values in force, with the CONTRACTS.md 8.3 defaults.
type settings struct {
	liveCodecs         []string
	onRecorderOverflow string
	clipboard          string
	downloads          string
	uploads            string
	idleTimeoutMinutes int
	bodyCapBytes       int
}

func resolveSettings(in *api.PAMWebAppSettings) settings {
	s := settings{
		liveCodecs: []string{"vp9", "h264"}, onRecorderOverflow: "continue_with_loss",
		clipboard: "off", downloads: "quarantine", uploads: "block", idleTimeoutMinutes: 15, bodyCapBytes: 65536,
	}
	if in == nil {
		return s
	}
	if len(in.LiveCodecs) > 0 {
		s.liveCodecs = in.LiveCodecs
	}
	if in.OnRecorderOverflow != "" {
		s.onRecorderOverflow = in.OnRecorderOverflow
	}
	if in.Clipboard != "" {
		s.clipboard = in.Clipboard
	}
	if in.Downloads != "" {
		s.downloads = in.Downloads
	}
	if in.Uploads != "" {
		s.uploads = in.Uploads
	}
	if in.IdleTimeoutMinutes != nil {
		s.idleTimeoutMinutes = *in.IdleTimeoutMinutes
	}
	if in.BodyCapBytes != nil {
		s.bodyCapBytes = *in.BodyCapBytes
	}
	return s
}

func intersect(a, b []string) []string {
	var out []string
	for _, x := range a {
		for _, y := range b {
			if x == y {
				out = append(out, x)
				break
			}
		}
	}
	return out
}

// Display and runner defaults handed to the supervisor (CONTRACTS.md 3.1).
var (
	defaultDisplay   = supervisor.Display{Width: 1280, Height: 720, Framerate: 30}
	defaultRecording = supervisor.Recording{SegmentSeconds: 10, BitrateKbps: 1500, CRF: 26}
	defaultResources = supervisor.Resources{CPUs: 1.5, MemoryMb: 1536, PidsLimit: 512}
)

// Timing rules (CONTRACTS.md 1.9, 1.11, 4.1); variables so tests can shorten them.
var (
	liveWindowFrames      = 60
	liveWindowBytes       = 2 * 1024 * 1024
	keyframeMinPeriod     = 2 * time.Second
	degradedClearAfter    = 5 * time.Second
	viewerGrace           = 60 * time.Second
	agentReconnectGrace   = 15 * time.Second
	attachReadyTimeout    = 90 * time.Second
	timeLeftPeriod        = 60 * time.Second
	timeLeftFinalPeriod   = 10 * time.Second
	timeLeftFinalInterval = time.Minute
)

// liveSession is the per-session runtime: the current viewer and agent links, the recorder and the end-once latch.
type liveSession struct {
	svc   *Service
	p     SessionParams
	cfg   settings
	log   zerolog.Logger
	rec   *recorder.Recorder
	input *inputPath

	ready   chan struct{} // closed once the session is ready for a viewer
	endOnce sync.Once
	endCh   chan struct{}

	mu             sync.Mutex
	endReason      string
	viewer         *viewerLink
	viewerActivity func()
	graceTimer     *time.Timer
	agent          *agentLink
	agentLostAt    time.Time
	codec          string
	candidates     []string
	videoConfig    []byte

	winMu         sync.Mutex
	inflight      []inflightFrame
	inflightB     int
	dropping      bool
	lastKeyReq    time.Time
	keyReqDrops   int
	degraded      bool
	droppedFrames int
	lastDrop      time.Time
}

type inflightFrame struct {
	seq  uint32
	size int
}

func (ls *liveSession) end(reason string) {
	ls.endOnce.Do(func() {
		ls.mu.Lock()
		ls.endReason = reason
		ls.mu.Unlock()
		close(ls.endCh)
	})
}

func (ls *liveSession) reason() string {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return ls.endReason
}

func (ls *liveSession) currentViewer() *viewerLink {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return ls.viewer
}

func (ls *liveSession) currentAgent() *agentLink {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return ls.agent
}

func (ls *liveSession) agentControl(c contract.AgentControl) {
	if a := ls.currentAgent(); a != nil {
		if err := a.control(c); err != nil {
			ls.log.Debug().Err(err).Str("kind", c.Kind).Msg("Web App: agent control write failed")
		}
	}
}

func (ls *liveSession) viewerControl(c contract.ControlDown) {
	if v := ls.currentViewer(); v != nil {
		v.control(c)
	}
}

func (ls *liveSession) touch() {
	if ls.p.OnActivity != nil {
		ls.p.OnActivity()
	}
	ls.mu.Lock()
	act := ls.viewerActivity
	ls.mu.Unlock()
	if act != nil {
		act()
	}
}

func (ls *liveSession) record(t contract.EventType, body any) {
	if _, err := ls.rec.Append(t, body); err != nil && !errors.Is(err, recorder.ErrClosed) {
		ls.log.Error().Err(err).Str("event", t.String()).Msg("Web App recording append failed")
	}
}

func (ls *liveSession) recordAt(t contract.EventType, body any, at time.Time) {
	if _, err := ls.rec.AppendAt(t, body, at); err != nil && !errors.Is(err, recorder.ErrClosed) {
		ls.log.Error().Err(err).Str("event", t.String()).Msg("Web App recording append failed")
	}
}

// HandleSession runs one Web App session over the viewer tunnel conn. The first connection for a session owns it
// (launch, recording, runner destroy on every exit path) and returns when the session ends; a later connection for
// the same session reattaches as the new viewer link (CONTRACTS.md 1.11) and returns when that link ends.
func (s *Service) HandleSession(ctx context.Context, conn net.Conn, p SessionParams) error {
	s.mu.Lock()
	if existing := s.live[p.SessionID]; existing != nil {
		s.mu.Unlock()
		return existing.attach(ctx, conn, p)
	}
	s.mu.Unlock()

	l := s.log.With().Str("sessionId", p.SessionID).Logger()
	vl := newViewerLink(conn)
	defer vl.close(2 * time.Second)
	fail := func(code string, err error) error {
		vl.controlError(code, code, true)
		l.Error().Err(err).Str("code", code).Msg("Web App session failed")
		return err
	}

	readyCtx, cancelReady := context.WithTimeout(ctx, s.cfg.HealthTimeout+5*time.Second)
	ready := s.Ready(readyCtx)
	cancelReady()
	if !ready {
		return fail(contract.ErrCodeRunnerUnavailable, errors.New("webapp: Web App sessions are disabled (supervisor unavailable)"))
	}
	if p.Credentials == nil || p.Credentials.WebApp == nil {
		return fail(contract.ErrCodeInternal, errors.New("webapp: credentials carry no webApp object"))
	}
	if p.Recording == nil || len(p.Recording.SessionKey) != 32 || p.Recording.UploadToken == "" {
		return fail(contract.ErrCodeInternal, errors.New("webapp: recording secrets missing"))
	}
	wa := p.Credentials.WebApp
	cfg := resolveSettings(wa.Settings)
	allowed := make([]string, 0, len(wa.ConnectionDetails.AllowedHosts))
	for _, h := range wa.ConnectionDetails.AllowedHosts {
		allowed = append(allowed, strings.ToLower(strings.TrimSpace(h)))
	}

	hello, err := readHello(conn, s.cfg.HelloTimeout)
	if err != nil {
		if errors.Is(err, contract.ErrFrameTooLarge) {
			return fail(contract.ErrCodeFrameTooLarge, err)
		}
		return fail(contract.ErrCodeProtocol, err)
	}

	ls := &liveSession{svc: s, p: p, cfg: cfg, log: l, endCh: make(chan struct{}), ready: make(chan struct{}), endReason: "error",
		input: newInputPath(defaultDisplay.Width, defaultDisplay.Height)}
	s.mu.Lock()
	if s.live[p.SessionID] != nil {
		s.mu.Unlock()
		return fail(contract.ErrCodeSessionInUse, errors.New("webapp: session already running"))
	}
	s.live[p.SessionID] = ls
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.live[p.SessionID] == ls {
			delete(s.live, p.SessionID)
		}
		s.mu.Unlock()
		ls.end(ls.reason())
	}()

	token, err := supervisor.NewRunnerToken()
	if err != nil {
		return fail(contract.ErrCodeInternal, err)
	}
	pending, unregister := s.registerPending(p.SessionID, token)
	defer func() {
		unregister()
		select {
		case extra := <-pending.links:
			extra.conn.Close()
		default:
		}
	}()

	agentAddr, proxyAddr := s.addrs()
	launch := supervisor.LaunchRequest{
		SessionID: p.SessionID, Image: s.cfg.RunnerImage, RunnerToken: token,
		GatewayAgentAddr: agentAddr, EgressProxyAddr: proxyAddr,
		StartURL: wa.ConnectionDetails.URL, AllowedHosts: allowed,
		// Tunnel-only egress: Chromium sees the app's own certificate, so it trusts the app CA (certificate only).
		CaPem:     wa.ConnectionDetails.SSLCertificate,
		Policy:    supervisor.Policy{Clipboard: cfg.clipboard, Downloads: cfg.downloads, Uploads: cfg.uploads, Kiosk: true},
		Display:   defaultDisplay,
		Recording: defaultRecording,
		Resources: defaultResources,
		Watermark: supervisor.Watermark{Text: fmt.Sprintf("%s %s", shortID(p.SessionID), time.Now().UTC().Format("2006-01-02T15:04Z"))},
	}
	lctx, cancelLaunch := context.WithTimeout(ctx, 90*time.Second)
	runner, err := s.sup.Launch(lctx, launch)
	cancelLaunch()
	if err != nil {
		code := contract.ErrCodeRunnerUnavailable
		if supervisor.IsCode(err, supervisor.CodeCapacityExhausted) {
			code = contract.ErrCodeCapacity
		}
		return fail(code, fmt.Errorf("webapp: launch runner: %w", err))
	}
	l.Info().Str("container", runner.ContainerName).Str("ip", runner.IP).Msg("Web App runner launched")
	defer func() {
		dctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.sup.Destroy(dctx, p.SessionID); err != nil {
			l.Error().Err(err).Msg("Web App runner destroy failed")
		}
	}()
	runnerIP, err := netip.ParseAddr(runner.IP)
	if err != nil {
		return fail(contract.ErrCodeRunnerUnavailable, fmt.Errorf("webapp: supervisor returned a bad runner ip %q", runner.IP))
	}
	pending.setIP(runnerIP)

	rec, err := recorder.New(recorder.Options{
		SessionID: p.SessionID, ProjectID: p.Recording.ProjectId, SessionKey: p.Recording.SessionKey,
		RecordingKey: s.recKey, ExpiresAt: p.ExpiresAt,
		Backend:         s.newBackend(p.SessionID, p.Recording.UploadToken),
		Log:             l,
		ViewerConnected: func() bool { return ls.currentViewer() != nil },
		OnOverflow:      func() { ls.recordingLoss(0) },
		StatePath:       filepath.Join(s.cfg.StateDir, "webapp-sessions", p.SessionID+".json"),
	})
	if err != nil {
		return fail(contract.ErrCodeInternal, err)
	}
	ls.rec = rec
	if err := rec.Open(recorder.SessionOpen{
		GatewayID: s.gatewayID(), AccountID: p.Credentials.AccountId, StartURL: wa.ConnectionDetails.URL, AllowedHosts: allowed,
		Runner: recorder.RunnerInfo{Image: s.cfg.RunnerImage, IP: runner.IP},
	}); err != nil {
		return fail(contract.ErrCodeInternal, err)
	}
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := rec.Close(cctx, ls.reason()); err != nil {
			l.Error().Err(err).Msg("Web App recorder close failed")
		}
		l.Info().Str("reason", ls.reason()).Msg("Web App session ended")
	}()

	unregisterEgress := s.proxy.Register(runnerIP, &egress.Session{SessionID: p.SessionID, AllowedHosts: allowed, Record: ls.record})
	defer unregisterEgress()

	tickDone := make(chan struct{})
	defer close(tickDone)
	go ls.ticker(tickDone)

	// Wait for the runner agent.
	var agent *agentLink
	select {
	case agent = <-pending.links:
	case <-time.After(s.cfg.AgentWaitTimeout):
		return fail(contract.ErrCodeRunnerUnavailable, errAgentTimeout)
	case <-ctx.Done():
		ls.end(endReasonForCancel(p.ExpiresAt))
		return ctx.Err()
	}
	ls.mu.Lock()
	ls.agent = agent
	ls.mu.Unlock()
	defer func() {
		if a := ls.currentAgent(); a != nil {
			a.conn.Close()
		}
	}()
	l.Info().Str("agentVersion", agent.hello.AgentVersion).Strs("liveCodecs", agent.hello.LiveCodecs).Msg("Web App agent connected")
	if d := agent.hello.Display; d.Width > 0 && d.Height > 0 {
		ls.input.setFramebuffer(d.Width, d.Height)
	}

	ls.candidates = intersect(cfg.liveCodecs, agent.hello.LiveCodecs)
	codec, ok := contract.ChooseLiveCodec(hello, ls.candidates)
	if !ok {
		return fail(contract.ErrCodeNoDecoder, errors.New("webapp: no live codec in common with the viewer"))
	}
	if err := ls.startLive(codec); err != nil {
		ls.end("runner_exit")
		return fail(contract.ErrCodeRunnerUnavailable, err)
	}
	go ls.readAgent(agent)
	go ls.watchAgentLinks(pending)

	ls.attachViewer(vl, p.OnActivity, true)
	close(ls.ready)

	select {
	case <-ls.endCh:
	case <-ctx.Done():
		ls.end(endReasonForCancel(p.ExpiresAt))
	}
	reason := ls.reason()
	if v := ls.currentViewer(); v != nil {
		v.control(contract.ControlDown{Kind: contract.ControlSessionEnding, Reason: reason})
		v.close(2 * time.Second)
	}
	ls.agentControl(contract.AgentControl{Kind: "shutdown", Reason: reason})
	return nil
}

func readHello(conn net.Conn, timeout time.Duration) (contract.ViewerHello, error) {
	var hello contract.ViewerHello
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	f, err := contract.ReadFrame(conn, contract.MaxUpstreamPayload)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return hello, fmt.Errorf("webapp: read HELLO: %w", err)
	}
	if f.Type != contract.FrameHello || json.Unmarshal(f.Payload, &hello) != nil {
		return hello, errors.New("webapp: first viewer frame is not a valid HELLO")
	}
	return hello, nil
}

// startLive asks the agent for the live stream and records the codec choice when it changes.
func (ls *liveSession) startLive(codec string) error {
	a := ls.currentAgent()
	if a == nil {
		return errors.New("webapp: no agent link")
	}
	if err := a.control(contract.AgentControl{Kind: "live_start", Codec: codec, BitrateKbps: 2500}); err != nil {
		return err
	}
	ls.mu.Lock()
	changed := ls.codec != codec
	ls.codec = codec
	ls.mu.Unlock()
	if changed {
		codecString := contract.CodecStringH264Live
		if codec == "vp9" {
			codecString = contract.CodecStringVP9Live
		}
		ls.record(contract.EventLiveCodec, map[string]any{"codec": codec, "codecString": codecString, "encoderMode": "dual", "candidates": ls.candidates})
		ls.log.Info().Str("codec", codec).Msg("Web App live codec chosen")
	}
	return nil
}

// attachViewer makes vl the session's viewer link: session_ready and time_left, the last VIDEO_CONFIG, a fresh
// keyframe, and its reader.
func (ls *liveSession) attachViewer(vl *viewerLink, onActivity func(), first bool) {
	ls.mu.Lock()
	ls.viewer = vl
	ls.viewerActivity = nil
	if !first {
		ls.viewerActivity = onActivity
	}
	if ls.graceTimer != nil {
		ls.graceTimer.Stop()
		ls.graceTimer = nil
	}
	cfgPayload := ls.videoConfig
	ls.mu.Unlock()

	ls.winMu.Lock()
	ls.inflight, ls.inflightB = nil, 0
	ls.dropping = !first // a new viewer decoder needs a keyframe first
	ls.winMu.Unlock()

	inputEnabled := true
	vl.control(contract.ControlDown{
		Kind: contract.ControlSessionReady, SessionID: ls.p.SessionID, ExpiresAt: ls.p.ExpiresAt.UTC().Format(time.RFC3339),
		InputEnabled: &inputEnabled, Policy: &contract.SessionPolicy{Clipboard: ls.cfg.clipboard, Downloads: ls.cfg.downloads, Uploads: ls.cfg.uploads},
	})
	ls.sendTimeLeft(vl)
	if !first {
		ls.releaseHeld()
		if cfgPayload != nil {
			vl.enqueue(&contract.Frame{Type: contract.FrameVideoConfig, Payload: cfgPayload}, false)
		}
		ls.requestKeyframe(true)
	}
	go ls.readViewer(vl)
	go func() {
		<-vl.dead
		ls.viewerGone(vl)
	}()
}

func (ls *liveSession) sendTimeLeft(vl *viewerLink) {
	left := int(time.Until(ls.p.ExpiresAt).Seconds())
	if left < 0 {
		left = 0
	}
	vl.control(contract.ControlDown{Kind: contract.ControlTimeLeft, SecondsLeft: &left, ExpiresAt: ls.p.ExpiresAt.UTC().Format(time.RFC3339)})
}

// viewerGone starts the reattach grace period when the current viewer link drops.
func (ls *liveSession) viewerGone(vl *viewerLink) {
	select {
	case <-ls.endCh:
		return // the session is ending: no grace, no releases
	default:
	}
	ls.mu.Lock()
	if ls.viewer != vl {
		ls.mu.Unlock()
		return
	}
	ls.viewer = nil
	ls.viewerActivity = nil
	ls.graceTimer = time.AfterFunc(viewerGrace, func() { ls.end(viewerGoneReason(ls.p.ExpiresAt)) })
	ls.mu.Unlock()
	ls.log.Info().Msg("Web App viewer disconnected, waiting for a reattach")
	ls.releaseHeld()
}

// attach serves a reattaching viewer on a new tunnel connection (CONTRACTS.md 1.11).
func (ls *liveSession) attach(ctx context.Context, conn net.Conn, p SessionParams) error {
	vl := newViewerLink(conn)
	defer vl.close(2 * time.Second)
	select {
	case <-ls.ready:
	case <-ls.endCh:
		vl.controlError(contract.ErrCodeInternal, "session ended", true)
		return errors.New("webapp: session ended before the reattach")
	case <-time.After(attachReadyTimeout):
		vl.controlError(contract.ErrCodeSessionInUse, contract.ErrCodeSessionInUse, true)
		return errors.New("webapp: session not ready for a reattach")
	}
	hello, err := readHello(conn, ls.svc.cfg.HelloTimeout)
	if err != nil {
		vl.controlError(contract.ErrCodeProtocol, contract.ErrCodeProtocol, true)
		return err
	}
	ls.mu.Lock()
	busy := ls.viewer != nil
	ls.mu.Unlock()
	if busy {
		vl.controlError(contract.ErrCodeSessionInUse, contract.ErrCodeSessionInUse, true)
		return errors.New("webapp: a viewer is already attached")
	}
	codec, ok := contract.ChooseLiveCodec(hello, ls.candidates)
	if !ok {
		vl.controlError(contract.ErrCodeNoDecoder, contract.ErrCodeNoDecoder, true)
		return errors.New("webapp: no live codec in common with the reattaching viewer")
	}
	ls.mu.Lock()
	sameCodec := ls.codec == codec
	if !sameCodec {
		ls.videoConfig = nil
	}
	ls.mu.Unlock()
	if !sameCodec {
		if err := ls.startLive(codec); err != nil {
			vl.controlError(contract.ErrCodeRunnerUnavailable, contract.ErrCodeRunnerUnavailable, true)
			return err
		}
	}
	ls.log.Info().Msg("Web App viewer reattached")
	ls.attachViewer(vl, p.OnActivity, false)
	select {
	case <-vl.dead:
	case <-ls.endCh:
		<-vl.dead
	case <-ctx.Done():
	}
	return nil
}

// ticker drives the recorder clock (E seals, heartbeat), time_left and the viewer_degraded clear.
func (ls *liveSession) ticker(done chan struct{}) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	nextTimeLeft := time.Now().Add(timeLeftPeriod)
	for {
		select {
		case <-done:
			return
		case now := <-t.C:
			if err := ls.rec.Tick(); err != nil {
				ls.log.Error().Err(err).Msg("Web App recorder tick failed")
			}
			if !now.Before(nextTimeLeft) {
				if v := ls.currentViewer(); v != nil {
					ls.sendTimeLeft(v)
				}
				period := timeLeftPeriod
				if ls.p.ExpiresAt.Sub(now) <= timeLeftFinalInterval {
					period = timeLeftFinalPeriod
				}
				nextTimeLeft = now.Add(period)
			}
			ls.maybeClearDegraded(now)
		}
	}
}

func (ls *liveSession) maybeClearDegraded(now time.Time) {
	ls.winMu.Lock()
	if !ls.degraded || now.Sub(ls.lastDrop) < degradedClearAfter {
		ls.winMu.Unlock()
		return
	}
	ls.degraded = false
	dropped := ls.droppedFrames
	ls.winMu.Unlock()
	ls.reportDegraded(false, dropped)
}

func (ls *liveSession) reportDegraded(active bool, dropped int) {
	ls.viewerControl(contract.ControlDown{Kind: contract.ControlViewerDegraded, Active: &active, DroppedFrames: &dropped})
	ls.record(contract.EventViewerDegraded, map[string]any{"active": active, "droppedFrames": dropped})
}

// recordingLoss tells the viewer about recorder loss and applies the overflow policy (CONTRACTS.md 4.3).
func (ls *liveSession) recordingLoss(lostMs int64) {
	ls.viewerControl(contract.ControlDown{Kind: contract.ControlRecordingState, State: "loss", LostMs: &lostMs})
	if ls.cfg.onRecorderOverflow == "terminate" {
		ls.end("recording_failed")
	}
}

// releaseHeld injects a release for every held key and button and records them as synthetic L3 input.
func (ls *liveSession) releaseHeld() {
	rel := ls.input.releases()
	if len(rel) == 0 {
		return
	}
	if a := ls.currentAgent(); a != nil {
		_ = a.sendJSON(contract.FrameInputInject, contract.InputBatch{Events: rel})
	}
	ls.record(contract.EventL3Input, &l3Input{Events: toL3(rel, true), Dropped: []droppedEntry{}})
}

func shortID(id string) string {
	if len(id) >= 8 {
		return id[:8]
	}
	return id
}

func endReasonForCancel(expiresAt time.Time) string {
	if !time.Now().Before(expiresAt) {
		return "expired"
	}
	return "admin_terminated"
}

func viewerGoneReason(expiresAt time.Time) string {
	if !time.Now().Before(expiresAt) {
		return "expired"
	}
	return "viewer_lost"
}

func (ls *liveSession) readViewer(vl *viewerLink) {
	defer vl.kill()
	for {
		f, err := contract.ReadFrame(vl.conn, contract.MaxUpstreamPayload)
		if err != nil {
			if errors.Is(err, contract.ErrFrameTooLarge) || errors.Is(err, contract.ErrBadVersion) {
				code := contract.ErrCodeFrameTooLarge
				if errors.Is(err, contract.ErrBadVersion) {
					code = contract.ErrCodeProtocol
				}
				vl.controlError(code, code, true)
				vl.close(time.Second)
			}
			return
		}
		arrival := time.Now()
		ls.touch()
		if !f.Type.IsUpstream() {
			ls.log.Debug().Uint8("type", uint8(f.Type)).Msg("Web App: dropped a non-upstream frame from the viewer")
			continue
		}
		switch f.Type {
		case contract.FrameInput:
			ls.handleInput(vl, f, arrival)
		case contract.FrameAck:
			if ack, err := contract.UnmarshalAck(f.Payload); err == nil {
				ls.ack(ack.AckSeq)
			}
		case contract.FrameKeyframeRequest:
			ls.requestKeyframe(false)
		case contract.FrameControlUp:
			var cu contract.ControlUp
			if json.Unmarshal(f.Payload, &cu) != nil {
				continue
			}
			switch cu.Kind {
			case "end_session":
				ls.end("user_end")
				// Keep the link open so the owner can send session_ending on it, then close it.
				<-vl.dead
				return
			case "visibility":
				kind := "live_resume"
				if cu.Hidden != nil && *cu.Hidden {
					kind = "live_pause"
				}
				ls.agentControl(contract.AgentControl{Kind: kind})
			}
		case contract.FrameClipboardUp:
			ls.recordAt(contract.EventL3Input, clipboardBlocked(len(f.Payload), f.Seq), arrival)
		}
	}
}

func (ls *liveSession) handleInput(vl *viewerLink, f *contract.Frame, arrival time.Time) {
	kept, rec, tooMany, err := ls.input.process(f.Payload, f.Seq, arrival)
	if rec != nil {
		ls.recordAt(contract.EventL3Input, rec, arrival)
	}
	if err != nil {
		vl.controlError(contract.ErrCodeProtocol, "malformed INPUT frame", false)
		if tooMany {
			ls.log.Warn().Msg("Web App: too many malformed input frames, closing the viewer link")
			vl.close(time.Second)
		}
		return
	}
	if len(kept) == 0 {
		return
	}
	a := ls.currentAgent()
	if a == nil {
		return
	}
	if err := a.sendJSON(contract.FrameInputInject, contract.InputBatch{Events: kept}); err != nil {
		ls.log.Warn().Err(err).Msg("Web App: input injection failed")
		return
	}
	ls.input.trackInjected(kept)
}

// ack releases live-window entries up to ackSeq (inclusive, wrap-aware).
func (ls *liveSession) ack(ackSeq uint32) {
	ls.winMu.Lock()
	defer ls.winMu.Unlock()
	i := 0
	for ; i < len(ls.inflight); i++ {
		if int32(ls.inflight[i].seq-ackSeq) > 0 {
			break
		}
		ls.inflightB -= ls.inflight[i].size
	}
	ls.inflight = ls.inflight[i:]
}

// requestKeyframe asks the live encoder for a keyframe, at most once per 2 s per session.
func (ls *liveSession) requestKeyframe(force bool) {
	ls.winMu.Lock()
	now := time.Now()
	if !force && now.Sub(ls.lastKeyReq) < keyframeMinPeriod {
		ls.keyReqDrops++
		ls.winMu.Unlock()
		return
	}
	ls.lastKeyReq = now
	ls.winMu.Unlock()
	ls.agentControl(contract.AgentControl{Kind: "keyframe"})
}

// forwardVideoChunk applies the live window (CONTRACTS.md 1.9): over 60 frames or 2 MiB unacknowledged, drop until the
// next keyframe, ask for one and report viewer_degraded. The recording is never affected.
func (ls *liveSession) forwardVideoChunk(f *contract.Frame) {
	vl := ls.currentViewer()
	if vl == nil {
		return
	}
	keyframe := f.Flags&contract.FlagKeyframe != 0
	ls.winMu.Lock()
	over := len(ls.inflight) >= liveWindowFrames || ls.inflightB+len(f.Payload) > liveWindowBytes
	if ls.dropping && keyframe && !over {
		ls.dropping = false
	}
	congested := over
	if !ls.dropping && over {
		ls.dropping = true
	}
	dropping := ls.dropping
	ls.winMu.Unlock()
	if !dropping {
		if seq, ok := vl.enqueue(f, true); ok {
			ls.winMu.Lock()
			ls.inflight = append(ls.inflight, inflightFrame{seq: seq, size: len(f.Payload)})
			ls.inflightB += len(f.Payload)
			ls.winMu.Unlock()
			return
		}
		congested = true
		ls.winMu.Lock()
		ls.dropping = true
		ls.winMu.Unlock()
	}
	// Drops while waiting for the first keyframe of a new viewer are not degradation.
	ls.winMu.Lock()
	ls.droppedFrames++
	ls.lastDrop = time.Now()
	becameDegraded := congested && !ls.degraded
	if becameDegraded {
		ls.degraded = true
	}
	dropped := ls.droppedFrames
	ls.winMu.Unlock()
	if becameDegraded {
		ls.reportDegraded(true, dropped)
	}
	ls.requestKeyframe(false)
}

// watchAgentLinks replaces the agent link when the runner agent reconnects with the same token (CONTRACTS.md 4.1).
func (ls *liveSession) watchAgentLinks(p *pendingAgent) {
	for {
		select {
		case <-ls.endCh:
			return
		case nl := <-p.links:
			ls.replaceAgent(nl)
		}
	}
}

func (ls *liveSession) replaceAgent(nl *agentLink) {
	now := time.Now()
	ls.mu.Lock()
	old := ls.agent
	lostAt := ls.agentLostAt
	if lostAt.IsZero() {
		lostAt = now
	}
	ls.agent = nl
	ls.agentLostAt = time.Time{}
	codec := ls.codec
	ls.videoConfig = nil
	ls.mu.Unlock()
	if old != nil {
		old.conn.Close()
	}
	ls.log.Warn().Msg("Web App agent reconnected, link replaced")
	ls.record(contract.EventContinuityUnknown, map[string]any{"fromUs": ls.rec.MonoUs(lostAt), "toUs": ls.rec.MonoUs(now), "reason": "agent_disconnected"})
	ls.releaseHeld()
	ls.winMu.Lock()
	ls.dropping = true
	ls.inflight, ls.inflightB = nil, 0
	ls.winMu.Unlock()
	if err := ls.startLive(codec); err != nil {
		ls.log.Warn().Err(err).Msg("Web App: live_start on the new agent link failed")
	}
	go ls.readAgent(nl)
}

// agentGone waits for a reconnect before ending the session with runner_exit.
func (ls *liveSession) agentGone(a *agentLink) {
	ls.mu.Lock()
	if ls.agent != a {
		ls.mu.Unlock()
		return
	}
	ls.agentLostAt = time.Now()
	ls.mu.Unlock()
	time.AfterFunc(agentReconnectGrace, func() {
		if ls.currentAgent() == a {
			ls.end("runner_exit")
		}
	})
}

func (ls *liveSession) readAgent(a *agentLink) {
	for {
		f, err := contract.ReadFrame(a.conn, contract.MaxAgentPayload)
		if err != nil {
			ls.agentGone(a)
			return
		}
		if ls.currentAgent() != a {
			return
		}
		if f.Type.IsUpstream() {
			continue
		}
		switch f.Type {
		case contract.FrameVideoConfig:
			var vc contract.VideoConfig
			if json.Unmarshal(f.Payload, &vc) == nil {
				ls.input.setFramebuffer(vc.Width, vc.Height)
			}
			ls.mu.Lock()
			ls.videoConfig = f.Payload
			ls.mu.Unlock()
			if vl := ls.currentViewer(); vl != nil {
				vl.enqueue(&contract.Frame{Type: f.Type, Flags: f.Flags, TimestampUs: f.TimestampUs, Payload: f.Payload}, false)
			}
		case contract.FrameVideoChunk:
			if len(f.Payload) > contract.MaxDownstreamPayload {
				continue
			}
			ls.forwardVideoChunk(&contract.Frame{Type: f.Type, Flags: f.Flags, TimestampUs: f.TimestampUs, Payload: f.Payload})
		case contract.FrameRecInit:
			var meta contract.RecInitMeta
			body, err := contract.UnmarshalMetaPrefixed(f.Payload, &meta)
			if err == nil {
				err = ls.rec.RecInit(meta, body)
			}
			if err != nil && !errors.Is(err, recorder.ErrClosed) {
				ls.log.Error().Err(err).Msg("Web App REC_INIT rejected")
			}
		case contract.FrameRecSegment:
			var meta contract.RecSegmentMeta
			body, err := contract.UnmarshalMetaPrefixed(f.Payload, &meta)
			if err == nil {
				err = ls.rec.RecSegment(meta, body)
			}
			if err != nil && !errors.Is(err, recorder.ErrClosed) {
				ls.log.Error().Err(err).Msg("Web App REC_SEGMENT rejected")
				// A segment that does not match its digest is lost evidence: record it as such.
				_ = ls.rec.Loss(recorder.LossBody{Stream: "V", FromUs: ls.rec.PtsMonoUs(meta.StartPtsUs), ToUs: ls.rec.PtsMonoUs(meta.EndPtsUs), Count: meta.FrameCount, Reason: "segment_rejected"})
			}
		case contract.FrameRecLoss:
			var rl contract.RecLoss
			if json.Unmarshal(f.Payload, &rl) != nil {
				continue
			}
			ls.log.Warn().Str("reason", rl.Reason).Int("framesLost", rl.FramesLost).Msg("Web App recorder reported loss")
			if err := ls.rec.Loss(recorder.LossBody{Stream: "V", FromUs: ls.rec.PtsMonoUs(rl.FromPtsUs), ToUs: ls.rec.PtsMonoUs(rl.ToPtsUs), Count: rl.FramesLost, Reason: rl.Reason}); err != nil && !errors.Is(err, recorder.ErrClosed) {
				ls.log.Error().Err(err).Msg("Web App loss record failed")
			}
			ls.recordingLoss((rl.ToPtsUs - rl.FromPtsUs) / 1000)
		case contract.FrameAgentEvent:
			var ev contract.AgentEvent
			if json.Unmarshal(f.Payload, &ev) == nil {
				ls.log.Debug().Str("kind", ev.Kind).Msg("Web App agent event")
			}
		}
	}
}
