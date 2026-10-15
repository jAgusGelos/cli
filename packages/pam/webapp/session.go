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
		liveCodecs: []string{codecVP9, codecH264}, onRecorderOverflow: overflowContinueWithLoss,
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
	if _, err := ls.rec.Append(t, body); recorderFailed(err) {
		ls.log.Error().Err(err).Str("event", t.String()).Msg("Web App recording append failed")
	}
}

func (ls *liveSession) recordAt(t contract.EventType, body any, at time.Time) {
	if _, err := ls.rec.AppendAt(t, body, at); recorderFailed(err) {
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
	defer vl.close(viewerFlushWait)
	fail := func(code string, err error) error { return failSession(vl, l, code, err) }

	readyCtx, cancelReady := context.WithTimeout(ctx, s.cfg.HealthTimeout+readyGraceExtra)
	ready := s.Ready(readyCtx)
	cancelReady()
	if !ready {
		return fail(contract.ErrCodeRunnerUnavailable, errors.New("webapp: Web App sessions are disabled (supervisor unavailable)"))
	}
	if err := checkParams(p); err != nil {
		return fail(contract.ErrCodeInternal, err)
	}
	wa := p.Credentials.WebApp
	cfg := resolveSettings(wa.Settings)
	allowed := normalizeHosts(wa.ConnectionDetails.AllowedHosts)

	hello, err := readHello(conn, s.cfg.HelloTimeout)
	if err != nil {
		return fail(frameErrCode(err), err)
	}

	ls := &liveSession{svc: s, p: p, cfg: cfg, log: l, endCh: make(chan struct{}), ready: make(chan struct{}), endReason: endError,
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

	runner, err := s.launchRunner(ctx, p, cfg, allowed, token)
	if err != nil {
		return fail(launchErrCode(err), fmt.Errorf("webapp: launch runner: %w", err))
	}
	l.Info().Str("container", runner.ContainerName).Str("ip", runner.IP).Msg("Web App runner launched")
	defer func() {
		dctx, cancel := context.WithTimeout(context.Background(), destroyTimeout)
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

	rec, err := s.newRecorder(ls)
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
		cctx, cancel := context.WithTimeout(context.Background(), recorderCloseTimeout)
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

	return ls.serve(ctx, vl, hello, pending)
}

// serve waits for the runner agent, starts the live stream and the first viewer link, and returns when the session
// ends.
func (ls *liveSession) serve(ctx context.Context, vl *viewerLink, hello contract.ViewerHello, pending *pendingAgent) error {
	fail := func(code string, err error) error { return failSession(vl, ls.log, code, err) }
	var agent *agentLink
	select {
	case agent = <-pending.links:
	case <-time.After(ls.svc.cfg.AgentWaitTimeout):
		return fail(contract.ErrCodeRunnerUnavailable, errAgentTimeout)
	case <-ctx.Done():
		ls.end(endReasonForCancel(ls.p.ExpiresAt))
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
	ls.log.Info().Str("agentVersion", agent.hello.AgentVersion).Strs("liveCodecs", agent.hello.LiveCodecs).Msg("Web App agent connected")
	if d := agent.hello.Display; d.Width > 0 && d.Height > 0 {
		ls.input.setFramebuffer(d.Width, d.Height)
	}

	ls.candidates = intersect(ls.cfg.liveCodecs, agent.hello.LiveCodecs)
	codec, ok := contract.ChooseLiveCodec(hello, ls.candidates)
	if !ok {
		return fail(contract.ErrCodeNoDecoder, errors.New("webapp: no live codec in common with the viewer"))
	}
	if err := ls.startLive(codec); err != nil {
		ls.end(endRunnerExit)
		return fail(contract.ErrCodeRunnerUnavailable, err)
	}
	go ls.readAgent(agent)
	go ls.watchAgentLinks(pending)

	ls.attachViewer(vl, ls.p.OnActivity, true)
	close(ls.ready)

	select {
	case <-ls.endCh:
	case <-ctx.Done():
		ls.end(endReasonForCancel(ls.p.ExpiresAt))
	}
	reason := ls.reason()
	if v := ls.currentViewer(); v != nil {
		v.control(contract.ControlDown{Kind: contract.ControlSessionEnding, Reason: reason})
		v.close(viewerFlushWait)
	}
	ls.agentControl(contract.AgentControl{Kind: agentShutdown, Reason: reason})
	return nil
}

func failSession(vl *viewerLink, l zerolog.Logger, code string, err error) error {
	vl.fatalError(code)
	l.Error().Err(err).Str("code", code).Msg("Web App session failed")
	return err
}

func checkParams(p SessionParams) error {
	if p.Credentials == nil || p.Credentials.WebApp == nil {
		return errors.New("webapp: credentials carry no webApp object")
	}
	if p.Recording == nil || len(p.Recording.SessionKey) != sessionKeyBytes || p.Recording.UploadToken == "" {
		return errors.New("webapp: recording secrets missing")
	}
	return nil
}

func normalizeHosts(hosts []string) []string {
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, strings.ToLower(strings.TrimSpace(h)))
	}
	return out
}

// frameErrCode maps a frame read error to the CONTROL error code sent to the viewer.
func frameErrCode(err error) string {
	if errors.Is(err, contract.ErrFrameTooLarge) {
		return contract.ErrCodeFrameTooLarge
	}
	return contract.ErrCodeProtocol
}

func launchErrCode(err error) string {
	if supervisor.IsCode(err, supervisor.CodeCapacityExhausted) {
		return contract.ErrCodeCapacity
	}
	return contract.ErrCodeRunnerUnavailable
}

func (s *Service) launchRunner(ctx context.Context, p SessionParams, cfg settings, allowed []string, token string) (*supervisor.LaunchResponse, error) {
	wa := p.Credentials.WebApp
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
	lctx, cancel := context.WithTimeout(ctx, launchTimeout)
	defer cancel()
	return s.sup.Launch(lctx, launch)
}

func (s *Service) newRecorder(ls *liveSession) (*recorder.Recorder, error) {
	p := ls.p
	return recorder.New(recorder.Options{
		SessionID: p.SessionID, ProjectID: p.Recording.ProjectId, SessionKey: p.Recording.SessionKey,
		RecordingKey: s.recKey, ExpiresAt: p.ExpiresAt,
		Backend:         s.newBackend(p.SessionID, p.Recording.UploadToken),
		Log:             ls.log,
		ViewerConnected: func() bool { return ls.currentViewer() != nil },
		OnOverflow:      func() { ls.recordingLoss(0) },
		StatePath:       filepath.Join(s.cfg.StateDir, "webapp-sessions", p.SessionID+".json"),
	})
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
	defer vl.close(viewerFlushWait)
	select {
	case <-ls.ready:
	case <-ls.endCh:
		vl.controlError(contract.ErrCodeInternal, "session ended", true)
		return errors.New("webapp: session ended before the reattach")
	case <-time.After(attachReadyTimeout):
		vl.fatalError(contract.ErrCodeSessionInUse)
		return errors.New("webapp: session not ready for a reattach")
	}
	hello, err := readHello(conn, ls.svc.cfg.HelloTimeout)
	if err != nil {
		vl.fatalError(contract.ErrCodeProtocol)
		return err
	}
	ls.mu.Lock()
	busy := ls.viewer != nil
	ls.mu.Unlock()
	if busy {
		vl.fatalError(contract.ErrCodeSessionInUse)
		return errors.New("webapp: a viewer is already attached")
	}
	codec, ok := contract.ChooseLiveCodec(hello, ls.candidates)
	if !ok {
		vl.fatalError(contract.ErrCodeNoDecoder)
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
			vl.fatalError(contract.ErrCodeRunnerUnavailable)
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
	ls.viewerControl(contract.ControlDown{Kind: contract.ControlRecordingState, State: recordingStateLoss, LostMs: &lostMs})
	if ls.cfg.onRecorderOverflow == overflowTerminate {
		ls.end(endRecordingFailed)
	}
}

// releaseHeld injects a release for every held key and button and records them as synthetic L3 input.
func (ls *liveSession) releaseHeld() {
	rel := ls.input.releases()
	if len(rel) == 0 {
		return
	}
	if a := ls.currentAgent(); a != nil {
		if err := a.sendJSON(contract.FrameInputInject, contract.InputBatch{Events: rel}); err != nil {
			ls.log.Debug().Err(err).Msg("Web App: release injection failed")
		}
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
		return endExpired
	}
	return endAdminTerminated
}

func viewerGoneReason(expiresAt time.Time) string {
	if !time.Now().Before(expiresAt) {
		return endExpired
	}
	return endViewerLost
}

func (ls *liveSession) readViewer(vl *viewerLink) {
	defer vl.kill()
	for {
		f, err := contract.ReadFrame(vl.conn, contract.MaxUpstreamPayload)
		if err != nil {
			if errors.Is(err, contract.ErrFrameTooLarge) || errors.Is(err, contract.ErrBadVersion) {
				vl.fatalError(frameErrCode(err))
				vl.close(viewerErrorFlushWait)
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
			if ls.handleControlUp(f.Payload) {
				// Keep the link open so the owner can send session_ending on it, then close it.
				<-vl.dead
				return
			}
		case contract.FrameClipboardUp:
			ls.recordAt(contract.EventL3Input, clipboardBlocked(len(f.Payload), f.Seq), arrival)
		}
	}
}

// handleControlUp applies one CONTROL_UP and reports whether the viewer ended the session.
func (ls *liveSession) handleControlUp(payload []byte) bool {
	var cu contract.ControlUp
	if json.Unmarshal(payload, &cu) != nil {
		return false
	}
	switch cu.Kind {
	case controlUpEndSession:
		ls.end(endUserEnd)
		return true
	case controlUpVisibility:
		kind := agentLiveResume
		if cu.Hidden != nil && *cu.Hidden {
			kind = agentLivePause
		}
		ls.agentControl(contract.AgentControl{Kind: kind})
	}
	return false
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
			vl.close(viewerErrorFlushWait)
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
