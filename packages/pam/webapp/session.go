package webapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
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

const (
	liveWindowFrames  = 60
	liveWindowBytes   = 2 * 1024 * 1024
	keyframeMinPeriod = 2 * time.Second
)

// liveSession is the per-session runtime: both links, the recorder and the end-once latch.
type liveSession struct {
	svc    *Service
	p      SessionParams
	log    zerolog.Logger
	viewer *viewerLink
	agent  *agentLink
	rec    *recorder.Recorder
	input  *inputPath

	endOnce   sync.Once
	endCh     chan struct{}
	endReason string

	winMu       sync.Mutex
	inflight    []inflightFrame
	inflightB   int
	dropping    bool
	lastKeyReq  time.Time
	keyReqDrops int
}

type inflightFrame struct {
	seq  uint32
	size int
}

func (ls *liveSession) end(reason string) {
	ls.endOnce.Do(func() {
		ls.endReason = reason
		close(ls.endCh)
	})
}

func (ls *liveSession) record(t contract.EventType, body any) {
	if _, err := ls.rec.Append(t, body); err != nil && !errors.Is(err, recorder.ErrClosed) {
		ls.log.Error().Err(err).Str("event", t.String()).Msg("Web App recording append failed")
	}
}

// HandleSession runs one Web App session over the viewer tunnel conn until it ends. It is the only recorder of the
// session (CONTRACTS.md 1.5) and destroys the runner on every exit path.
func (s *Service) HandleSession(ctx context.Context, conn net.Conn, p SessionParams) error {
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

	// Viewer HELLO must be the first upstream frame.
	_ = conn.SetReadDeadline(time.Now().Add(s.cfg.HelloTimeout))
	f, err := contract.ReadFrame(conn, contract.MaxUpstreamPayload)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		if errors.Is(err, contract.ErrFrameTooLarge) {
			return fail(contract.ErrCodeFrameTooLarge, err)
		}
		return fmt.Errorf("webapp: read HELLO: %w", err)
	}
	var hello contract.ViewerHello
	if f.Type != contract.FrameHello || json.Unmarshal(f.Payload, &hello) != nil {
		return fail(contract.ErrCodeProtocol, errors.New("webapp: first viewer frame is not a valid HELLO"))
	}

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
		Backend: s.newBackend(p.SessionID, p.Recording.UploadToken),
		Log:     l,
	})
	if err != nil {
		return fail(contract.ErrCodeInternal, err)
	}
	if err := rec.Open(recorder.SessionOpen{
		GatewayID: s.gatewayID(), StartURL: wa.ConnectionDetails.URL, AllowedHosts: allowed,
		Runner: recorder.RunnerInfo{Image: s.cfg.RunnerImage, IP: runner.IP},
	}); err != nil {
		return fail(contract.ErrCodeInternal, err)
	}

	ls := &liveSession{svc: s, p: p, log: l, viewer: vl, rec: rec, endCh: make(chan struct{}), endReason: "error",
		input: newInputPath(defaultDisplay.Width, defaultDisplay.Height)}
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := rec.Close(cctx, ls.endReason); err != nil {
			l.Error().Err(err).Msg("Web App recorder close failed")
		}
		l.Info().Str("reason", ls.endReason).Msg("Web App session ended")
	}()

	unregisterEgress := s.proxy.Register(runnerIP, &egress.Session{SessionID: p.SessionID, AllowedHosts: allowed, Record: ls.record})
	defer unregisterEgress()

	tickDone := make(chan struct{})
	defer close(tickDone)
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if err := rec.Tick(); err != nil {
					l.Error().Err(err).Msg("Web App E chunk seal failed")
				}
			case <-tickDone:
				return
			}
		}
	}()

	// Wait for the runner agent.
	select {
	case ls.agent = <-pending.links:
	case <-time.After(s.cfg.AgentWaitTimeout):
		ls.endReason = "error"
		return fail(contract.ErrCodeRunnerUnavailable, errAgentTimeout)
	case <-ctx.Done():
		ls.endReason = endReasonForCancel(p.ExpiresAt)
		return ctx.Err()
	}
	defer ls.agent.conn.Close()
	l.Info().Str("agentVersion", ls.agent.hello.AgentVersion).Strs("liveCodecs", ls.agent.hello.LiveCodecs).Msg("Web App agent connected")
	if d := ls.agent.hello.Display; d.Width > 0 && d.Height > 0 {
		ls.input.setFramebuffer(d.Width, d.Height)
	}

	candidates := intersect(cfg.liveCodecs, ls.agent.hello.LiveCodecs)
	codec, ok := contract.ChooseLiveCodec(hello, candidates)
	if !ok {
		ls.endReason = "error"
		return fail(contract.ErrCodeNoDecoder, errors.New("webapp: no live codec in common with the viewer"))
	}
	if err := ls.agent.control(contract.AgentControl{Kind: "live_start", Codec: codec, BitrateKbps: 2500}); err != nil {
		ls.endReason = "runner_exit"
		return fail(contract.ErrCodeRunnerUnavailable, err)
	}
	codecString := contract.CodecStringH264Live
	if codec == "vp9" {
		codecString = contract.CodecStringVP9Live
	}
	ls.record(contract.EventLiveCodec, map[string]any{"codec": codec, "codecString": codecString, "encoderMode": "dual", "candidates": candidates})
	l.Info().Str("codec", codec).Msg("Web App live codec chosen")

	inputEnabled := true
	vl.control(contract.ControlDown{
		Kind: contract.ControlSessionReady, SessionID: p.SessionID, ExpiresAt: p.ExpiresAt.UTC().Format(time.RFC3339),
		InputEnabled: &inputEnabled, Policy: &contract.SessionPolicy{Clipboard: cfg.clipboard, Downloads: cfg.downloads, Uploads: cfg.uploads},
	})
	secondsLeft := int(time.Until(p.ExpiresAt).Seconds())
	vl.control(contract.ControlDown{Kind: contract.ControlTimeLeft, SecondsLeft: &secondsLeft, ExpiresAt: p.ExpiresAt.UTC().Format(time.RFC3339)})

	go ls.readViewer(conn)
	go ls.readAgent()

	select {
	case <-ls.endCh:
	case <-ctx.Done():
		ls.end(endReasonForCancel(p.ExpiresAt))
	case <-vl.dead:
		ls.end(viewerGoneReason(p.ExpiresAt))
	}
	reason := ls.endReason
	vl.control(contract.ControlDown{Kind: contract.ControlSessionEnding, Reason: reason})
	_ = ls.agent.control(contract.AgentControl{Kind: "shutdown", Reason: reason})
	return nil
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
	// Viewer reattach within a grace period (CONTRACTS.md 1.11) is not wired yet: the session ends now.
	return "viewer_lost"
}

func (ls *liveSession) readViewer(conn net.Conn) {
	for {
		f, err := contract.ReadFrame(conn, contract.MaxUpstreamPayload)
		if err != nil {
			if errors.Is(err, contract.ErrFrameTooLarge) || errors.Is(err, contract.ErrBadVersion) {
				code := contract.ErrCodeFrameTooLarge
				if errors.Is(err, contract.ErrBadVersion) {
					code = contract.ErrCodeProtocol
				}
				ls.viewer.controlError(code, code, true)
			}
			ls.end(viewerGoneReason(ls.p.ExpiresAt))
			return
		}
		arrival := time.Now()
		if ls.p.OnActivity != nil {
			ls.p.OnActivity()
		}
		if !f.Type.IsUpstream() {
			ls.log.Debug().Uint8("type", uint8(f.Type)).Msg("Web App: dropped a non-upstream frame from the viewer")
			continue
		}
		switch f.Type {
		case contract.FrameInput:
			ls.handleInput(f, arrival)
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
				return
			case "visibility":
				kind := "live_resume"
				if cu.Hidden != nil && *cu.Hidden {
					kind = "live_pause"
				}
				_ = ls.agent.control(contract.AgentControl{Kind: kind})
			}
		case contract.FrameClipboardUp:
			if _, err := ls.rec.AppendAt(contract.EventL3Input, clipboardBlocked(len(f.Payload), f.Seq), arrival); err != nil {
				ls.log.Error().Err(err).Msg("Web App L3 append failed")
			}
		}
	}
}

func (ls *liveSession) handleInput(f *contract.Frame, arrival time.Time) {
	kept, rec, tooMany, err := ls.input.process(f.Payload, f.Seq, arrival)
	if rec != nil {
		if _, aerr := ls.rec.AppendAt(contract.EventL3Input, rec, arrival); aerr != nil && !errors.Is(aerr, recorder.ErrClosed) {
			ls.log.Error().Err(aerr).Msg("Web App L3 append failed")
		}
	}
	if err != nil {
		ls.viewer.controlError(contract.ErrCodeProtocol, "malformed INPUT frame", false)
		if tooMany {
			ls.log.Warn().Msg("Web App: too many malformed input frames, closing the viewer link")
			ls.viewer.kill()
		}
		return
	}
	if len(kept) == 0 {
		return
	}
	if err := ls.agent.sendJSON(contract.FrameInputInject, contract.InputBatch{Events: kept}); err != nil {
		ls.log.Warn().Err(err).Msg("Web App: input injection failed")
	}
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
	_ = ls.agent.control(contract.AgentControl{Kind: "keyframe"})
}

// forwardVideoChunk applies the live window (CONTRACTS.md 1.9): over 60 frames or 2 MiB unacknowledged, drop until the
// next keyframe and ask for one. The recording is never affected.
func (ls *liveSession) forwardVideoChunk(f *contract.Frame) {
	keyframe := f.Flags&contract.FlagKeyframe != 0
	ls.winMu.Lock()
	over := len(ls.inflight) >= liveWindowFrames || ls.inflightB+len(f.Payload) > liveWindowBytes
	if ls.dropping && keyframe && !over {
		ls.dropping = false
	}
	if !ls.dropping && over {
		ls.dropping = true
	}
	dropping := ls.dropping
	ls.winMu.Unlock()
	if dropping {
		ls.requestKeyframe(false)
		return
	}
	seq, ok := ls.viewer.enqueue(f, true)
	if !ok {
		ls.winMu.Lock()
		ls.dropping = true
		ls.winMu.Unlock()
		ls.requestKeyframe(false)
		return
	}
	ls.winMu.Lock()
	ls.inflight = append(ls.inflight, inflightFrame{seq: seq, size: len(f.Payload)})
	ls.inflightB += len(f.Payload)
	ls.winMu.Unlock()
}

func (ls *liveSession) readAgent() {
	for {
		f, err := contract.ReadFrame(ls.agent.conn, contract.MaxAgentPayload)
		if err != nil {
			ls.end("runner_exit")
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
			ls.viewer.enqueue(&contract.Frame{Type: f.Type, Flags: f.Flags, TimestampUs: f.TimestampUs, Payload: f.Payload}, false)
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
			}
		case contract.FrameRecLoss:
			ls.log.Warn().Int("bytes", len(f.Payload)).Msg("Web App recorder reported loss")
		case contract.FrameAgentEvent:
			var ev contract.AgentEvent
			if json.Unmarshal(f.Payload, &ev) == nil {
				ls.log.Debug().Str("kind", ev.Kind).Msg("Web App agent event")
			}
		}
	}
}
