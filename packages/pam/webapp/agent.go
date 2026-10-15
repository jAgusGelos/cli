package webapp

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/webapp/contract"
	"github.com/Infisical/infisical-merge/packages/pam/webapp/recorder"
)

// startLive asks the agent for the live stream and records the codec choice when it changes.
func (ls *liveSession) startLive(codec string) error {
	a := ls.currentAgent()
	if a == nil {
		return errors.New("webapp: no agent link")
	}
	if err := a.control(contract.AgentControl{Kind: agentLiveStart, Codec: codec, BitrateKbps: liveBitrateKbps}); err != nil {
		return err
	}
	ls.mu.Lock()
	changed := ls.codec != codec
	ls.codec = codec
	ls.mu.Unlock()
	if changed {
		codecString := contract.CodecStringH264Live
		if codec == codecVP9 {
			codecString = contract.CodecStringVP9Live
		}
		ls.record(contract.EventLiveCodec, map[string]any{"codec": codec, "codecString": codecString, "encoderMode": encoderModeDual, "candidates": ls.candidates})
		ls.log.Info().Str("codec", codec).Msg("Web App live codec chosen")
	}
	return nil
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

// requestKeyframe asks the live encoder for a keyframe, at most once per keyframeMinPeriod per session.
func (ls *liveSession) requestKeyframe(force bool) {
	ls.winMu.Lock()
	now := time.Now()
	if !force && now.Sub(ls.lastKeyReq) < keyframeMinPeriod {
		ls.winMu.Unlock()
		return
	}
	ls.lastKeyReq = now
	ls.winMu.Unlock()
	ls.agentControl(contract.AgentControl{Kind: agentKeyframe})
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
	ls.record(contract.EventContinuityUnknown, map[string]any{"fromUs": ls.rec.MonoUs(lostAt), "toUs": ls.rec.MonoUs(now), "reason": continuityAgentLost})
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
			ls.end(endRunnerExit)
		}
	})
}

func (ls *liveSession) readAgent(a *agentLink) {
	defer close(a.done)
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
			ls.handleVideoConfig(f)
		case contract.FrameVideoChunk:
			if len(f.Payload) > contract.MaxDownstreamPayload {
				continue
			}
			ls.forwardVideoChunk(downstreamCopy(f))
		case contract.FrameRecInit:
			ls.handleRecInit(f.Payload)
		case contract.FrameRecSegment:
			ls.handleRecSegment(f.Payload)
		case contract.FrameRecLoss:
			ls.handleRecLoss(f.Payload)
		case contract.FrameAgentEvent:
			var ev contract.AgentEvent
			if json.Unmarshal(f.Payload, &ev) == nil {
				ls.log.Debug().Str("kind", ev.Kind).Msg("Web App agent event")
				ls.focus.apply(ev, time.Now())
			}
		}
	}
}

// downstreamCopy is an agent frame as queued for the viewer, which assigns its own seq.
func downstreamCopy(f *contract.Frame) *contract.Frame {
	return &contract.Frame{Type: f.Type, Flags: f.Flags, TimestampUs: f.TimestampUs, Payload: f.Payload}
}

func (ls *liveSession) handleVideoConfig(f *contract.Frame) {
	var vc contract.VideoConfig
	if json.Unmarshal(f.Payload, &vc) == nil {
		ls.input.setFramebuffer(vc.Width, vc.Height)
	}
	ls.mu.Lock()
	ls.videoConfig = f.Payload
	ls.mu.Unlock()
	if vl := ls.currentViewer(); vl != nil {
		vl.enqueue(downstreamCopy(f), false)
	}
}

func (ls *liveSession) handleRecInit(payload []byte) {
	var meta contract.RecInitMeta
	body, err := contract.UnmarshalMetaPrefixed(payload, &meta)
	if err == nil {
		err = ls.rec.RecInit(meta, body)
	}
	if recorderFailed(err) {
		ls.log.Error().Err(err).Msg("Web App REC_INIT rejected")
	}
}

func (ls *liveSession) handleRecSegment(payload []byte) {
	var meta contract.RecSegmentMeta
	body, err := contract.UnmarshalMetaPrefixed(payload, &meta)
	if err == nil {
		err = ls.rec.RecSegment(meta, body)
	}
	if !recorderFailed(err) {
		return
	}
	ls.log.Error().Err(err).Msg("Web App REC_SEGMENT rejected")
	// A segment that does not match its digest is lost evidence: record it as such.
	ls.recordLoss(recorder.LossBody{Stream: contract.SeriesV.Letter(), FromUs: ls.rec.PtsMonoUs(meta.StartPtsUs), ToUs: ls.rec.PtsMonoUs(meta.EndPtsUs), Count: meta.FrameCount, Reason: lossReasonSegmentRejected})
}

func (ls *liveSession) handleRecLoss(payload []byte) {
	var rl contract.RecLoss
	if json.Unmarshal(payload, &rl) != nil {
		return
	}
	ls.log.Warn().Str("reason", rl.Reason).Int("framesLost", rl.FramesLost).Msg("Web App recorder reported loss")
	ls.recordLoss(recorder.LossBody{Stream: contract.SeriesV.Letter(), FromUs: ls.rec.PtsMonoUs(rl.FromPtsUs), ToUs: ls.rec.PtsMonoUs(rl.ToPtsUs), Count: rl.FramesLost, Reason: rl.Reason})
	ls.recordingLoss((rl.ToPtsUs - rl.FromPtsUs) / 1000)
}

func (ls *liveSession) recordLoss(l recorder.LossBody) {
	if err := ls.rec.Loss(l); recorderFailed(err) {
		ls.log.Error().Err(err).Msg("Web App loss record failed")
	}
}

// recorderFailed reports a real recorder error: ErrClosed is expected while the session winds down.
func recorderFailed(err error) bool {
	return err != nil && !errors.Is(err, recorder.ErrClosed)
}
