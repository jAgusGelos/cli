package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/webapp/contract"
)

type authed struct {
	conn  net.Conn
	hello *contract.AgentHello
}

type linkEnd struct {
	gen int
	err error
}

// acceptAgents authenticates every connection on the agent port (source IP, session, constant-time token) and hands
// the authenticated ones to the returned channel. Other connections (the netns probe dials this port too) are read
// for a hello and dropped.
func (h *harness) acceptAgents(ln net.Listener) <-chan authed {
	out := make(chan authed, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go h.authenticate(c, out)
		}
	}()
	return out
}

func (h *harness) authenticate(c net.Conn, out chan<- authed) {
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
	case out <- authed{conn: c, hello: &hello}:
	default:
		h.logger.Printf("agent endpoint: unclaimed authenticated link from %s, closing it", src)
		c.Close()
	}
}

func (h *harness) checkHello(hello *contract.AgentHello, n int) {
	h.mu.Lock()
	if h.hello == nil {
		h.hello = hello
	}
	h.hellos = append(h.hellos, *hello)
	h.mu.Unlock()
	suffix := ""
	if n > 1 {
		suffix = fmt.Sprintf(" (link %d)", n)
	}
	h.add("agent connected and authenticated"+suffix, true, "source %s, token and session match", h.runnerIP)
	h.add("AGENT_HELLO fields"+suffix, slices.Contains(hello.LiveCodecs, h.o.codec) && hello.RecordingCodec == "h264" &&
		hello.EncoderMode == "dual" && hello.ImageDigest == h.imageID,
		"liveCodecs %v (want %s) recordingCodec %s encoderMode %s imageDigest %s display %dx%d@%d",
		hello.LiveCodecs, h.o.codec, hello.RecordingCodec, hello.EncoderMode, hello.ImageDigest,
		hello.Display.Width, hello.Display.Height, hello.Display.Framerate)
}

type agentLink struct {
	conn  net.Conn
	gen   int
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

func (h *harness) attach(a authed, ends chan<- linkEnd) error {
	link := &agentLink{conn: a.conn, start: time.Now()}
	welcome := map[string]any{"ok": true, "recording": map[string]int{"segmentSeconds": segmentSeconds}}
	if err := link.send(contract.FrameAgentWelcome, welcome); err != nil {
		a.conn.Close()
		return err
	}
	h.mu.Lock()
	h.linkGen++
	link.gen = h.linkGen
	h.link = link
	h.mu.Unlock()
	go func() { ends <- linkEnd{gen: link.gen, err: h.readLoop(a.conn, link.gen)} }()
	return nil
}

func (h *harness) send(t contract.FrameType, v any) error {
	h.mu.Lock()
	l := h.link
	h.mu.Unlock()
	if l == nil {
		return errors.New("no agent link")
	}
	return l.send(t, v)
}

func (h *harness) liveStart() error {
	return h.send(contract.FrameAgentControl, contract.AgentControl{Kind: "live_start", Codec: h.o.codec})
}

func (h *harness) sinceStartMs() int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.startClock.IsZero() {
		return 0
	}
	return time.Since(h.startClock).Milliseconds()
}

func (h *harness) drive(first authed, links <-chan authed) {
	w, err := newLiveWriter(h.o.out, h.o.codec)
	if err != nil {
		h.add("create live output", false, "%v", err)
		return
	}
	h.mu.Lock()
	h.live = w
	h.mu.Unlock()
	defer w.Close()

	ends := make(chan linkEnd, 8)
	if err := h.attach(first, ends); err != nil {
		h.add("send AGENT_WELCOME", false, "%v", err)
		return
	}
	defer func() {
		h.mu.Lock()
		l := h.link
		h.mu.Unlock()
		l.conn.Close()
	}()
	if err := h.liveStart(); err != nil {
		h.add("send live_start", false, "%v", err)
		return
	}
	h.mu.Lock()
	h.startClock = time.Now()
	h.mu.Unlock()
	h.logger.Printf("live_start %s sent; collecting for at least %s", h.o.codec, h.o.duration)

	if ended, readErr := h.collect(h.startScenarios(links, ends), ends); ended {
		h.add("agent link stays up for the collection window", false, "link closed early: %v", readErr)
		h.captureRunnerLogs()
		return
	}
	h.netnsCheck()
	h.statusCheck("running")
	h.shutdownAgent(ends)
	h.captureRunnerLogs()
}

func (h *harness) startScenarios(links <-chan authed, ends chan linkEnd) <-chan struct{} {
	var wg sync.WaitGroup
	scenario := func(f func()) {
		wg.Add(1)
		go func() { defer wg.Done(); f() }()
	}
	inputDone := make(chan struct{})
	if h.o.lockdown {
		close(inputDone)
		scenario(h.runLockdown)
	} else {
		scenario(func() {
			defer close(inputDone)
			time.Sleep(inputAt)
			h.waitForStartPage(time.Until(h.startClock.Add(h.o.duration - 3*time.Second)))
			h.injectInput()
		})
	}
	if h.o.measure > 0 {
		scenario(func() { <-inputDone; h.runMeasure() })
	}
	if h.o.stallTest || h.o.reconnectTest {
		scenario(func() { <-inputDone; h.runFaults(links, ends) })
	}
	scenDone := make(chan struct{})
	go func() { wg.Wait(); close(scenDone) }()
	return scenDone
}

func (h *harness) collect(scenDone <-chan struct{}, ends <-chan linkEnd) (ended bool, readErr error) {
	kf := time.After(keyframeAt)
	end := time.After(h.o.duration)
	hardEnd := time.After(h.o.duration + 5*time.Minute)
	endFired, scenFinished := false, false
	for !endFired || !scenFinished {
		select {
		case <-kf:
			h.mu.Lock()
			h.kfRequestAt = len(h.chunks)
			h.mu.Unlock()
			h.logger.Printf("sending AGENT_CONTROL keyframe at chunk %d", h.kfRequestAt)
			_ = h.send(contract.FrameAgentControl, contract.AgentControl{Kind: "keyframe"})
		case <-end:
			endFired = true
		case <-scenDone:
			scenFinished = true
			scenDone = nil
		case <-hardEnd:
			h.add("scenarios finish within duration + 5 min", false, "still running, stopping")
			return false, nil
		case e := <-ends:
			if h.isCurrentLink(e.gen) {
				return true, e.err
			}
		}
	}
	return false, nil
}

func (h *harness) shutdownAgent(ends <-chan linkEnd) {
	h.logger.Printf("sending AGENT_CONTROL shutdown")
	_ = h.send(contract.FrameAgentControl, contract.AgentControl{Kind: "shutdown", Reason: "harness_done"})
	deadline := time.After(shutdownWait)
	for {
		select {
		case e := <-ends:
			if h.isCurrentLink(e.gen) {
				h.add("agent closes the link after shutdown", true, "read loop ended: %v", e.err)
				return
			}
		case <-deadline:
			h.add("agent closes the link after shutdown", false, "still open after %s", shutdownWait)
			return
		}
	}
}

func (h *harness) isCurrentLink(gen int) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.link != nil && h.link.gen == gen
}

func (h *harness) readLoop(conn net.Conn, gen int) error {
	for {
		_ = conn.SetReadDeadline(time.Now().Add(45 * time.Second))
		f, err := contract.ReadFrame(conn, contract.MaxAgentPayload)
		if err != nil {
			return err
		}
		if err := h.handleFrame(f, gen); err != nil {
			return err
		}
	}
}

func (h *harness) handleFrame(f *contract.Frame, gen int) error {
	switch f.Type {
	case contract.FrameVideoConfig:
		h.onVideoConfig(f, gen)
	case contract.FrameVideoChunk:
		return h.onVideoChunk(f)
	case contract.FrameRecInit:
		return h.onRecInit(f, gen)
	case contract.FrameRecSegment:
		return h.onRecSegment(f, gen)
	case contract.FrameRecLoss:
		h.onRecLoss(f, gen)
	case contract.FrameAgentEvent:
		h.onAgentEvent(f, gen)
	default:
		h.logger.Printf("unexpected frame 0x%02x (%d bytes) from agent", f.Type, len(f.Payload))
	}
	return nil
}

func (h *harness) lastEpochLocked() int {
	if n := len(h.videoConfigs); n > 0 {
		return h.videoConfigs[n-1].Epoch
	}
	return 0
}

func (h *harness) onVideoConfig(f *contract.Frame, gen int) {
	var vc contract.VideoConfig
	if err := json.Unmarshal(f.Payload, &vc); err != nil {
		h.logger.Printf("bad VIDEO_CONFIG: %v", err)
		return
	}
	h.mu.Lock()
	if h.videoConfig == nil {
		h.videoConfig = &vc
	}
	h.videoConfigs = append(h.videoConfigs, vc)
	h.live.Configure(vc)
	h.mu.Unlock()
	h.logger.Printf("VIDEO_CONFIG (link %d) %s", gen, f.Payload)
}

func (h *harness) onVideoChunk(f *contract.Frame) error {
	at := h.sinceStartMs()
	h.mu.Lock()
	defer h.mu.Unlock()
	ci := chunkInfo{Index: len(h.chunks), Epoch: h.lastEpochLocked(), Keyframe: f.Flags&contract.FlagKeyframe != 0,
		PtsUs: f.TimestampUs, Bytes: len(f.Payload), ArrivalMs: at}
	if ci.Index == 0 {
		h.firstChunk = append([]byte(nil), f.Payload...)
	}
	h.chunks = append(h.chunks, ci)
	return h.live.WriteChunk(f.Payload)
}

func (h *harness) onRecInit(f *contract.Frame, gen int) error {
	var meta contract.RecInitMeta
	body, err := contract.UnmarshalMetaPrefixed(f.Payload, &meta)
	if err != nil {
		h.logger.Printf("bad REC_INIT: %v", err)
		return nil
	}
	h.mu.Lock()
	h.recInits++
	n := h.recInits
	h.recInit = &meta
	h.mu.Unlock()
	name := "rec-init.mp4"
	if n > 1 {
		name = fmt.Sprintf("rec-init-%d.mp4", n)
	}
	if err := os.WriteFile(filepath.Join(h.o.out, name), body, 0o644); err != nil {
		return err
	}
	h.logger.Printf("REC_INIT (link %d) %d bytes codec %s", gen, len(body), meta.Codec)
	return nil
}

func (h *harness) onRecSegment(f *contract.Frame, gen int) error {
	var meta contract.RecSegmentMeta
	body, err := contract.UnmarshalMetaPrefixed(f.Payload, &meta)
	if err != nil {
		h.logger.Printf("bad REC_SEGMENT: %v", err)
		return nil
	}
	sum := sha256.Sum256(body)
	name := fmt.Sprintf("rec-seg-%04d.mp4", meta.SegmentIndex)
	if gen > 1 {
		name = fmt.Sprintf("rec-seg-%04d-link%d.mp4", meta.SegmentIndex, gen)
	}
	if err := os.WriteFile(filepath.Join(h.o.out, name), body, 0o644); err != nil {
		return err
	}
	si := segInfo{Meta: meta, File: name, ShaOK: hex.EncodeToString(sum[:]) == meta.SHA256, Bytes: len(body),
		Link: gen, Received: time.Now()}
	h.mu.Lock()
	h.segs = append(h.segs, si)
	h.mu.Unlock()
	h.logger.Printf("REC_SEGMENT %d (link %d): %d bytes, frames %d, pts %d..%d, sha256 ok %v", meta.SegmentIndex,
		gen, len(body), meta.FrameCount, meta.StartPtsUs, meta.EndPtsUs, si.ShaOK)
	return nil
}

func (h *harness) onRecLoss(f *contract.Frame, gen int) {
	var loss contract.RecLoss
	_ = json.Unmarshal(f.Payload, &loss)
	h.mu.Lock()
	h.losses = append(h.losses, loss)
	h.mu.Unlock()
	h.logger.Printf("REC_LOSS (link %d) %s", gen, f.Payload)
}

func (h *harness) onAgentEvent(f *contract.Frame, gen int) {
	at := h.sinceStartMs()
	h.mu.Lock()
	h.events = append(h.events, agentEvent{AtMs: at, Payload: append(json.RawMessage(nil), f.Payload...)})
	h.mu.Unlock()
	h.logger.Printf("AGENT_EVENT (link %d) %s", gen, f.Payload)
}
