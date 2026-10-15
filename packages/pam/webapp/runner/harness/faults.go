package main

import (
	"os/exec"
	"slices"
	"time"
)

func (h *harness) runFaults(links <-chan authed, ends chan linkEnd) {
	if h.o.stallTest {
		h.stallXvfb()
	}
	if h.o.reconnectTest {
		h.reconnectAgent(links, ends)
	}
}

func (h *harness) setFault(k string, v any) {
	h.mu.Lock()
	h.faults[k] = v
	h.mu.Unlock()
}

// stallXvfb freezes the X server for 2 s so the capture gets no frame for more than 1 s (CONTRACTS 4.3 capture_stall).
func (h *harness) stallXvfb() {
	time.Sleep(time.Second)
	at := h.sinceStartMs()
	out1, err1 := exec.Command("docker", "exec", h.runnerName(), "pkill", "-STOP", "-x", "Xvfb").CombinedOutput()
	time.Sleep(2 * time.Second)
	out2, err2 := exec.Command("docker", "exec", h.runnerName(), "pkill", "-CONT", "-x", "Xvfb").CombinedOutput()
	h.logger.Printf("stall-test: Xvfb stopped at %d ms for 2 s (stop %v %s, cont %v %s)", at, err1, out1, err2, out2)
	h.setFault("stall", map[string]any{"stoppedAtMs": at, "durationMs": 2000, "stopOk": err1 == nil, "contOk": err2 == nil})
	// Let the agent notice the resumed frames and report before the scenario ends.
	time.Sleep(8 * time.Second)
}

func (h *harness) reconnectAgent(links <-chan authed, ends chan linkEnd) {
	time.Sleep(3 * time.Second)
	h.mu.Lock()
	old := h.link
	h.link = nil
	maxBefore := 0
	for _, s := range h.segs {
		maxBefore = max(maxBefore, s.Meta.SegmentIndex)
	}
	epochBefore := h.lastEpochLocked()
	hellosBefore := len(h.hellos)
	h.mu.Unlock()
	closedAt := time.Now()
	old.conn.Close()
	h.logger.Printf("reconnect-test: closed agent link %d (max segment index %d)", old.gen, maxBefore)
	info := map[string]any{"closedAtMs": h.sinceStartMs(), "maxSegmentBefore": maxBefore, "epochBefore": epochBefore}
	select {
	case a := <-links:
		info["redialMs"] = time.Since(closedAt).Milliseconds()
		h.checkHello(a.hello, hellosBefore+1)
		if err := h.attach(a, ends); err != nil {
			info["attachError"] = err.Error()
			break
		}
		if err := h.liveStart(); err != nil {
			info["liveStartError"] = err.Error()
		}
		h.logger.Printf("reconnect-test: link re-established after %d ms, live_start re-sent", info["redialMs"])
	case <-time.After(45 * time.Second):
		info["redialMs"] = -1
		h.logger.Printf("reconnect-test: no re-dial within 45 s")
	}
	h.setFault("reconnect", info)
	// One full segment after the re-dial proves the recording continues on the new link.
	time.Sleep((segmentSeconds + 4) * time.Second)
}

func (h *harness) finishFaults() {
	h.mu.Lock()
	stall, hasStall := h.faults["stall"]
	rec, hasRec := h.faults["reconnect"].(map[string]any)
	losses := slices.Clone(h.losses)
	segs := slices.Clone(h.segs)
	configs := len(h.videoConfigs)
	newEpoch := h.lastEpochLocked()
	chunks := slices.Clone(h.chunks)
	h.mu.Unlock()

	count := func(reason string) int {
		n := 0
		for _, l := range losses {
			if l.Reason == reason {
				n++
			}
		}
		return n
	}
	if hasStall {
		h.add("stall-test: exactly one REC_LOSS capture_stall", count("capture_stall") == 1,
			"%d capture_stall of %d REC_LOSS %+v (%v)", count("capture_stall"), len(losses), losses, stall)
	}
	if !hasRec {
		return
	}
	redial, _ := rec["redialMs"].(int64)
	h.add("reconnect-test: agent re-dials after the link drops", redial >= 0, "re-dial after %d ms", redial)
	if redial < 0 {
		return
	}
	maxBefore, _ := rec["maxSegmentBefore"].(int)
	epochBefore, _ := rec["epochBefore"].(int)
	minAfter, maxAfter := 0, 0
	var afterIdx []int
	for _, s := range segs {
		if s.Link > 1 {
			afterIdx = append(afterIdx, s.Meta.SegmentIndex)
			if minAfter == 0 || s.Meta.SegmentIndex < minAfter {
				minAfter = s.Meta.SegmentIndex
			}
			maxAfter = max(maxAfter, s.Meta.SegmentIndex)
		}
	}
	restarts := count("agent_restart")
	gap := minAfter > maxBefore+1
	continues := len(afterIdx) > 0 && maxAfter > maxBefore && (!gap || restarts > 0)
	h.add("reconnect-test: REC_SEGMENT index sequence continues on the new link", continues,
		"before max %d, after %v, gap %v, REC_LOSS agent_restart %d", maxBefore, afterIdx, gap, restarts)
	if !gap {
		h.addCheck("reconnect-test: no REC_LOSS agent_restart when nothing was lost", restarts == 0, false,
			"agent_restart %d", restarts)
	}
	firstKey, found := false, false
	for _, c := range chunks {
		if c.Epoch == newEpoch && newEpoch > epochBefore {
			firstKey, found = c.Keyframe, true
			break
		}
	}
	h.add("reconnect-test: live restarts with a new epoch and a keyframe", found && firstKey,
		"epoch %d -> %d, %d VIDEO_CONFIGs, first chunk of new epoch keyframe %v", epochBefore, newEpoch, configs, firstKey)
}
