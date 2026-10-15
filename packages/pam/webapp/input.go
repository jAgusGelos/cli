package webapp

import (
	"encoding/json"
	"errors"
	"math"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/webapp/contract"
)

// Input limits not fixed by the contract (CONTRACTS.md 1.8 caps the frame at 61 440 bytes).
const (
	maxKeyFieldLen   = 64
	maxIMETextBytes  = 4096
	maxWheelDelta    = 100000
	malformedWindow  = 10 * time.Second
	malformedLimit   = 5
	moveRecordPeriod = 100 * time.Millisecond // L3 move events at most 10 per second
)

// droppedEntry is one L3 "dropped" item (CONTRACTS.md 5.4): filter drops carry rule, paste/clipboard drops carry bytes.
type droppedEntry struct {
	T      string `json:"t"`
	Action string `json:"action,omitempty"`
	Code   string `json:"code,omitempty"`
	Mods   int    `json:"mods,omitempty"`
	Button int    `json:"button,omitempty"`
	Rule   string `json:"rule,omitempty"`
	Bytes  *int   `json:"bytes,omitempty"`
}

type l3Input struct {
	Events   []contract.InputEvent `json:"events"`
	Dropped  []droppedEntry        `json:"dropped"`
	Masked   bool                  `json:"masked"`
	FrameSeq uint32                `json:"frameSeq"`
}

var errMalformed = errors.New("malformed input")

// inputPath validates, filters and prepares one session's viewer input (plan AD-4).
type inputPath struct {
	filter *contract.InputFilter

	mu          sync.Mutex
	fbW, fbH    int
	malformed   []time.Time
	lastMoveRec time.Time
}

func newInputPath(width, height int) *inputPath {
	return &inputPath{filter: contract.NewInputFilter(), fbW: width, fbH: height}
}

// setFramebuffer updates the coordinate bounds from VIDEO_CONFIG.
func (p *inputPath) setFramebuffer(w, h int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if w > 0 && h > 0 {
		p.fbW, p.fbH = w, h
	}
}

func (p *inputPath) inBounds(x, y int) bool {
	if p.fbW <= 0 || p.fbH <= 0 {
		return x >= 0 && y >= 0
	}
	return x >= 0 && y >= 0 && x < p.fbW && y < p.fbH
}

func (p *inputPath) validate(ev contract.InputEvent) bool {
	switch ev.T {
	case "key":
		return (ev.Action == "down" || ev.Action == "up") && ev.Code != "" && len(ev.Code) <= maxKeyFieldLen && len(ev.Key) <= maxKeyFieldLen
	case "move":
		return p.inBounds(ev.X, ev.Y)
	case "button":
		return (ev.Action == "down" || ev.Action == "up") && ev.Button >= 0 && p.inBounds(ev.X, ev.Y)
	case "wheel":
		return p.inBounds(ev.X, ev.Y) && !math.IsNaN(ev.DX) && !math.IsNaN(ev.DY) && math.Abs(ev.DX) <= maxWheelDelta && math.Abs(ev.DY) <= maxWheelDelta
	case "ime":
		return ev.Text != "" && len(ev.Text) <= maxIMETextBytes
	case "paste":
		return ev.ID != "" && ev.Total > 0 && ev.Part >= 0 && ev.Part < ev.Total
	}
	return false
}

// process handles one INPUT payload. It returns the events to inject and the L3 body to record (nil when nothing is
// worth recording, e.g. a frame of coalesced moves). err is errMalformed when the whole frame is dropped; tooMany
// reports the fifth malformed frame within 10 s.
func (p *inputPath) process(payload []byte, frameSeq uint32, arrival time.Time) (inject []contract.InputEvent, rec *l3Input, tooMany bool, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var batch contract.InputBatch
	valid := json.Unmarshal(payload, &batch) == nil
	if valid {
		for _, ev := range batch.Events {
			if !p.validate(ev) {
				valid = false
				break
			}
		}
	}
	if !valid {
		cutoff := arrival.Add(-malformedWindow)
		kept := p.malformed[:0]
		for _, t := range p.malformed {
			if t.After(cutoff) {
				kept = append(kept, t)
			}
		}
		p.malformed = append(kept, arrival)
		rec = &l3Input{Events: []contract.InputEvent{}, Dropped: []droppedEntry{{T: "malformed", Rule: "malformed"}}, FrameSeq: frameSeq}
		return nil, rec, len(p.malformed) >= malformedLimit, errMalformed
	}

	var dropped []droppedEntry
	var candidates []contract.InputEvent
	for _, ev := range batch.Events {
		if ev.T == "paste" {
			// Clipboard to the remote is off by default (CONTRACTS.md 8.3); paste reassembly is not implemented yet.
			n := len(ev.Text)
			dropped = append(dropped, droppedEntry{T: "paste_blocked", Bytes: &n})
			continue
		}
		candidates = append(candidates, ev)
	}
	kept, filtered := p.filter.Filter(candidates)
	for _, d := range filtered {
		dropped = append(dropped, droppedEntry{T: d.T, Action: d.Action, Code: d.Code, Mods: d.Mods, Button: d.Button, Rule: d.Rule})
	}

	// L3 keeps every non-move event; moves are coalesced to at most one per 100 ms, the last move of a frame wins.
	recorded := make([]contract.InputEvent, 0, len(kept))
	lastMove := -1
	for i, ev := range kept {
		if ev.T == "move" {
			lastMove = i
		}
	}
	for i, ev := range kept {
		if ev.T == "move" {
			if i != lastMove || arrival.Sub(p.lastMoveRec) < moveRecordPeriod {
				continue
			}
			p.lastMoveRec = arrival
		}
		recorded = append(recorded, ev)
	}
	if dropped == nil {
		dropped = []droppedEntry{}
	}
	if len(recorded) > 0 || len(dropped) > 0 {
		rec = &l3Input{Events: recorded, Dropped: dropped, FrameSeq: frameSeq}
	}
	return kept, rec, false, nil
}

// clipboardBlocked is the L3 body for a dropped CLIPBOARD_UP frame.
func clipboardBlocked(n int, frameSeq uint32) *l3Input {
	return &l3Input{Events: []contract.InputEvent{}, Dropped: []droppedEntry{{T: "clipboard_blocked", Bytes: &n}}, FrameSeq: frameSeq}
}
