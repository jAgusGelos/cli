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

// l3Event is a recorded input event; synthetic marks gateway-generated releases (CONTRACTS.md section 7).
type l3Event struct {
	contract.InputEvent
	Synthetic bool `json:"synthetic,omitempty"`
}

type l3Input struct {
	Events   []l3Event      `json:"events"`
	Dropped  []droppedEntry `json:"dropped"`
	Masked   bool           `json:"masked"`
	FrameSeq uint32         `json:"frameSeq"`
}

// Input event types and actions (CONTRACTS.md 1.8) and the L3 drop kinds the gateway adds.
const (
	inputKey    = "key"
	inputMove   = "move"
	inputButton = "button"
	inputWheel  = "wheel"
	inputIME    = "ime"
	inputPaste  = "paste"

	actionDown = "down"
	actionUp   = "up"

	dropMalformed        = "malformed"
	dropPasteBlocked     = "paste_blocked"
	dropClipboardBlocked = "clipboard_blocked"
)

var errMalformed = errors.New("malformed input")

// inputPath validates, filters and prepares one session's viewer input (plan AD-4).
type inputPath struct {
	filter *contract.InputFilter

	mu          sync.Mutex
	heldKeys    map[string]contract.InputEvent // injected key down without its up, by code
	heldButtons map[int]contract.InputEvent
	fbW, fbH    int
	malformed   []time.Time
	lastMoveRec time.Time
}

func newInputPath(width, height int) *inputPath {
	return &inputPath{filter: contract.NewInputFilter(), fbW: width, fbH: height,
		heldKeys: map[string]contract.InputEvent{}, heldButtons: map[int]contract.InputEvent{}}
}

// trackInjected remembers what the agent holds down after injecting kept.
func (p *inputPath) trackInjected(kept []contract.InputEvent) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, ev := range kept {
		switch {
		case ev.T == inputKey && ev.Action == actionDown:
			p.heldKeys[ev.Code] = ev
		case ev.T == inputKey && ev.Action == actionUp:
			delete(p.heldKeys, ev.Code)
		case ev.T == inputButton && ev.Action == actionDown:
			p.heldButtons[ev.Button] = ev
		case ev.T == inputButton && ev.Action == actionUp:
			delete(p.heldButtons, ev.Button)
		}
	}
}

// releases returns a key up for every held key and a button up for every held button, then clears the filter state.
func (p *inputPath) releases() []contract.InputEvent {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []contract.InputEvent
	for code, ev := range p.heldKeys {
		out = append(out, contract.InputEvent{T: inputKey, Action: actionUp, Code: code, Key: ev.Key})
	}
	for b, ev := range p.heldButtons {
		out = append(out, contract.InputEvent{T: inputButton, Action: actionUp, Button: b, X: ev.X, Y: ev.Y})
	}
	p.heldKeys = map[string]contract.InputEvent{}
	p.heldButtons = map[int]contract.InputEvent{}
	p.filter = contract.NewInputFilter()
	return out
}

func toL3(evs []contract.InputEvent, synthetic bool) []l3Event {
	out := make([]l3Event, 0, len(evs))
	for _, ev := range evs {
		out = append(out, l3Event{InputEvent: ev, Synthetic: synthetic})
	}
	return out
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
	case inputKey:
		return (ev.Action == actionDown || ev.Action == actionUp) && ev.Code != "" && len(ev.Code) <= maxKeyFieldLen && len(ev.Key) <= maxKeyFieldLen
	case inputMove:
		return p.inBounds(ev.X, ev.Y)
	case inputButton:
		return (ev.Action == actionDown || ev.Action == actionUp) && ev.Button >= 0 && p.inBounds(ev.X, ev.Y)
	case inputWheel:
		return p.inBounds(ev.X, ev.Y) && !math.IsNaN(ev.DX) && !math.IsNaN(ev.DY) && math.Abs(ev.DX) <= maxWheelDelta && math.Abs(ev.DY) <= maxWheelDelta
	case inputIME:
		return ev.Text != "" && len(ev.Text) <= maxIMETextBytes
	case inputPaste:
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
		rec = &l3Input{Events: []l3Event{}, Dropped: []droppedEntry{{T: dropMalformed, Rule: dropMalformed}}, FrameSeq: frameSeq}
		return nil, rec, p.noteMalformedLocked(arrival) >= malformedLimit, errMalformed
	}

	var dropped []droppedEntry
	var candidates []contract.InputEvent
	for _, ev := range batch.Events {
		if ev.T == inputPaste {
			// Clipboard to the remote is off by default (CONTRACTS.md 8.3); paste reassembly is not implemented yet.
			n := len(ev.Text)
			dropped = append(dropped, droppedEntry{T: dropPasteBlocked, Bytes: &n})
			continue
		}
		candidates = append(candidates, ev)
	}
	kept, filtered := p.filter.Filter(candidates)
	for _, d := range filtered {
		dropped = append(dropped, droppedEntry{T: d.T, Action: d.Action, Code: d.Code, Mods: d.Mods, Button: d.Button, Rule: d.Rule})
	}

	recorded := p.coalesceMovesLocked(kept, arrival)
	if dropped == nil {
		dropped = []droppedEntry{}
	}
	if len(recorded) > 0 || len(dropped) > 0 {
		rec = &l3Input{Events: toL3(recorded, false), Dropped: dropped, FrameSeq: frameSeq}
	}
	return kept, rec, false, nil
}

// noteMalformedLocked adds a malformed frame at arrival and returns how many fell within malformedWindow.
func (p *inputPath) noteMalformedLocked(arrival time.Time) int {
	cutoff := arrival.Add(-malformedWindow)
	kept := p.malformed[:0]
	for _, t := range p.malformed {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	p.malformed = append(kept, arrival)
	return len(p.malformed)
}

// coalesceMovesLocked keeps every non-move event for L3; moves are coalesced to at most one per moveRecordPeriod, the
// last move of a frame wins.
func (p *inputPath) coalesceMovesLocked(kept []contract.InputEvent, arrival time.Time) []contract.InputEvent {
	recorded := make([]contract.InputEvent, 0, len(kept))
	lastMove := -1
	for i, ev := range kept {
		if ev.T == inputMove {
			lastMove = i
		}
	}
	for i, ev := range kept {
		if ev.T == inputMove {
			if i != lastMove || arrival.Sub(p.lastMoveRec) < moveRecordPeriod {
				continue
			}
			p.lastMoveRec = arrival
		}
		recorded = append(recorded, ev)
	}
	return recorded
}

// clipboardBlocked is the L3 body for a dropped CLIPBOARD_UP frame.
func clipboardBlocked(n int, frameSeq uint32) *l3Input {
	return &l3Input{Events: []l3Event{}, Dropped: []droppedEntry{{T: dropClipboardBlocked, Bytes: &n}}, FrameSeq: frameSeq}
}
