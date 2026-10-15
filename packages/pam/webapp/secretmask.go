package webapp

import (
	"fmt"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/webapp/contract"
)

// secretFocusWindow is how long an L3 body waits before it is recorded. A key typed into a secret field reaches the
// gateway before the extension's focus report for that field; the report trails it by the inject and report latency
// (tens of ms), so the wait lets a late report still mask the key (CONTRACTS.md 5.4). Variable so tests can shorten it.
var secretFocusWindow = 500 * time.Millisecond

const (
	maskedKey  = "*"
	maskedCode = "Masked"
	maskedText = "***"
)

// secretFocus is the L3 masking state: sensitive while any frame of the runner browser reports focus on a secret
// field. Frames report independently and in no guaranteed order across frames, hence the per-frame map.
type secretFocus struct {
	mu        sync.Mutex
	frames    map[string]bool
	clearedAt time.Time // when the state last went from sensitive to not sensitive
}

func newSecretFocus() *secretFocus {
	return &secretFocus{frames: map[string]bool{}}
}

func frameKey(ev contract.AgentEvent) string {
	tab, frame := -1, -1
	if ev.TabID != nil {
		tab = *ev.TabID
	}
	if ev.FrameID != nil {
		frame = *ev.FrameID
	}
	return fmt.Sprintf("%d:%d", tab, frame)
}

func (f *secretFocus) set(frame string, sensitive bool, at time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	was := len(f.frames) > 0
	if sensitive {
		f.frames[frame] = true
	} else {
		delete(f.frames, frame)
	}
	if was && len(f.frames) == 0 {
		f.clearedAt = at
	}
}

// sensitiveSince reports whether the state is sensitive now or was at any instant since arrival.
func (f *secretFocus) sensitiveSince(arrival time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.frames) > 0 || !f.clearedAt.Before(arrival)
}

// apply updates the state from one AGENT_EVENT; other kinds are ignored.
func (f *secretFocus) apply(ev contract.AgentEvent, at time.Time) {
	switch ev.Kind {
	case agentEventFocus:
		// A focus report without its flag counts as sensitive: masking too much is the safe side.
		f.set(frameKey(ev), ev.Sensitive == nil || *ev.Sensitive, at)
	case agentEventPage:
		f.set(frameKey(ev), false, at)
	}
}

// masked returns the body as recorded while sensitive: key identity, modifiers and typed text are replaced, the rest
// (event kinds, actions, timing, pointer input, drops) is kept. Bodies with nothing to mask are returned unchanged.
func masked(body *l3Input) *l3Input {
	out := *body
	out.Events = make([]l3Event, len(body.Events))
	for i, ev := range body.Events {
		switch ev.T {
		case inputKey:
			ev.Key, ev.Code, ev.Mods = maskedKey, maskedCode, 0
			out.Masked = true
		case inputIME, inputPaste:
			ev.Text = maskedText
			out.Masked = true
		}
		out.Events[i] = ev
	}
	if !out.Masked {
		return body
	}
	return &out
}

type pendingL3 struct {
	body    *l3Input
	arrival time.Time
}

// l3Queue records L3 bodies in arrival order, each secretFocusWindow after its arrival and stamped with it, masked
// when the focus state was sensitive at any instant in between.
type l3Queue struct {
	focus  *secretFocus
	commit func(body *l3Input, arrival time.Time)

	commitMu sync.Mutex // held across pop and commit so bodies are recorded in order

	mu      sync.Mutex
	pending []pendingL3
	timer   *time.Timer
	closed  bool
}

func newL3Queue(focus *secretFocus, commit func(*l3Input, time.Time)) *l3Queue {
	return &l3Queue{focus: focus, commit: commit}
}

func (q *l3Queue) push(body *l3Input, arrival time.Time) {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		q.commitMu.Lock()
		defer q.commitMu.Unlock()
		q.record(pendingL3{body: body, arrival: arrival})
		return
	}
	q.pending = append(q.pending, pendingL3{body: body, arrival: arrival})
	if q.timer == nil {
		q.timer = time.AfterFunc(time.Until(arrival.Add(secretFocusWindow)), q.releaseDue)
	}
	q.mu.Unlock()
}

func (q *l3Queue) releaseDue() {
	q.commitMu.Lock()
	defer q.commitMu.Unlock()
	q.mu.Lock()
	now := time.Now()
	n := 0
	for n < len(q.pending) && !now.Before(q.pending[n].arrival.Add(secretFocusWindow)) {
		n++
	}
	due := q.pending[:n:n]
	q.pending = q.pending[n:]
	q.timer = nil
	if len(q.pending) > 0 && !q.closed {
		q.timer = time.AfterFunc(time.Until(q.pending[0].arrival.Add(secretFocusWindow)), q.releaseDue)
	}
	q.mu.Unlock()
	for _, p := range due {
		q.record(p)
	}
}

// flush records every pending body now and records later ones without waiting. It runs before the recorder writes
// session_end, so no L3 body is lost or recorded after it.
func (q *l3Queue) flush() {
	q.commitMu.Lock()
	defer q.commitMu.Unlock()
	q.mu.Lock()
	q.closed = true
	if q.timer != nil {
		q.timer.Stop()
		q.timer = nil
	}
	rest := q.pending
	q.pending = nil
	q.mu.Unlock()
	for _, p := range rest {
		q.record(p)
	}
}

func (q *l3Queue) record(p pendingL3) {
	body := p.body
	if q.focus.sensitiveSince(p.arrival) {
		body = masked(body)
	}
	q.commit(body, p.arrival)
}
