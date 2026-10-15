package webapp

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/webapp/contract"
	"github.com/stretchr/testify/require"
)

func focusEvent(sensitive *bool, tab, frame int) contract.AgentEvent {
	return contract.AgentEvent{Kind: agentEventFocus, Sensitive: sensitive, TabID: &tab, FrameID: &frame}
}

func boolPtr(b bool) *bool { return &b }

func intPtr(i int) *int { return &i }

func TestSecretFocusAggregatesFrames(t *testing.T) {
	f := newSecretFocus()
	t0 := time.Now()
	f.apply(focusEvent(boolPtr(true), 1, 0), t0)
	f.apply(focusEvent(boolPtr(false), 1, 4), t0.Add(time.Millisecond))
	require.True(t, f.sensitiveSince(t0.Add(time.Hour)), "another frame leaving focus does not clear the top frame")

	f.apply(focusEvent(boolPtr(true), 1, 4), t0.Add(2*time.Millisecond))
	f.apply(focusEvent(boolPtr(false), 1, 0), t0.Add(3*time.Millisecond))
	require.True(t, f.sensitiveSince(t0.Add(time.Hour)), "the iframe is still on a secret field")

	cleared := t0.Add(10 * time.Millisecond)
	f.apply(contract.AgentEvent{Kind: agentEventPage, TabID: intPtr(1), FrameID: intPtr(4)}, cleared)
	require.True(t, f.sensitiveSince(cleared), "a body that arrived when the state cleared is masked")
	require.True(t, f.sensitiveSince(t0), "a body that arrived while sensitive is masked")
	require.False(t, f.sensitiveSince(cleared.Add(time.Microsecond)))
}

func TestSecretFocusMissingFlagIsSensitive(t *testing.T) {
	f := newSecretFocus()
	f.apply(focusEvent(nil, 2, 0), time.Now())
	require.True(t, f.sensitiveSince(time.Now()))
}

func TestSecretFocusIgnoresOtherKinds(t *testing.T) {
	f := newSecretFocus()
	f.apply(contract.AgentEvent{Kind: "ext_hello", Sensitive: boolPtr(true)}, time.Now())
	require.False(t, f.sensitiveSince(time.Now()))
}

func TestMaskedReplacesKeysAndText(t *testing.T) {
	body := &l3Input{Events: []l3Event{
		{InputEvent: contract.InputEvent{T: inputKey, Action: actionDown, Code: "KeyS", Key: "S", Mods: contract.ModShift, Ts: 1}},
		{InputEvent: contract.InputEvent{T: inputKey, Action: actionUp, Code: "KeyS", Key: "S", Mods: contract.ModShift, Ts: 2}, Synthetic: true},
		{InputEvent: contract.InputEvent{T: inputIME, Text: "contraseña"}},
		{InputEvent: contract.InputEvent{T: inputButton, Action: actionDown, X: 4, Y: 5}},
	}, Dropped: []droppedEntry{{T: inputKey, Code: "KeyN", Mods: 2, Rule: "Ctrl+N"}}, FrameSeq: 9}

	out := masked(body)
	raw, err := json.Marshal(out)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "KeyS")
	require.NotContains(t, string(raw), `"S"`)
	require.NotContains(t, string(raw), "contraseña")
	require.True(t, out.Masked)
	require.Equal(t, l3Event{InputEvent: contract.InputEvent{T: inputKey, Action: actionDown, Code: maskedCode, Key: maskedKey, Ts: 1}}, out.Events[0])
	require.True(t, out.Events[1].Synthetic)
	require.Equal(t, actionUp, out.Events[1].Action)
	require.Equal(t, maskedText, out.Events[2].Text)
	require.Equal(t, body.Events[3], out.Events[3], "pointer input is kept")
	require.Equal(t, body.Dropped, out.Dropped)
	require.Equal(t, uint32(9), out.FrameSeq)
	require.Equal(t, "KeyS", body.Events[0].Code, "the caller's body is not modified")
}

func TestMaskedLeavesPointerOnlyBodies(t *testing.T) {
	body := &l3Input{Events: []l3Event{{InputEvent: contract.InputEvent{T: inputMove, X: 1, Y: 1}}}, Dropped: []droppedEntry{}}
	require.Same(t, body, masked(body))
}

type committed struct {
	mu     sync.Mutex
	bodies []*l3Input
}

func (c *committed) add(body *l3Input, _ time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bodies = append(c.bodies, body)
}

func (c *committed) snapshot() []*l3Input {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*l3Input(nil), c.bodies...)
}

func keyBody(code string, seq uint32) *l3Input {
	return &l3Input{Events: []l3Event{{InputEvent: contract.InputEvent{T: inputKey, Action: actionDown, Code: code, Key: "x"}}}, Dropped: []droppedEntry{}, FrameSeq: seq}
}

func TestL3QueueMasksBodiesBeforeALateFocusReport(t *testing.T) {
	focus := newSecretFocus()
	var c committed
	q := newL3Queue(focus, c.add)
	t0 := time.Now()
	q.push(keyBody("KeyA", 1), t0)
	focus.apply(focusEvent(boolPtr(true), 1, 0), t0.Add(50*time.Millisecond))
	q.push(keyBody("KeyB", 2), t0.Add(60*time.Millisecond))
	focus.apply(focusEvent(boolPtr(false), 1, 0), t0.Add(70*time.Millisecond))
	q.push(keyBody("KeyC", 3), t0.Add(80*time.Millisecond))
	q.flush()

	got := c.snapshot()
	require.Len(t, got, 3)
	for i, want := range []struct {
		seq    uint32
		masked bool
	}{{1, true}, {2, true}, {3, false}} {
		require.Equal(t, want.seq, got[i].FrameSeq, "bodies keep their arrival order")
		require.Equal(t, want.masked, got[i].Masked, "body %d", want.seq)
	}
	require.Equal(t, "KeyC", got[2].Events[0].Code)
}

func TestL3QueueRecordsAfterTheWindow(t *testing.T) {
	prev := secretFocusWindow
	secretFocusWindow = 20 * time.Millisecond
	t.Cleanup(func() { secretFocusWindow = prev })

	var c committed
	q := newL3Queue(newSecretFocus(), c.add)
	q.push(keyBody("KeyA", 1), time.Now())
	q.push(keyBody("KeyB", 2), time.Now())
	require.Empty(t, c.snapshot(), "nothing is recorded inside the window")
	require.Eventually(t, func() bool { return len(c.snapshot()) == 2 }, 2*time.Second, 5*time.Millisecond)
	require.Equal(t, uint32(1), c.snapshot()[0].FrameSeq)

	q.flush()
	q.push(keyBody("KeyC", 3), time.Now())
	require.Len(t, c.snapshot(), 3, "after the flush, bodies are recorded at once")
}

// A key typed into a password field reaches the gateway before the extension reports the focus; it must still be
// recorded masked, while keys after the field lost focus are recorded as typed.
func TestHarnessMasksKeysTypedIntoASecretField(t *testing.T) {
	prev := secretFocusWindow
	secretFocusWindow = 300 * time.Millisecond
	t.Cleanup(func() { secretFocusWindow = prev })

	h := newHarness(t)
	v, agent, done := startSession(t, h, h.params())
	typeKey := func(code, key string) {
		t.Helper()
		v.send(t, contract.FrameInput, []byte(`{"events":[{"t":"key","action":"down","code":"`+code+`","key":"`+key+`","mods":1,"ts":1},{"t":"key","action":"up","code":"`+code+`","key":"`+key+`","ts":2}]}`))
		select {
		case <-agent.injected:
		case <-time.After(5 * time.Second):
			t.Fatal("no INPUT_INJECT")
		}
	}

	typeKey("KeyS", "S")
	agent.write(contract.FrameAgentEvent, []byte(`{"kind":"focus","sensitive":true,"tabId":1,"frameId":0}`))
	typeKey("Digit3", "#")
	agent.write(contract.FrameAgentEvent, []byte(`{"kind":"focus","sensitive":false,"tabId":1,"frameId":0}`))
	h.svc.mu.Lock()
	ls := h.svc.live[hSession]
	h.svc.mu.Unlock()
	require.Eventually(t, func() bool {
		ls.focus.mu.Lock()
		defer ls.focus.mu.Unlock()
		return len(ls.focus.frames) == 0 && !ls.focus.clearedAt.IsZero()
	}, 5*time.Second, 5*time.Millisecond, "the gateway applied focus true, then false")
	typeKey("KeyQ", "Q")
	v.endSession(t, done)

	res, err := h.backend.Verify(h.key, hSession, h.svc.RecordingPublicKey())
	require.NoError(t, err)
	bodies := l3Bodies(t, res)
	require.Len(t, bodies, 3)
	for i, want := range []bool{true, true, false} {
		require.Equal(t, want, bodies[i].Masked, "body %d", i)
	}
	for _, e := range res.ByType(contract.EventL3Input)[:2] {
		require.NotContains(t, string(e.Body), "KeyS")
		require.NotContains(t, string(e.Body), "Digit3")
		require.NotContains(t, string(e.Body), `"#"`)
	}
	require.Equal(t, "KeyQ", bodies[2].Events[0].Code)
	require.Equal(t, contract.EventSessionEnd, res.Events[len(res.Events)-1].Type, "queued L3 is recorded before session_end")
}
