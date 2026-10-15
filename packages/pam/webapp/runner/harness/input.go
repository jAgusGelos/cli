package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/Infisical/infisical-merge/packages/pam/webapp/contract"
)

// Page geometry of /input in a 1280x720 kiosk (body margin 24px, font 18px): h1 to about y=90, #txt 24px font on
// y 90..124 and 606px wide, #btn block below at y 132..166, #scroller 300px tall below it.
var (
	txtPoint      = [2]int{300, 107}
	btnPoint      = [2]int{70, 149}
	scrollerPoint = [2]int{640, 320}
)

var modBits = map[string]int{"ShiftLeft": 1, "ControlLeft": 2, "AltLeft": 4, "MetaLeft": 8}
var modKeys = map[string]string{"ShiftLeft": "Shift", "ControlLeft": "Control", "AltLeft": "Alt", "MetaLeft": "Meta"}

// usShifted maps the shifted characters of a US layout to their unshifted KeyboardEvent.code.
var usShifted = map[rune]string{
	':': "Semicolon", '!': "Digit1", '@': "Digit2", '#': "Digit3", '$': "Digit4", '%': "Digit5", '^': "Digit6",
	'&': "Digit7", '*': "Digit8", '(': "Digit9", ')': "Digit0", '_': "Minus", '+': "Equal", '?': "Slash",
	'<': "Comma", '>': "Period", '"': "Quote", '{': "BracketLeft", '}': "BracketRight", '|': "Backslash", '~': "Backquote",
}

var usPlain = map[rune]string{
	' ': "Space", '-': "Minus", '=': "Equal", '/': "Slash", '.': "Period", ',': "Comma", ';': "Semicolon",
	'\'': "Quote", '[': "BracketLeft", ']': "BracketRight", '\\': "Backslash", '`': "Backquote",
}

// charKey returns the KeyboardEvent.code a US-layout viewer reports for r and whether Shift is held.
func charKey(r rune) (code string, shift bool) {
	switch {
	case r >= 'a' && r <= 'z':
		return "Key" + string(unicode.ToUpper(r)), false
	case r >= 'A' && r <= 'Z':
		return "Key" + string(r), true
	case r >= '0' && r <= '9':
		return "Digit" + string(r), false
	}
	if c, ok := usPlain[r]; ok {
		return c, false
	}
	if c, ok := usShifted[r]; ok {
		return c, true
	}
	return "", false
}

func (h *harness) ts() float64 { return float64(h.sinceStartMs()) }

// sendInput sends one INPUT_INJECT batch and paces like a viewer.
func (h *harness) sendInput(evs ...contract.InputEvent) {
	if err := h.send(contract.FrameInputInject, contract.InputBatch{Events: evs}); err != nil {
		h.logger.Printf("INPUT_INJECT send: %v", err)
	}
	time.Sleep(40 * time.Millisecond)
}

// press sends a key with modifiers the way a browser viewer does: each modifier's own keydown, the key down/up with
// the mods bitmask, then the modifiers released in reverse order.
func (h *harness) press(code, key string, mods ...string) {
	m := 0
	for _, mod := range mods {
		m |= modBits[mod]
		h.sendInput(contract.InputEvent{T: "key", Action: "down", Code: mod, Key: modKeys[mod], Mods: m, Ts: h.ts()})
	}
	h.sendInput(contract.InputEvent{T: "key", Action: "down", Code: code, Key: key, Mods: m, Ts: h.ts()},
		contract.InputEvent{T: "key", Action: "up", Code: code, Key: key, Mods: m, Ts: h.ts()})
	for i := len(mods) - 1; i >= 0; i-- {
		m &^= modBits[mods[i]]
		h.sendInput(contract.InputEvent{T: "key", Action: "up", Code: mods[i], Key: modKeys[mods[i]], Mods: m, Ts: h.ts()})
	}
}

// comboEvents is press as one event list, for a single INPUT_INJECT batch.
func comboEvents(code, key string, mods ...string) []contract.InputEvent {
	var evs []contract.InputEvent
	m := 0
	for _, mod := range mods {
		m |= modBits[mod]
		evs = append(evs, contract.InputEvent{T: "key", Action: "down", Code: mod, Key: modKeys[mod], Mods: m})
	}
	evs = append(evs, contract.InputEvent{T: "key", Action: "down", Code: code, Key: key, Mods: m},
		contract.InputEvent{T: "key", Action: "up", Code: code, Key: key, Mods: m})
	for i := len(mods) - 1; i >= 0; i-- {
		m &^= modBits[mods[i]]
		evs = append(evs, contract.InputEvent{T: "key", Action: "up", Code: mods[i], Key: modKeys[mods[i]], Mods: m})
	}
	return evs
}

func (h *harness) textEvents(s string) []contract.InputEvent {
	var evs []contract.InputEvent
	for _, r := range s {
		code, shift := charKey(r)
		if shift {
			evs = append(evs, comboEvents(code, string(r), "ShiftLeft")...)
		} else {
			evs = append(evs, comboEvents(code, string(r))...)
		}
	}
	ts := h.ts()
	for i := range evs {
		evs[i].Ts = ts
	}
	return evs
}

func (h *harness) typeString(s string) {
	for _, r := range s {
		code, shift := charKey(r)
		if shift {
			h.press(code, string(r), "ShiftLeft")
		} else {
			h.press(code, string(r))
		}
	}
}

func (h *harness) click(p [2]int) {
	h.sendInput(contract.InputEvent{T: "move", X: p[0], Y: p[1], Ts: h.ts()})
	h.sendInput(contract.InputEvent{T: "button", Action: "down", Button: 0, X: p[0], Y: p[1], Ts: h.ts()})
	h.sendInput(contract.InputEvent{T: "button", Action: "up", Button: 0, X: p[0], Y: p[1], Ts: h.ts()})
}

func (h *harness) chunkCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.chunks)
}

func (h *harness) injectInput() {
	h.mu.Lock()
	h.inputChunk = len(h.chunks)
	h.inputRan = true
	h.mu.Unlock()
	h.logger.Printf("injecting input: click #txt, type %q, Enter, click #btn, wheel", typedText)

	h.click(txtPoint)
	h.typeString(typedText)
	h.press("Enter", "Enter")
	time.Sleep(300 * time.Millisecond)
	h.click(btnPoint)
	time.Sleep(300 * time.Millisecond)
	h.sendInput(contract.InputEvent{T: "move", X: scrollerPoint[0], Y: scrollerPoint[1], Ts: h.ts()})
	for i := 0; i < 5; i++ {
		h.sendInput(contract.InputEvent{T: "wheel", DY: 120, X: scrollerPoint[0], Y: scrollerPoint[1], Ts: h.ts()})
	}
	h.logger.Printf("input injected")
}

type demoEntry struct {
	Ts     float64 `json:"ts"`
	Method string  `json:"method"`
	Path   string  `json:"path"`
	Body   string  `json:"body"`
}

// demoLog returns the demo app's JSON log entries since the runner launch.
func (h *harness) demoLog() ([]demoEntry, []byte, error) {
	since := h.launchAt.Add(-2 * time.Second).UTC().Format(time.RFC3339)
	out, err := exec.Command("docker", "logs", "--since", since, demoAppName).CombinedOutput()
	if err != nil {
		return nil, out, err
	}
	var entries []demoEntry
	for _, line := range strings.Split(string(out), "\n") {
		var e demoEntry
		if json.Unmarshal([]byte(strings.TrimSpace(line)), &e) == nil && e.Method != "" {
			entries = append(entries, e)
		}
	}
	return entries, out, nil
}

// waitForRequest polls the demo app log for a request with this method and path prefix served after `after`.
func (h *harness) waitForRequest(method, prefix string, after time.Time, max time.Duration) bool {
	deadline := time.Now().Add(max)
	cut := float64(after.UnixNano()) / 1e9
	for {
		entries, _, _ := h.demoLog()
		for _, e := range entries {
			if e.Method == method && strings.HasPrefix(e.Path, prefix) && e.Ts >= cut {
				return true
			}
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(400 * time.Millisecond)
	}
}

// waitForStartPage waits until the demo app served the start URL path, then leaves the page a moment to render, so
// input is not typed into a blank tab. It gives up after max and injects anyway.
func (h *harness) waitForStartPage(max time.Duration) {
	u, err := url.Parse(h.o.startURL)
	if err != nil {
		return
	}
	if h.waitForRequest("GET", u.RequestURI(), h.launchAt.Add(-2*time.Second), max) {
		loaded := time.Since(h.launchAt)
		h.addCheck("start page served within 10 s of launch", loaded <= 10*time.Second, false,
			"seen %s after launch", loaded.Round(100*time.Millisecond))
		time.Sleep(1500 * time.Millisecond)
		return
	}
	h.addCheck("start page served within 10 s of launch", false, false, "not served after %s; continuing anyway",
		time.Since(h.launchAt).Round(100*time.Millisecond))
}

// verifyDemoApp reads the demo app's JSON log since launch for the start page and the input probe events.
func (h *harness) verifyDemoApp() {
	entries, raw, err := h.demoLog()
	if err != nil {
		h.add("demo app log readable", false, "docker logs: %v", err)
		return
	}
	_ = os.WriteFile(filepath.Join(h.o.out, "demo-app.log"), raw, 0o644)
	startPath := "/input"
	if u, err := url.Parse(h.o.startURL); err == nil {
		startPath = u.Path
	}
	var typed, clicked, scrolled, pageLoaded bool
	var seen []string
	scrolls := 0
	for _, e := range entries {
		if e.Method == "GET" && strings.HasPrefix(e.Path, startPath) {
			pageLoaded = true
		}
		if e.Method != "POST" || e.Path != "/event" {
			continue
		}
		var ev struct {
			Probe string `json:"probe"`
			Type  string `json:"type"`
			Value string `json:"value"`
		}
		if json.Unmarshal([]byte(e.Body), &ev) != nil || ev.Probe != "input" {
			continue
		}
		seen = append(seen, ev.Type)
		switch ev.Type {
		case "enter", "text":
			typed = typed || strings.Contains(ev.Value, typedText)
		case "click":
			clicked = true
		case "scroll":
			scrolled = true
			scrolls++
		}
	}
	h.add("runner loaded the start page through the proxy", pageLoaded, "GET %s in demo app log", startPath)
	h.mu.Lock()
	inputRan, m := h.inputRan, h.measureRes
	if m != nil {
		m.ScrollEventsSeen = scrolls
	}
	h.mu.Unlock()
	if !inputRan {
		return
	}
	if len(seen) > 12 {
		seen = append(seen[:12:12], fmt.Sprintf("... %d more", len(seen)-12))
	}
	h.add("demo app saw typed text", typed, "input events %v", seen)
	h.add("demo app saw the button click", clicked, "input events %v", seen)
	h.addCheck("demo app saw the wheel scroll", scrolled, false, "input events %v", seen)
}
