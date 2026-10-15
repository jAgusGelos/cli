package main

import (
	"encoding/json"
	"fmt"
	"image"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	demoUser          = "alice"
	demoPassword      = "S3cret-vaulted-pw"
	rogueURL          = "https://app.corp.internal/rogue.crx"
	profileExtensions = "/home/rbi/profile/Default/Extensions"
	// Tab stops on the demo app's /home before the #rogue-crx link (links and buttons in document order).
	rogueTabStops = 10
)

type windowInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Class    string `json:"class"`
	Geometry string `json:"geometry"`
	Viewable bool   `json:"viewable"`
}

type lockdownStep struct {
	Item         string            `json:"item"`
	Action       string            `json:"action"`
	StartMs      int64             `json:"startMs"`
	SnapMs       int64             `json:"snapMs"`
	Chunk        int               `json:"chunk"`
	PreChunk     int               `json:"preChunk"`
	PNG          string            `json:"png,omitempty"`
	Windows      []windowInfo      `json:"windows"`
	EarlyWindows []windowInfo      `json:"earlyWindows,omitempty"`
	Events       []json.RawMessage `json:"events,omitempty"`
	FrameDiff    float64           `json:"frameDiffVsBefore"`
	Result       string            `json:"result"`
	Detail       string            `json:"detail"`
	conformance  bool
}

type lockdownRun struct {
	ImageID         string          `json:"imageId"`
	LoggedIn        bool            `json:"loggedIn"`
	RogueServed     bool            `json:"rogueServed"`
	RogueVia        string          `json:"rogueVia"`
	Steps           []*lockdownStep `json:"steps"`
	ExtensionsDir   string          `json:"extensionsDir"`
	Quarantine      string          `json:"quarantine"`
	WatchdogEvents  int             `json:"watchdogEvents"`
	EvidenceDir     string          `json:"evidenceDir"`
	TopLevelInitial int             `json:"topLevelInitial"`
}

var childRE = regexp.MustCompile(`^\s*(0x[0-9a-f]+) (?:"(.*)"|\(has no name\)): \((.*?)\)\s+(\S+)`)

// windows lists the top-level X11 windows of the runner display with their map state.
func (h *harness) windows() []windowInfo {
	script := `xwininfo -root -children; echo ---; for w in $(xwininfo -root -children | awk '$1 ~ /^0x/ {print $1}'); do ` +
		`printf '%s ' "$w"; xwininfo -id "$w" | awk '/Map State/ {print $3}'; done`
	out, err := exec.Command("docker", "exec", "-e", "DISPLAY=:99", h.runnerName(), "sh", "-c", script).CombinedOutput()
	if err != nil {
		h.logger.Printf("xwininfo: %v %s", err, strings.TrimSpace(string(out)))
		return nil
	}
	tree, states, _ := strings.Cut(string(out), "\n---\n")
	viewable := map[string]bool{}
	for _, line := range strings.Split(states, "\n") {
		if f := strings.Fields(line); len(f) == 2 {
			viewable[f[0]] = f[1] == "IsViewable"
		}
	}
	var ws []windowInfo
	for _, line := range strings.Split(tree, "\n") {
		m := childRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ws = append(ws, windowInfo{ID: m[1], Name: m[2], Class: m[3], Geometry: m[4], Viewable: viewable[m[1]]})
	}
	return ws
}

// topLevel keeps viewable windows bigger than a tooltip-sized stub.
func topLevel(ws []windowInfo) []windowInfo {
	var out []windowInfo
	for _, w := range ws {
		var wd, ht int
		if !w.Viewable || w.Name == "" {
			continue
		}
		if _, err := fmt.Sscanf(w.Geometry, "%dx%d", &wd, &ht); err != nil || wd < 50 || ht < 50 {
			continue
		}
		out = append(out, w)
	}
	return out
}

func windowNamed(ws []windowInfo, sub string) bool {
	for _, w := range ws {
		if strings.Contains(strings.ToLower(w.Name), strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

func names(ws []windowInfo) []string {
	out := []string{}
	for _, w := range ws {
		out = append(out, fmt.Sprintf("%q %s", w.Name, w.Geometry))
	}
	return out
}

func (h *harness) snap(r *lockdownRun, item, action string, start int64, conformance bool) *lockdownStep {
	st := &lockdownStep{Item: item, Action: action, StartMs: start, SnapMs: h.sinceStartMs(), Chunk: h.chunkCount() - 1, PreChunk: -1,
		Windows: topLevel(h.windows()), conformance: conformance}
	h.mu.Lock()
	r.Steps = append(r.Steps, st)
	h.mu.Unlock()
	h.logger.Printf("lockdown %s: chunk %d, windows %v", item, st.Chunk, names(st.Windows))
	return st
}

func (h *harness) runLockdown() {
	r := &lockdownRun{ImageID: h.imageID, EvidenceDir: filepath.Join(h.o.out, "lockdown")}
	h.mu.Lock()
	h.lockdownRun = r
	h.mu.Unlock()
	_ = os.MkdirAll(r.EvidenceDir, 0o755)
	h.waitForStartPage(60 * time.Second)
	base := h.snap(r, "baseline", "start page loaded", h.sinceStartMs(), false)
	r.TopLevelInitial = len(base.Windows)

	// Setup: sign in by keyboard (the user typing, not the extension) to reach /home and its rogue CRX link.
	t0 := time.Now()
	start := h.sinceStartMs()
	h.press("Tab", "Tab")
	h.typeString(demoUser)
	h.press("Tab", "Tab")
	h.typeString(demoPassword)
	h.press("Enter", "Enter")
	r.LoggedIn = h.waitForRequest("GET", "/home", t0, 10*time.Second)
	if r.LoggedIn {
		time.Sleep(1500 * time.Millisecond)
		t1 := time.Now()
		for i := 0; i < rogueTabStops; i++ {
			h.press("Tab", "Tab")
		}
		h.press("Enter", "Enter")
		r.RogueServed = h.waitForRequest("GET", "/rogue.crx", t1, 8*time.Second)
		r.RogueVia = "Tab to #rogue-crx on /home + Enter"
		time.Sleep(2 * time.Second)
	}
	h.snap(r, "rogue CRX install", "sign in by keyboard, then follow the /rogue.crx link", start, true)

	step := func(item, action string, settle time.Duration, conformance bool, keys func()) *lockdownStep {
		time.Sleep(700 * time.Millisecond)
		pre := h.chunkCount() - 1
		start := h.sinceStartMs()
		keys()
		time.Sleep(settle)
		st := h.snap(r, item, action, start, conformance)
		st.PreChunk = pre
		return st
	}
	step("F12", "F12", 1500*time.Millisecond, true, func() { h.press("F12", "F12") })
	h.press("Escape", "Escape")
	step("Ctrl+Shift+I", "ControlLeft+ShiftLeft+KeyI", 1500*time.Millisecond, true, func() { h.press("KeyI", "I", "ControlLeft", "ShiftLeft") })
	h.press("Escape", "Escape")
	step("Ctrl+P", "ControlLeft+KeyP", 2*time.Second, true, func() { h.press("KeyP", "p", "ControlLeft") })
	// Park focus on a blank spot so a stray Enter cannot follow the focused link.
	h.click([2]int{900, 600})
	step("Ctrl+N escape window", "ControlLeft+KeyN", 2*time.Second, false, func() { h.press("KeyN", "n", "ControlLeft") })
	// The watchdog closes the escape window within its 500 ms poll, so the URL goes in as one INPUT_INJECT batch
	// right after Ctrl+N: the closed window's title in watchdog_closed shows what it was showing.
	step("typed chrome://settings", "ControlLeft+KeyN, then one batch: ControlLeft+KeyL, chrome://settings, Enter", 2500*time.Millisecond, true, func() {
		h.press("KeyN", "n", "ControlLeft")
		time.Sleep(150 * time.Millisecond)
		h.sendInput(append(append(comboEvents("KeyL", "l", "ControlLeft"), h.textEvents("chrome://settings")...),
			comboEvents("Enter", "Enter")...)...)
	})
	if !r.RogueServed {
		t2 := time.Now()
		h.press("KeyN", "n", "ControlLeft")
		time.Sleep(150 * time.Millisecond)
		h.sendInput(append(append(comboEvents("KeyL", "l", "ControlLeft"), h.textEvents(rogueURL)...),
			comboEvents("Enter", "Enter")...)...)
		r.RogueServed = h.waitForRequest("GET", "/rogue.crx", t2, 8*time.Second)
		r.RogueVia = "typed in a Ctrl+N window omnibox"
		time.Sleep(2 * time.Second)
	}
	var early []windowInfo
	tm := step("Shift+Esc Task Manager + watchdog", "ShiftLeft+Escape", 0, true, func() {
		h.press("Escape", "Escape", "ShiftLeft")
		time.Sleep(400 * time.Millisecond)
		early = topLevel(h.windows())
		time.Sleep(2100 * time.Millisecond)
	})
	h.mu.Lock()
	tm.EarlyWindows = early
	h.mu.Unlock()
	out, _ := exec.Command("docker", "exec", h.runnerName(), "sh", "-c",
		"ls -la "+profileExtensions+" 2>&1; echo; find "+profileExtensions+" -maxdepth 2 2>/dev/null").CombinedOutput()
	r.ExtensionsDir = strings.TrimSpace(string(out))
	out, _ = exec.Command("docker", "exec", h.runnerName(), "ls", "-la", "/quarantine").CombinedOutput()
	r.Quarantine = strings.TrimSpace(string(out))
}

func (h *harness) eventsBetween(from, to int64) []json.RawMessage {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []json.RawMessage
	for _, e := range h.events {
		if e.AtMs >= from && (to < 0 || e.AtMs < to) {
			out = append(out, e.Payload)
		}
	}
	return out
}

func eventKind(p json.RawMessage) (kind, wmName string) {
	var e struct {
		Kind   string `json:"kind"`
		WmName string `json:"wmName"`
	}
	_ = json.Unmarshal(p, &e)
	return e.Kind, e.WmName
}

// extensionsOK: no extension directory other than the Infisical one (M3) in the profile.
func extensionsOK(listing string) (bool, []string) {
	var found []string
	for _, line := range strings.Split(listing, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, profileExtensions+"/") {
			continue
		}
		rel := strings.TrimPrefix(line, profileExtensions+"/")
		id, _, _ := strings.Cut(rel, "/")
		if id != "Temp" && id != "lkjooopbmemjeafdccpphemkofjpfiao" && !contains(found, id) {
			found = append(found, id)
		}
	}
	return len(found) == 0, found
}

// frameDiff is the fraction of pixels whose channels differ by more than 32 between two PNGs.
func frameDiff(a, b string) float64 {
	ia, err1 := readPNG(a)
	ib, err2 := readPNG(b)
	if err1 != nil || err2 != nil || ia.Bounds() != ib.Bounds() {
		return -1
	}
	bd := ia.Bounds()
	diff := 0
	for y := bd.Min.Y; y < bd.Max.Y; y++ {
		for x := bd.Min.X; x < bd.Max.X; x++ {
			r1, g1, b1, _ := ia.At(x, y).RGBA()
			r2, g2, b2, _ := ib.At(x, y).RGBA()
			if absDiff(r1, r2) > 32<<8 || absDiff(g1, g2) > 32<<8 || absDiff(b1, b2) > 32<<8 {
				diff++
			}
		}
	}
	return float64(diff) / float64(bd.Dx()*bd.Dy())
}

func absDiff(a, b uint32) uint32 {
	if a > b {
		return a - b
	}
	return b - a
}

func readPNG(path string) (image.Image, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return png.Decode(f)
}

// finishLockdown extracts the per-step frames from the live file and grades each item.
func (h *harness) finishLockdown() {
	h.mu.Lock()
	r := h.lockdownRun
	h.mu.Unlock()
	if r == nil {
		return
	}
	for i, st := range r.Steps {
		slug := strings.Trim(regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(strings.ToLower(st.Item), "-"), "-")
		p := filepath.Join(r.EvidenceDir, fmt.Sprintf("%02d-%s.png", i, slug))
		if st.Chunk >= 0 && h.extractFrame(st.Chunk, p) {
			st.PNG = p
		}
		next := int64(-1)
		if i+1 < len(r.Steps) {
			next = r.Steps[i+1].StartMs
		}
		st.Events = h.eventsBetween(st.StartMs, next)
		st.FrameDiff = -1
		before := strings.TrimSuffix(p, ".png") + "-before.png"
		if st.PreChunk >= 0 && st.PNG != "" && h.extractFrame(st.PreChunk, before) {
			st.FrameDiff = frameDiff(before, st.PNG)
		}
	}
	for _, e := range h.eventsBetween(0, -1) {
		if k, _ := eventKind(e); k == "watchdog_closed" {
			r.WatchdogEvents++
		}
	}
	initial := r.TopLevelInitial
	var prev *lockdownStep
	for _, st := range r.Steps {
		grade(r, st, prev, initial)
		prev = st
		if st.Item == "baseline" {
			continue
		}
		fatal := st.conformance
		h.addCheck("lockdown: "+st.Item, st.Result == "PASS", fatal, "%s: %s", st.Result, st.Detail)
	}
	b, _ := json.MarshalIndent(r, "", "  ")
	_ = os.WriteFile(filepath.Join(h.o.out, "lockdown.json"), b, 0o644)
}

func grade(r *lockdownRun, st, prev *lockdownStep, initial int) {
	n := len(st.Windows)
	win := strings.Join(names(st.Windows), ", ")
	watchdog := []string{}
	for _, e := range st.Events {
		if k, wm := eventKind(e); k == "watchdog_closed" {
			watchdog = append(watchdog, wm)
		}
	}
	pass := func(ok bool, detail string, args ...any) {
		st.Result = "FAIL"
		if ok {
			st.Result = "PASS"
		}
		st.Detail = fmt.Sprintf(detail, args...)
	}
	switch st.Item {
	case "baseline":
		st.Result, st.Detail = "INFO", fmt.Sprintf("%d top-level windows: %s", n, win)
	case "rogue CRX install":
		ok, extra := extensionsOK(r.ExtensionsDir)
		if !r.RogueServed {
			st.Result, st.Detail = "FAIL", fmt.Sprintf("inconclusive: /rogue.crx never requested (logged in %v)", r.LoggedIn)
			return
		}
		pass(ok, "/rogue.crx fetched via %s; profile Extensions has no foreign id (found %v); windows: %s", r.RogueVia, extra, win)
	case "F12", "Ctrl+Shift+I":
		dev := windowNamed(st.Windows, "DevTools")
		pass(!dev && n <= initial, "DevTools window %v, top-level windows %d (baseline %d): %s", dev, n, initial, win)
	case "Ctrl+P":
		printWin := windowNamed(st.Windows, "Print")
		pass(!printWin && n <= initial && st.FrameDiff >= 0 && st.FrameDiff < 0.10,
			"print window %v, top-level windows %d (baseline %d), frame change vs just before the keys %.1f%%",
			printWin, n, initial, st.FrameDiff*100)
	case "Ctrl+N escape window":
		if n > len(prev.Windows) {
			st.Result = "FAIL"
			st.Detail = fmt.Sprintf("known kiosk escape (SPIKE F1): a second browser window is open (%s); pages stay policy-blocked; closed by the M3 extension guard or the watchdog", win)
			return
		}
		pass(true, "no extra window remained (watchdog/guard events %v): %s", watchdog, win)
	case "typed chrome://settings":
		settings := windowNamed(st.Windows, "Settings")
		for _, wm := range watchdog {
			settings = settings || strings.Contains(strings.ToLower(wm), "settings -")
		}
		pass(!settings, "no window titled Settings; windows closed by the watchdog %v; windows: %s", watchdog, win)
	case "Shift+Esc Task Manager + watchdog":
		early := windowNamed(st.EarlyWindows, "Task Manager")
		late := windowNamed(st.Windows, "Task Manager")
		closed := false
		for _, wm := range watchdog {
			closed = closed || strings.Contains(strings.ToLower(wm), "task manager")
		}
		switch {
		case late:
			st.Result = "FAIL-pending-watchdog"
			st.Detail = fmt.Sprintf("Task Manager still open 2.5 s after Shift+Esc, watchdog_closed events %v; windows: %s", watchdog, win)
		case closed:
			pass(true, "Task Manager opened (seen at 400 ms: %v) and the watchdog closed it: watchdog_closed %v", early, watchdog)
		default:
			pass(!early, "Task Manager seen at 400 ms %v, gone at 2.5 s without a watchdog_closed event %v", early, watchdog)
		}
	}
}
