package contract

// Gateway input filter: browser-chrome shortcuts dropped before injection (CONTRACTS.md section 7, D-11 item 11).

type ShortcutRule struct {
	Name  string
	Codes []string // empty = any code
	Mods  int      // all of these must be held; extra modifiers do not prevent a match
}

var fKeys = []string{"F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F10", "F11", "F12"}

// ShortcutRules is the normative list; order decides which rule name is reported.
var ShortcutRules = []ShortcutRule{
	{"Ctrl+Alt+*", append(append([]string{}, fKeys...), "Backspace"), ModCtrl | ModAlt},
	{"Meta+*", nil, ModMeta},
	{"MetaLeft/MetaRight", []string{"MetaLeft", "MetaRight", "OSLeft", "OSRight"}, 0},
	{"Ctrl+Shift+Delete", []string{"Delete"}, ModCtrl | ModShift},
	{"Ctrl+Shift+I", []string{"KeyI"}, ModCtrl | ModShift},
	{"Ctrl+Shift+J", []string{"KeyJ"}, ModCtrl | ModShift},
	{"Ctrl+Shift+C", []string{"KeyC"}, ModCtrl | ModShift},
	{"Ctrl+Shift+B", []string{"KeyB"}, ModCtrl | ModShift},
	{"Ctrl+Shift+M", []string{"KeyM"}, ModCtrl | ModShift},
	{"Ctrl+Shift+A", []string{"KeyA"}, ModCtrl | ModShift},
	{"Ctrl+N", []string{"KeyN"}, ModCtrl},
	{"Ctrl+T", []string{"KeyT"}, ModCtrl},
	{"Ctrl+W", []string{"KeyW"}, ModCtrl},
	{"Ctrl+F4", []string{"F4"}, ModCtrl},
	{"Alt+F4", []string{"F4"}, ModAlt},
	{"Ctrl+Q", []string{"KeyQ"}, ModCtrl},
	{"Ctrl+H", []string{"KeyH"}, ModCtrl},
	{"Ctrl+J", []string{"KeyJ"}, ModCtrl},
	{"F12", []string{"F12"}, 0},
	{"Ctrl+U", []string{"KeyU"}, ModCtrl},
	{"Ctrl+P", []string{"KeyP"}, ModCtrl},
	{"Ctrl+S", []string{"KeyS"}, ModCtrl},
	{"Ctrl+O", []string{"KeyO"}, ModCtrl},
	{"F11", []string{"F11"}, 0},
	{"Ctrl+L", []string{"KeyL"}, ModCtrl},
	{"Alt+D", []string{"KeyD"}, ModAlt},
	{"F6", []string{"F6"}, 0},
	{"Ctrl+K", []string{"KeyK"}, ModCtrl},
	{"Ctrl+E", []string{"KeyE"}, ModCtrl},
	{"Ctrl+D", []string{"KeyD"}, ModCtrl},
	{"Alt+Home", []string{"Home"}, ModAlt},
	{"Alt+F", []string{"KeyF"}, ModAlt},
	{"Alt+E", []string{"KeyE"}, ModAlt},
	{"F10", []string{"F10"}, 0},
	{"F7", []string{"F7"}, 0},
	{"Shift+Escape", []string{"Escape"}, ModShift},
}

// MatchShortcut returns the name of the first rule matching a key event, or "".
func MatchShortcut(code string, mods int) string {
	for _, r := range ShortcutRules {
		if mods&r.Mods != r.Mods {
			continue
		}
		if len(r.Codes) == 0 {
			return r.Name
		}
		for _, c := range r.Codes {
			if c == code {
				return r.Name
			}
		}
	}
	return ""
}

// DroppedEvent is an entry of the L3 "dropped" list.
type DroppedEvent struct {
	T      string `json:"t"`
	Action string `json:"action,omitempty"`
	Code   string `json:"code,omitempty"`
	Mods   int    `json:"mods,omitempty"`
	Button int    `json:"button,omitempty"`
	Rule   string `json:"rule"`
}

// InputFilter is per session. It remembers codes dropped on keydown so the matching keyup is dropped too.
type InputFilter struct {
	droppedDown map[string]string
}

func NewInputFilter() *InputFilter { return &InputFilter{droppedDown: map[string]string{}} }

// Filter splits a batch into events to inject and events dropped by a rule.
func (f *InputFilter) Filter(events []InputEvent) (kept []InputEvent, dropped []DroppedEvent) {
	for _, ev := range events {
		switch ev.T {
		case "key":
			if ev.Action == "up" {
				if rule, ok := f.droppedDown[ev.Code]; ok {
					delete(f.droppedDown, ev.Code)
					dropped = append(dropped, DroppedEvent{T: "key", Action: "up", Code: ev.Code, Mods: ev.Mods, Rule: rule})
					continue
				}
			} else if rule := MatchShortcut(ev.Code, ev.Mods); rule != "" {
				f.droppedDown[ev.Code] = rule
				dropped = append(dropped, DroppedEvent{T: "key", Action: ev.Action, Code: ev.Code, Mods: ev.Mods, Rule: rule})
				continue
			}
		case "button":
			if ev.Button < 0 || ev.Button > 2 {
				dropped = append(dropped, DroppedEvent{T: "button", Action: ev.Action, Button: ev.Button, Rule: "Button>2"})
				continue
			}
		}
		kept = append(kept, ev)
	}
	return kept, dropped
}
