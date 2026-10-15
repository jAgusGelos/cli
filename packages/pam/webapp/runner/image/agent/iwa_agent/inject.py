"""INPUT_INJECT to XTest (AD-9). The mapping helpers are pure; Xlib is imported only by XInjector."""
import threading
import time

WHEEL_STEP_PX = 40
SHIFT_L = 0xFFE1
REMAP_SETTLE_S = 0.05
US_SHIFTED = '~!@#$%^&*()_+{}|:"<>?'
TEXT_CONTROL = {"\n": 0xFF0D, "\t": 0xFF09}

_NAMED = {
    "Enter": 0xFF0D, "NumpadEnter": 0xFF8D, "Tab": 0xFF09, "Backspace": 0xFF08, "Escape": 0xFF1B,
    "Delete": 0xFFFF, "Insert": 0xFF63, "Home": 0xFF50, "End": 0xFF57, "PageUp": 0xFF55, "PageDown": 0xFF56,
    "ArrowLeft": 0xFF51, "ArrowUp": 0xFF52, "ArrowRight": 0xFF53, "ArrowDown": 0xFF54,
    "ShiftLeft": 0xFFE1, "ShiftRight": 0xFFE2, "ControlLeft": 0xFFE3, "ControlRight": 0xFFE4,
    "AltLeft": 0xFFE9, "AltRight": 0xFFEA, "MetaLeft": 0xFFEB, "MetaRight": 0xFFEC,
    "CapsLock": 0xFFE5, "ContextMenu": 0xFF67, "Space": 0x0020,
    "Minus": 0x002D, "Equal": 0x003D, "BracketLeft": 0x005B, "BracketRight": 0x005D, "Backslash": 0x005C,
    "Semicolon": 0x003B, "Quote": 0x0027, "Backquote": 0x0060, "Comma": 0x002C, "Period": 0x002E,
    "Slash": 0x002F, "IntlBackslash": 0x003C,
    "NumpadAdd": 0xFFAB, "NumpadSubtract": 0xFFAD, "NumpadMultiply": 0xFFAA, "NumpadDivide": 0xFFAF,
    "NumpadDecimal": 0xFFAE,
}

CODE_TO_KEYSYM = dict(_NAMED)
CODE_TO_KEYSYM.update({f"Key{chr(c)}": c + 0x20 for c in range(ord("A"), ord("Z") + 1)})
CODE_TO_KEYSYM.update({f"Digit{d}": 0x30 + d for d in range(10)})
CODE_TO_KEYSYM.update({f"Numpad{d}": 0xFFB0 + d for d in range(10)})
CODE_TO_KEYSYM.update({f"F{n}": 0xFFBE + n - 1 for n in range(1, 13)})

KEY_TO_KEYSYM = {
    "Enter": 0xFF0D, "Tab": 0xFF09, "Backspace": 0xFF08, "Escape": 0xFF1B, "Delete": 0xFFFF, "Insert": 0xFF63,
    "Home": 0xFF50, "End": 0xFF57, "PageUp": 0xFF55, "PageDown": 0xFF56, "ArrowLeft": 0xFF51, "ArrowUp": 0xFF52,
    "ArrowRight": 0xFF53, "ArrowDown": 0xFF54, "Shift": 0xFFE1, "Control": 0xFFE3, "Alt": 0xFFE9,
    "Meta": 0xFFEB, "CapsLock": 0xFFE5, "ContextMenu": 0xFF67,
}
KEY_TO_KEYSYM.update({f"F{n}": 0xFFBE + n - 1 for n in range(1, 13)})

BUTTON_MAP = {0: 1, 1: 2, 2: 3}


def char_keysym(ch):
    cp = ord(ch)
    if 0x20 <= cp <= 0x7E or 0xA0 <= cp <= 0xFF:
        return cp
    return 0x1000000 + cp


def keysym_for(code, key):
    """X keysym for a KeyboardEvent (code first, then key), or None."""
    ks = CODE_TO_KEYSYM.get(code or "")
    if ks is not None:
        return ks
    if key:
        if key in KEY_TO_KEYSYM:
            return KEY_TO_KEYSYM[key]
        if len(key) == 1:
            return char_keysym(key)
    return None


def text_keysyms(text):
    """Keystrokes for typed text: list of (keysym, shift) on a US layout. Shift is a hint for ASCII; the injector
    uses the live keymap level when the keysym is mapped. Carriage returns are dropped (CRLF types one Enter)."""
    out = []
    for ch in text:
        if ch == "\r":
            continue
        if ch in TEXT_CONTROL:
            out.append((TEXT_CONTROL[ch], False))
            continue
        cp = ord(ch)
        if cp < 0x20 or cp == 0x7F:
            continue
        out.append((char_keysym(ch), ("A" <= ch <= "Z") or ch in US_SHIFTED))
    return out


def clamp(v, lo, hi):
    return lo if v < lo else hi if v > hi else v


def wheel_clicks(acc, delta):
    """Accumulate a wheel delta (px). Returns (signed clicks, remaining acc); one click per 40 px, rounded."""
    acc += delta
    q = acc / WHEEL_STEP_PX
    clicks = int(q + 0.5) if q >= 0 else -int(-q + 0.5)
    return clicks, acc - clicks * WHEEL_STEP_PX


def wheel_buttons(dx_clicks, dy_clicks):
    """List of X buttons to click: 4 up, 5 down, 6 left, 7 right."""
    out = []
    if dy_clicks:
        out += [5 if dy_clicks > 0 else 4] * abs(dy_clicks)
    if dx_clicks:
        out += [7 if dx_clicks > 0 else 6] * abs(dx_clicks)
    return out


class InputState:
    """Pure part of the injector: gating, clamping, wheel accumulation, and pressed tracking."""

    def __init__(self, width, height):
        self.width, self.height = width, height
        self.enabled = True
        self.acc_x = 0.0
        self.acc_y = 0.0
        self.counts = {"injected": 0, "dropped_disabled": 0, "unknown": 0, "unmapped_key": 0, "typed_chars": 0,
                       "remapped_chars": 0}

    def point(self, ev):
        x = clamp(int(ev.get("x", 0)), 0, self.width - 1)
        y = clamp(int(ev.get("y", 0)), 0, self.height - 1)
        return x, y

    def wheel(self, ev):
        cx, self.acc_x = wheel_clicks(self.acc_x, float(ev.get("dx", 0) or 0))
        cy, self.acc_y = wheel_clicks(self.acc_y, float(ev.get("dy", 0) or 0))
        return wheel_buttons(cx, cy)


class XInjector:
    def __init__(self, width, height, display_name=":99", log=None):
        from Xlib import X, display
        from Xlib.ext import xtest
        self._X, self._xtest = X, xtest
        self._d = display.Display(display_name)
        self.state = InputState(width, height)
        self._lock = threading.Lock()
        self._log = log or (lambda *a, **k: None)
        self._keys_down = set()
        self._buttons_down = set()
        self._spare = None

    def release_all(self):
        with self._lock:
            self._release_all()

    def set_enabled(self, enabled):
        with self._lock:
            self.state.enabled = bool(enabled)
            if not self.state.enabled:
                self._release_all()

    def _release_all(self):
        X, xt, d = self._X, self._xtest, self._d
        for kc in list(self._keys_down):
            xt.fake_input(d, X.KeyRelease, kc)
        for b in list(self._buttons_down):
            xt.fake_input(d, X.ButtonRelease, b)
        self._keys_down.clear()
        self._buttons_down.clear()
        d.sync()

    def inject_batch(self, batch):
        events = batch.get("events") or []
        with self._lock:
            if not self.state.enabled:
                self.state.counts["dropped_disabled"] += len(events)
                return
            for ev in events:
                try:
                    self._inject(ev)
                except (TypeError, ValueError) as e:
                    self._log("input_bad_event", t=str(ev.get("t")), error=str(e)[:120])
            self._d.sync()

    def _move(self, x, y):
        self._xtest.fake_input(self._d, self._X.MotionNotify, x=x, y=y)

    def _inject(self, ev):
        X, xt, d, st = self._X, self._xtest, self._d, self.state
        t = ev.get("t")
        if t == "move":
            self._move(*st.point(ev))
        elif t == "button":
            b = BUTTON_MAP.get(int(ev.get("button", 0)))
            if b is None:
                st.counts["unknown"] += 1
                return
            self._move(*st.point(ev))
            if ev.get("action") == "down":
                xt.fake_input(d, X.ButtonPress, b)
                self._buttons_down.add(b)
            else:
                xt.fake_input(d, X.ButtonRelease, b)
                self._buttons_down.discard(b)
        elif t == "wheel":
            self._move(*st.point(ev))
            for b in st.wheel(ev):
                xt.fake_input(d, X.ButtonPress, b)
                xt.fake_input(d, X.ButtonRelease, b)
        elif t == "key":
            ks = keysym_for(ev.get("code"), ev.get("key"))
            kc = d.keysym_to_keycode(ks) if ks is not None else 0
            if not kc:
                st.counts["unmapped_key"] += 1
                return
            if ev.get("action") == "down":
                xt.fake_input(d, X.KeyPress, kc)
                self._keys_down.add(kc)
            else:
                xt.fake_input(d, X.KeyRelease, kc)
                self._keys_down.discard(kc)
        elif t in ("ime", "paste"):
            text = ev.get("text")
            if not isinstance(text, str):
                raise ValueError("text must be a string")
            self._type_text(text)
        else:
            st.counts["unknown"] += 1
            return
        st.counts["injected"] += 1

    def _spare_keycode(self):
        """A keycode with no keysyms, borrowed for characters the keymap does not have."""
        if self._spare is None:
            d = self._d
            lo, hi = d.display.info.min_keycode, d.display.info.max_keycode
            mapping = d.get_keyboard_mapping(lo, hi - lo + 1)
            for i in range(len(mapping) - 1, -1, -1):
                if not any(mapping[i]):
                    self._spare = (lo + i, list(mapping[i]))
                    break
            else:
                self._spare = (hi, list(mapping[-1]))
        return self._spare

    def _tap(self, kc, shift):
        X, xt, d = self._X, self._xtest, self._d
        shift_kc = d.keysym_to_keycode(SHIFT_L) if shift else 0
        if shift_kc:
            xt.fake_input(d, X.KeyPress, shift_kc)
        xt.fake_input(d, X.KeyPress, kc)
        xt.fake_input(d, X.KeyRelease, kc)
        if shift_kc:
            xt.fake_input(d, X.KeyRelease, shift_kc)

    def _type_text(self, text):
        d, st = self._d, self.state
        remapped = None
        try:
            for ks, _shift_hint in text_keysyms(text):
                levels = [(kc, idx) for kc, idx in d.keysym_to_keycodes(ks) if idx in (0, 1)]
                if levels:
                    kc, idx = min(levels, key=lambda p: p[1])
                    self._tap(kc, idx == 1)
                else:
                    spare_kc, original = self._spare_keycode()
                    if remapped != ks:
                        if remapped is not None:
                            d.sync()
                            time.sleep(REMAP_SETTLE_S)
                        # Same keysym on every level so the Shift state does not matter.
                        d.change_keyboard_mapping(spare_kc, [tuple([ks] * max(2, len(original)))])
                        d.sync()
                        remapped = ks
                    self._tap(spare_kc, False)
                    st.counts["remapped_chars"] += 1
                st.counts["typed_chars"] += 1
        finally:
            if remapped is not None:
                d.sync()
                time.sleep(REMAP_SETTLE_S)
                spare_kc, original = self._spare
                d.change_keyboard_mapping(spare_kc, [tuple(original)])
                d.sync()
