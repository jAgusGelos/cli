"""X11 watchdog (AD-7, spike F1 layer c): close any top-level window that is not the session window.

There is no window manager, so Chromium's top-level windows are direct children of the root. The decision
function is pure; Xlib is imported only by XWatchdog."""
import threading
import time
from dataclasses import dataclass

POLL_S = 0.5
ESCALATE_S = 1.0
MIN_SIZE = 64
SESSION_ROLE = "browser"
SKIP_TYPES = {
    "_NET_WM_WINDOW_TYPE_MENU", "_NET_WM_WINDOW_TYPE_DROPDOWN_MENU", "_NET_WM_WINDOW_TYPE_POPUP_MENU",
    "_NET_WM_WINDOW_TYPE_TOOLTIP", "_NET_WM_WINDOW_TYPE_NOTIFICATION", "_NET_WM_WINDOW_TYPE_COMBO",
    "_NET_WM_WINDOW_TYPE_DND",
}


@dataclass
class Win:
    id: int
    viewable: bool
    override_redirect: bool
    width: int
    height: int
    wm_class: str = ""
    wm_name: str = ""
    role: str = ""
    transient_for: int = 0
    types: tuple = ()


def is_candidate(w):
    if not w.viewable or w.override_redirect:
        return False
    if w.width < MIN_SIZE or w.height < MIN_SIZE:
        return False
    return not any(t in SKIP_TYPES for t in w.types)


def is_browser(w):
    if "chromium" not in w.wm_class.lower():
        return False
    return not w.role or w.role == SESSION_ROLE


def decide(windows, session_id):
    """Returns (session_id, [windows to close]). The session window is the first Chromium browser window seen;
    windows transient for it (bubbles, dialogs) are kept."""
    cands = [w for w in windows if is_candidate(w)]
    if session_id is None:
        for w in cands:
            if is_browser(w):
                session_id = w.id
                break
        if session_id is None:
            return None, []
    close = [w for w in cands if w.id != session_id and w.transient_for != session_id]
    return session_id, close


def client_base(wid, mask):
    """X resource ids carry the owning client in the bits outside the resource mask."""
    return wid & ~mask


def _prop_str(w, atom, ptype):
    p = w.get_full_property(atom, ptype)
    if not p or not p.value:
        return ""
    v = p.value
    return v.decode("utf-8", "replace") if isinstance(v, bytes) else str(v)


def _describe(d, atoms, w):
    from Xlib import X, Xatom
    attrs = w.get_attributes()
    geo = w.get_geometry()
    if attrs.map_state != X.IsViewable or attrs.override_redirect or attrs.win_class == X.InputOnly:
        return Win(w.id, attrs.map_state == X.IsViewable, bool(attrs.override_redirect), geo.width, geo.height)
    cls = w.get_wm_class() or ("", "")
    name = _prop_str(w, atoms["_NET_WM_NAME"], atoms["UTF8_STRING"]) or (w.get_wm_name() or "")
    role = _prop_str(w, atoms["WM_WINDOW_ROLE"], Xatom.STRING)
    tr = w.get_full_property(Xatom.WM_TRANSIENT_FOR, Xatom.WINDOW)
    tp = w.get_full_property(atoms["_NET_WM_WINDOW_TYPE"], Xatom.ATOM)
    types = tuple(d.get_atom_name(a) for a in tp.value) if tp else ()
    return Win(w.id, True, False, geo.width, geo.height, cls[1] or cls[0], str(name), role,
               int(tr.value[0]) if tr and len(tr.value) else 0, types)


class XWatchdog:
    """`emit(event_dict)` reports each closed window as `AGENT_EVENT watchdog_closed`."""

    def __init__(self, emit, display_name=":99", log=None, poll_s=POLL_S):
        self.emit = emit
        self.display_name = display_name
        self.poll_s = poll_s
        self._log = log or (lambda *a, **k: None)
        self._stop = threading.Event()
        self._thread = None
        self.session_id = None
        self._pending = {}
        self.closed = 0

    def start(self):
        self._thread = threading.Thread(target=self._run, name="watchdog", daemon=True)
        self._thread.start()

    def stop(self, timeout=2):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout)

    def _run(self):
        from Xlib import display
        from Xlib.error import XError
        try:
            d = display.Display(self.display_name)
        except Exception as e:
            self._log("watchdog_failed", error=f"{type(e).__name__}: {e}"[:200])
            return
        root = d.screen().root
        atoms = {n: d.intern_atom(n) for n in ("WM_PROTOCOLS", "WM_DELETE_WINDOW", "WM_WINDOW_ROLE",
                                               "_NET_WM_NAME", "_NET_WM_WINDOW_TYPE", "UTF8_STRING")}
        mask = d.display.info.resource_id_mask
        self._log("watchdog_started", pollMs=int(self.poll_s * 1000))
        while not self._stop.wait(self.poll_s):
            try:
                self._poll(d, root, atoms, mask)
            except XError as e:
                self._log("watchdog_x_error", error=str(e)[:200])
            except Exception as e:
                self._log("watchdog_error", error=f"{type(e).__name__}: {e}"[:200])
        d.close()

    def _poll(self, d, root, atoms, mask):
        from Xlib import X
        from Xlib.error import XError
        from Xlib.protocol import event as xevent
        wins = []
        for child in root.query_tree().children:
            try:
                wins.append(_describe(d, atoms, child))
            except XError:
                continue
        prev = self.session_id
        self.session_id, close = decide(wins, self.session_id)
        if prev is None and self.session_id is not None:
            sw = next(w for w in wins if w.id == self.session_id)
            self._log("watchdog_session_window", window=hex(sw.id), wmClass=sw.wm_class, wmName=sw.wm_name)
        live_ids = {w.id for w in close}
        for wid in list(self._pending):
            if wid not in live_ids:
                del self._pending[wid]
        for w in close:
            self._close(d, X, xevent, atoms, mask, w)
        d.flush()

    def _close(self, d, X, xevent, atoms, mask, w):
        now = time.monotonic()
        first = self._pending.get(w.id)
        win = d.create_resource_object("window", w.id)
        if first is None:
            self._pending[w.id] = now
            ev = xevent.ClientMessage(window=win, client_type=atoms["WM_PROTOCOLS"],
                                      data=(32, [atoms["WM_DELETE_WINDOW"], X.CurrentTime, 0, 0, 0]))
            win.send_event(ev, event_mask=X.NoEventMask)
            self.closed += 1
            self._log("watchdog_closed", window=hex(w.id), wmClass=w.wm_class, wmName=w.wm_name, method="wm_delete")
            self.emit({"kind": "watchdog_closed", "wmClass": w.wm_class, "wmName": w.wm_name})
        elif now - first >= ESCALATE_S:
            # XKillClient would also kill the session window when both belong to the same client (one Chromium
            # browser process owns every window), so a same-client window is unmapped instead.
            if self.session_id is not None and client_base(w.id, mask) == client_base(self.session_id, mask):
                win.unmap()
                method = "unmap"
            else:
                d.kill_client(w.id)
                method = "kill_client"
            self._pending[w.id] = now
            self._log("watchdog_escalated", window=hex(w.id), wmClass=w.wm_class, method=method)
