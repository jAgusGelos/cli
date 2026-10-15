import unittest

from _path import AGENT  # noqa: F401
from iwa_agent.watchdog import Win, client_base, decide, is_candidate


def win(wid, cls="Chromium", name="input - Chromium", role="browser", **kw):
    base = dict(viewable=True, override_redirect=False, width=1280, height=720)
    base.update(kw)
    return Win(wid, wm_class=cls, wm_name=name, role=role, **base)


class WatchdogDecisionTest(unittest.TestCase):
    def test_first_browser_window_is_session(self):
        sid, close = decide([win(0x400001)], None)
        self.assertEqual(sid, 0x400001)
        self.assertEqual(close, [])

    def test_no_window_yet(self):
        self.assertEqual(decide([], None), (None, []))
        self.assertEqual(decide([win(1, viewable=False)], None), (None, []))

    def test_task_manager_and_new_window_closed(self):
        tm = win(0x400050, name="Task Manager - Chromium", role="task_manager", width=600, height=400)
        extra = win(0x400090, name="New Tab - Chromium")
        sid, close = decide([win(0x400001), tm, extra], 0x400001)
        self.assertEqual(sid, 0x400001)
        self.assertEqual([w.id for w in close], [0x400050, 0x400090])

    def test_task_manager_never_becomes_session(self):
        tm = win(0x400050, name="Task Manager - Chromium", role="task_manager")
        sid, close = decide([tm], None)
        self.assertIsNone(sid)
        self.assertEqual(close, [])

    def test_popups_menus_tooltips_kept(self):
        ws = [win(1),
              win(2, override_redirect=True, role=""),
              win(3, viewable=False),
              win(4, width=10, height=10),
              win(5, types=("_NET_WM_WINDOW_TYPE_MENU",)),
              win(6, types=("_NET_WM_WINDOW_TYPE_TOOLTIP",)),
              win(7, role="bubble", transient_for=1, width=300, height=200)]
        sid, close = decide(ws, 1)
        self.assertEqual(close, [])

    def test_transient_for_other_window_closed(self):
        sid, close = decide([win(1), win(8, role="bubble", transient_for=99)], 1)
        self.assertEqual([w.id for w in close], [8])

    def test_non_chromium_window_closed(self):
        sid, close = decide([win(1), win(2, cls="XTerm", role="")], 1)
        self.assertEqual([w.id for w in close], [2])

    def test_session_gone_is_not_replaced(self):
        sid, close = decide([win(2)], 1)
        self.assertEqual(sid, 1)
        self.assertEqual([w.id for w in close], [2])

    def test_candidate_and_client_base(self):
        self.assertFalse(is_candidate(win(1, override_redirect=True)))
        self.assertTrue(is_candidate(win(1)))
        self.assertEqual(client_base(0x400050, 0x1FFFFF), client_base(0x400001, 0x1FFFFF))
        self.assertNotEqual(client_base(0x600001, 0x1FFFFF), client_base(0x400001, 0x1FFFFF))


if __name__ == "__main__":
    unittest.main()
