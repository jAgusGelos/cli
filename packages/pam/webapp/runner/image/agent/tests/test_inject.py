import unittest

from _path import AGENT  # noqa: F401
from iwa_agent.inject import (BUTTON_MAP, CODE_TO_KEYSYM, InputState, keysym_for, wheel_buttons, wheel_clicks)


class KeysymTableTest(unittest.TestCase):
    def test_letters_digits(self):
        self.assertEqual(CODE_TO_KEYSYM["KeyA"], ord("a"))
        self.assertEqual(CODE_TO_KEYSYM["KeyZ"], ord("z"))
        self.assertEqual(CODE_TO_KEYSYM["Digit0"], ord("0"))
        self.assertEqual(CODE_TO_KEYSYM["Digit9"], ord("9"))

    def test_named(self):
        expected = {"Enter": 0xFF0D, "Tab": 0xFF09, "Backspace": 0xFF08, "Escape": 0xFF1B, "Delete": 0xFFFF,
                    "Home": 0xFF50, "End": 0xFF57, "PageUp": 0xFF55, "PageDown": 0xFF56, "ArrowLeft": 0xFF51,
                    "ArrowUp": 0xFF52, "ArrowRight": 0xFF53, "ArrowDown": 0xFF54, "Space": 0x20,
                    "ShiftLeft": 0xFFE1, "ControlLeft": 0xFFE3, "AltLeft": 0xFFE9, "MetaLeft": 0xFFEB,
                    "F1": 0xFFBE, "F12": 0xFFC9, "Minus": ord("-"), "Slash": ord("/"), "Quote": ord("'"),
                    "Backquote": ord("`"), "BracketLeft": ord("["), "Semicolon": ord(";")}
        for code, ks in expected.items():
            with self.subTest(code):
                self.assertEqual(CODE_TO_KEYSYM[code], ks)

    def test_fallback_from_key(self):
        self.assertEqual(keysym_for("KeyQ", "a"), ord("q"))
        self.assertEqual(keysym_for("", "Enter"), 0xFF0D)
        self.assertEqual(keysym_for("Unidentified", "é"), 0xE9)
        self.assertEqual(keysym_for(None, "€"), 0x1000000 + 0x20AC)
        self.assertIsNone(keysym_for("Unidentified", "Dead"))

    def test_buttons(self):
        self.assertEqual(BUTTON_MAP, {0: 1, 1: 2, 2: 3})


class WheelTest(unittest.TestCase):
    def test_clicks_round(self):
        self.assertEqual(wheel_clicks(0, 40), (1, 0))
        self.assertEqual(wheel_clicks(0, 120), (3, 0))
        self.assertEqual(wheel_clicks(0, -80), (-2, 0))
        self.assertEqual(wheel_clicks(0, 19)[0], 0)
        self.assertEqual(wheel_clicks(0, 20)[0], 1)
        self.assertEqual(wheel_clicks(0, -20)[0], -1)

    def test_accumulates_small_deltas(self):
        acc, total = 0.0, 0
        for _ in range(8):
            c, acc = wheel_clicks(acc, 10)
            total += c
        self.assertEqual(total, 2)

    def test_buttons(self):
        self.assertEqual(wheel_buttons(0, 2), [5, 5])
        self.assertEqual(wheel_buttons(0, -1), [4])
        self.assertEqual(wheel_buttons(1, 0), [7])
        self.assertEqual(wheel_buttons(-2, 0), [6, 6])

    def test_state_wheel_and_clamp(self):
        st = InputState(1280, 720)
        self.assertEqual(st.wheel({"dx": 0, "dy": 80}), [5, 5])
        self.assertEqual(st.point({"x": -5, "y": 9999}), (0, 719))
        self.assertEqual(st.point({"x": 1500, "y": 10}), (1279, 10))
        self.assertTrue(st.enabled)


if __name__ == "__main__":
    unittest.main()
