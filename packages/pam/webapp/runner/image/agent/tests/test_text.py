import unittest

from _path import AGENT  # noqa: F401
from iwa_agent.inject import text_keysyms


class TextKeysymTest(unittest.TestCase):
    def test_ascii_lower_upper(self):
        self.assertEqual(text_keysyms("aZ1"), [(ord("a"), False), (ord("Z"), True), (ord("1"), False)])

    def test_shifted_punctuation(self):
        for ch in '~!@#$%^&*()_+{}|:"<>?':
            with self.subTest(ch):
                self.assertEqual(text_keysyms(ch), [(ord(ch), True)])
        for ch in "`-=[]\\;',./ ":
            with self.subTest(ch):
                self.assertEqual(text_keysyms(ch), [(ord(ch), False)])

    def test_latin1_and_unicode(self):
        self.assertEqual(text_keysyms("é"), [(0xE9, False)])
        self.assertEqual(text_keysyms("ö"), [(0xF6, False)])
        self.assertEqual(text_keysyms("€"), [(0x1000000 + 0x20AC, False)])
        self.assertEqual(text_keysyms("日"), [(0x1000000 + 0x65E5, False)])
        self.assertEqual(text_keysyms("😀"), [(0x1000000 + 0x1F600, False)])

    def test_control_characters(self):
        self.assertEqual(text_keysyms("a\r\nb\tc"), [(ord("a"), False), (0xFF0D, False), (ord("b"), False),
                                                    (0xFF09, False), (ord("c"), False)])
        self.assertEqual(text_keysyms("\x00\x07\x7f"), [])

    def test_hello_world(self):
        ks = [k for k, _ in text_keysyms("héllo wörld")]
        self.assertEqual(ks, [ord("h"), 0xE9, ord("l"), ord("l"), ord("o"), 0x20, ord("w"), 0xF6, ord("r"),
                              ord("l"), ord("d")])


if __name__ == "__main__":
    unittest.main()
