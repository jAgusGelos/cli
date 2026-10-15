import io
import os
import struct
import unittest

from _path import TESTDATA
from iwa_agent.recorder import SegmentAccounting, Splitter, ffmpeg_argv, moof_sample_count, parse_init, read_boxes


def split(path):
    with open(path, "rb") as f:
        data = f.read()
    sp = Splitter()
    events = []
    for btype, box in read_boxes(io.BytesIO(data)):
        events.extend(sp.feed(btype, box))
    return data, sp, events


class SplitterTest(unittest.TestCase):
    def test_fixture_two_segments(self):
        data, sp, events = split(os.path.join(TESTDATA, "two-segments.mp4"))
        kinds = [e[0] for e in events]
        self.assertEqual(kinds, ["init", "segment", "segment"])
        init = events[0][1]
        self.assertEqual(init[4:8], b"ftyp")
        self.assertEqual([e[2] for e in events[1:]], [10, 10])
        for e in events[1:]:
            self.assertEqual(e[1][4:8], b"moof")
        info = parse_init(init)
        self.assertEqual(info["timescale"], 90000)
        self.assertTrue(info["codec"].startswith("avc1.64"))
        covered = len(init) + sum(len(e[1]) for e in events[1:])
        self.assertLessEqual(covered, len(data))
        self.assertTrue(set(sp.ignored) <= {b"mfra", b"free", b"sidx"})

    def test_largesize_box(self):
        body = b"x" * 5
        box = struct.pack(">I4sQ", 1, b"free", 16 + len(body)) + body
        boxes = list(read_boxes(io.BytesIO(box)))
        self.assertEqual(boxes, [(b"free", box)])

    def test_moof_without_trun(self):
        moof = struct.pack(">I4s", 8, b"moof")
        self.assertEqual(moof_sample_count(moof), 0)


class AccountingTest(unittest.TestCase):
    def test_meta_with_drops(self):
        acct = SegmentAccounting(30)
        for i in range(300):
            acct.fed(i)
        for i in range(305, 600):
            acct.fed(i)
        m1 = acct.segment_meta(300, b"")
        self.assertEqual((m1["segmentIndex"], m1["startPtsUs"], m1["endPtsUs"], m1["firstFrame"]), (1, 0, 10000000, 0))
        self.assertEqual((m1["framesCaptured"], m1["framesDropped"]), (300, 0))
        m2 = acct.segment_meta(295, b"abc")
        self.assertEqual((m2["segmentIndex"], m2["firstFrame"], m2["frameCount"]), (2, 300, 295))
        self.assertEqual((m2["framesCaptured"], m2["framesDropped"]), (300, 5))
        self.assertEqual(m2["endPtsUs"], 20000000)
        self.assertEqual(m2["sha256"], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_argv(self):
        argv = ffmpeg_argv(1280, 720, 30, 10, 26, 1500)
        joined = " ".join(argv)
        for part in ("-crf 26", "-maxrate 1500k", "-bufsize 3000k", "-g 300", "-keyint_min 300", "-sc_threshold 0",
                     "-force_key_frames expr:gte(t,n_forced*10)", "-profile:v high",
                     "-movflags frag_keyframe+empty_moov+default_base_moof", "pipe:1", "-f rawvideo"):
            self.assertIn(part, joined)


if __name__ == "__main__":
    unittest.main()
