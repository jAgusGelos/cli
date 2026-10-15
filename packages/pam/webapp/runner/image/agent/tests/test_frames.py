import io
import json
import os
import unittest

from _path import TESTDATA
from iwa_agent import frames


class FrameVectorsTest(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(TESTDATA, "frames.json")) as f:
            self.vectors = json.load(f)

    def test_vectors_round_trip(self):
        self.assertGreater(len(self.vectors), 0)
        for v in self.vectors:
            with self.subTest(v["name"]):
                raw = bytes.fromhex(v["frameHex"])
                fr = frames.decode(raw)
                self.assertEqual(fr.type, v["type"])
                self.assertEqual(fr.flags, v["flags"])
                self.assertEqual(fr.seq, v["seq"])
                self.assertEqual(fr.timestamp_us, v["timestampUs"])
                self.assertEqual(fr.payload.hex(), v["payloadHex"])
                self.assertEqual(frames.encode(fr.type, fr.flags, fr.seq, fr.timestamp_us, fr.payload), raw)

    def test_read_frame_stream(self):
        stream = io.BytesIO(b"".join(bytes.fromhex(v["frameHex"]) for v in self.vectors))
        got = []
        while True:
            fr = frames.read_frame(stream)
            if fr is None:
                break
            got.append(fr.type)
        self.assertEqual(got, [v["type"] for v in self.vectors])

    def test_rec_segment_meta(self):
        v = next(v for v in self.vectors if v["type"] == frames.REC_SEGMENT)
        meta, body = frames.split_meta(bytes.fromhex(v["payloadHex"]))
        self.assertEqual(meta["segmentIndex"], 1)
        rebuilt = frames.meta_payload(meta, body)
        self.assertEqual(frames.split_meta(rebuilt), (meta, body))


class FrameErrorsTest(unittest.TestCase):
    def test_bad_version(self):
        raw = bytearray(frames.encode(frames.AGENT_HELLO, 0, 0, 0, b"{}"))
        raw[0] = 2
        with self.assertRaises(frames.FrameError) as cm:
            frames.decode(bytes(raw))
        self.assertEqual(cm.exception.code, "protocol_error")

    def test_too_large(self):
        header = frames.HEADER.pack(1, frames.REC_SEGMENT, 0, 0, 0, frames.MAX_AGENT_PAYLOAD + 1)
        with self.assertRaises(frames.FrameError) as cm:
            frames.read_frame(io.BytesIO(header))
        self.assertEqual(cm.exception.code, "frame_too_large")
        with self.assertRaises(frames.FrameError):
            frames.encode(frames.REC_SEGMENT, 0, 0, 0, b"x" * 11, limit=10)

    def test_truncated(self):
        raw = frames.encode(frames.AGENT_HELLO, 0, 0, 0, b"{}")
        with self.assertRaises(frames.FrameError):
            frames.read_frame(io.BytesIO(raw[:-1]))
        with self.assertRaises(frames.FrameError):
            frames.read_frame(io.BytesIO(raw[:5]))
        self.assertIsNone(frames.read_frame(io.BytesIO(b"")))

    def test_seq_wraps(self):
        fr = frames.decode(frames.encode(frames.AGENT_EVENT, 0, frames.U32 + 3, 0, b""))
        self.assertEqual(fr.seq, 3)


if __name__ == "__main__":
    unittest.main()
