import json
import socket
import unittest

from _path import AGENT  # noqa: F401
from iwa_agent import frames
from iwa_agent.capture import StallDetector
from iwa_agent.link import Link, LinkError, Outbox
from iwa_agent.main import parse_kbps


class StallTest(unittest.TestCase):
    def feed(self, pts_list, fps=30):
        out = []
        det = StallDetector(fps, out.append)
        for i, pts in enumerate(pts_list):
            det.offer(i, pts, 0, None, None)
        return out, det

    def test_no_stall_at_steady_rate(self):
        out, det = self.feed([i * 33333 for i in range(100)])
        self.assertEqual(out, [])

    def test_one_stall_reported_after_it_ends(self):
        pts = [i * 33333 for i in range(10)]
        resume = pts[-1] + 2_000_000
        pts += [resume + i * 1000 for i in range(60)]
        out, det = self.feed(pts)
        self.assertEqual(len(out), 1)
        loss = out[0]
        self.assertEqual(loss["reason"], "capture_stall")
        self.assertEqual(loss["fromPtsUs"], pts[9] + 33333)
        self.assertEqual(loss["toPtsUs"], resume)
        self.assertEqual(loss["framesLost"], 59)

    def test_threshold(self):
        out, _ = self.feed([0, 999_999])
        self.assertEqual(out, [])
        out, _ = self.feed([0, 1_000_000])
        self.assertEqual(out[0]["framesLost"], 29)


def seg(index, start_s, seconds=10, fps=30):
    meta = {"segmentIndex": index, "startPtsUs": start_s * 1_000_000, "endPtsUs": (start_s + seconds) * 1_000_000,
            "frameCount": seconds * fps}
    return frames.meta_payload(meta, b"body%d" % index)


class FakeLink:
    def __init__(self, fail_after=None):
        self.sent = []
        self.closed = type("E", (), {"is_set": lambda s: False})()
        self.fail_after = fail_after

    def send(self, ftype, payload=b"", flags=0, timestamp_us=None):
        if self.fail_after is not None and len(self.sent) >= self.fail_after:
            raise LinkError("send failed")
        self.sent.append((ftype, payload))


class OutboxBacklogTest(unittest.TestCase):
    def test_backlog_keeps_60s_and_reports_overflow(self):
        box = Outbox()
        box.send(frames.REC_INIT, b"init")
        for i in range(9):
            box.send(frames.REC_SEGMENT, seg(i + 1, i * 10))
        self.assertFalse(box.send(frames.VIDEO_CHUNK, b"live", buffer=False))
        box.send(frames.AGENT_EVENT, b"{}")
        link = FakeLink()
        self.assertTrue(box.attach(link))
        types = [t for t, _ in link.sent]
        self.assertEqual(types[0], frames.REC_LOSS)
        loss = json.loads(link.sent[0][1])
        self.assertEqual(loss, {"fromPtsUs": 0, "toPtsUs": 30_000_000, "framesLost": 900, "reason": "agent_restart"})
        self.assertEqual(types[1], frames.REC_INIT)
        idx = [frames.split_meta(p)[0]["segmentIndex"] for t, p in link.sent if t == frames.REC_SEGMENT]
        self.assertEqual(idx, [4, 5, 6, 7, 8, 9])
        self.assertEqual(types[-1], frames.AGENT_EVENT)
        self.assertEqual(box.lost, [])

    def test_nothing_lost_within_budget(self):
        box = Outbox()
        for i in range(6):
            box.send(frames.REC_SEGMENT, seg(i + 1, i * 10))
        link = FakeLink()
        box.attach(link)
        self.assertNotIn(frames.REC_LOSS, [t for t, _ in link.sent])
        self.assertEqual(len(link.sent), 6)

    def test_failed_send_is_kept_for_reconnect(self):
        box = Outbox()
        first = FakeLink(fail_after=1)
        box.attach(first)
        box.send(frames.REC_SEGMENT, seg(1, 0))
        self.assertTrue(box.send(frames.REC_SEGMENT, seg(2, 10)))
        self.assertFalse(box.connected)
        second = FakeLink()
        box.attach(second)
        self.assertEqual([frames.split_meta(p)[0]["segmentIndex"] for _, p in second.sent], [2])

    def test_attach_failure_rebuffers(self):
        box = Outbox()
        for i in range(3):
            box.send(frames.REC_SEGMENT, seg(i + 1, i * 10))
        self.assertFalse(box.attach(FakeLink(fail_after=1)))
        link = FakeLink()
        box.attach(link)
        self.assertEqual([frames.split_meta(p)[0]["segmentIndex"] for _, p in link.sent], [2, 3])

    def test_real_link_closed_buffers(self):
        a, b = socket.socketpair()
        self.addCleanup(b.close)
        link = Link(a)
        box = Outbox()
        box.attach(link)
        link.close()
        self.assertTrue(box.send(frames.REC_SEGMENT, seg(1, 0)))
        self.assertFalse(box.send(frames.VIDEO_CHUNK, b"x", buffer=False))


class KbpsTest(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse_kbps(None, 2500), 2500)
        self.assertEqual(parse_kbps("1200", 2500), 1200)
        self.assertEqual(parse_kbps(10, 2500), 2500)
        self.assertIsNone(parse_kbps("x", None))


if __name__ == "__main__":
    unittest.main()
