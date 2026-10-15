import json
import socket
import threading
import unittest
from types import SimpleNamespace

from _path import AGENT  # noqa: F401
from iwa_agent import frames
from iwa_agent.link import Link, LinkError, Outbox, WelcomeRejected, build_hello, dial, parse_addr

CFG = SimpleNamespace(session_id="8a0c6a4e-1f7b-4e0e-9a43-5d2a6f0b9c11", runner_token="tok_" + "a" * 40,
                      image_digest="sha256:" + "0" * 64, width=1280, height=720, fps=30)


class FakeGateway:
    def __init__(self, sock, welcome):
        self.sock = sock
        self.reader = sock.makefile("rb")
        self.welcome = welcome
        self.received = []
        self.seq = 0

    def send(self, ftype, obj):
        self.sock.sendall(frames.encode(ftype, 0, self.seq, 0, frames.json_bytes(obj)))
        self.seq += 1

    def recv(self):
        fr = frames.read_frame(self.reader)
        if fr is not None:
            self.received.append(fr)
        return fr


class LinkTest(unittest.TestCase):
    def pair(self, welcome):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        return Link(a), FakeGateway(b, welcome)

    def test_hello_welcome_and_dispatch(self):
        link, gw = self.pair({"ok": True, "recording": {"segmentSeconds": 10}})

        def gateway():
            hello = gw.recv()
            assert hello.type == frames.AGENT_HELLO and hello.seq == 0
            gw.send(frames.AGENT_WELCOME, gw.welcome)
            gw.send(frames.AGENT_CONTROL, {"kind": "live_start", "codec": "h264"})
            gw.send(frames.INPUT_INJECT, {"events": [{"t": "move", "x": 1, "y": 2}]})
            gw.send(frames.AGENT_CONTROL, {"kind": "keyframe"})
            gw.recv()
            gw.recv()
            gw.send(frames.AGENT_CONTROL, {"kind": "shutdown", "reason": "user_end"})

        t = threading.Thread(target=gateway)
        t.start()
        welcome = link.handshake(build_hello(CFG))
        self.assertTrue(welcome["ok"])
        controls, inputs = [], []
        link.send_json(frames.AGENT_EVENT, {"kind": "x"})
        link.send(frames.VIDEO_CHUNK, b"\0\0\0\1", frames.FLAG_KEYFRAME, timestamp_us=33333)

        def on_control(msg):
            controls.append(msg["kind"])
            return "stop" if msg["kind"] == "shutdown" else None

        reason = link.run(on_control, inputs.append)
        t.join(5)
        self.assertEqual(reason, "shutdown")
        self.assertEqual(controls, ["live_start", "keyframe", "shutdown"])
        self.assertEqual(inputs[0]["events"][0]["t"], "move")
        hello = gw.received[0].json()
        self.assertEqual(hello["encoderMode"], "dual")
        self.assertEqual(hello["liveCodecs"], ["vp9", "h264"])
        self.assertEqual(hello["recordingCodec"], "h264")
        self.assertEqual(hello["imageDigest"], CFG.image_digest)
        self.assertEqual(hello["display"], {"width": 1280, "height": 720, "framerate": 30})
        self.assertEqual([f.seq for f in gw.received], [0, 1, 2])
        self.assertEqual(gw.received[2].timestamp_us, 33333)
        self.assertEqual(gw.received[2].flags, frames.FLAG_KEYFRAME)

    def test_welcome_rejected_closes(self):
        link, gw = self.pair({"ok": False, "error": "unauthorized"})

        def gateway():
            gw.recv()
            gw.send(frames.AGENT_WELCOME, gw.welcome)

        t = threading.Thread(target=gateway)
        t.start()
        with self.assertRaises(WelcomeRejected):
            link.handshake(build_hello(CFG))
        t.join(5)
        self.assertTrue(link.closed.is_set())
        with self.assertRaises(LinkError):
            link.send_json(frames.AGENT_EVENT, {})

    def test_wrong_first_frame(self):
        link, gw = self.pair(None)

        def gateway():
            gw.recv()
            gw.send(frames.AGENT_CONTROL, {"kind": "keyframe"})

        t = threading.Thread(target=gateway)
        t.start()
        with self.assertRaises(LinkError):
            link.handshake(build_hello(CFG))
        t.join(5)

    def test_outbox_buffers_until_attach(self):
        link, gw = self.pair(None)
        box = Outbox()
        self.assertTrue(box.send(frames.REC_INIT, b"init"))
        self.assertFalse(box.send(frames.VIDEO_CHUNK, b"live", buffer=False))
        box.attach(link)
        box.send(frames.REC_SEGMENT, b"seg")
        self.assertEqual([gw.recv().payload, gw.recv().payload], [b"init", b"seg"])

    def test_dial_budget(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        sleeps = []
        with self.assertRaises(LinkError):
            dial(f"127.0.0.1:{port}", budget_s=0.05, retry_s=0.01, sleep=sleeps.append)
        self.assertGreaterEqual(len(sleeps), 1)
        with self.assertRaises(ValueError):
            parse_addr("nohost")


if __name__ == "__main__":
    unittest.main()
