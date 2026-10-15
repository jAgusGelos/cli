"""Agent <-> gateway link (CONTRACTS 1 and 4): dial, handshake, framed send with one writer lock, reader dispatch."""
import collections
import socket
import threading
import time

from . import frames
from .live import CODECS

AGENT_VERSION = "1.0.0"


class LinkError(Exception):
    pass


class WelcomeRejected(LinkError):
    pass


def parse_addr(addr):
    host, sep, port = addr.rpartition(":")
    if not sep or not host or not port.isdigit() or not 0 < int(port) < 65536:
        raise ValueError(f"invalid address {addr!r}")
    return host, int(port)


def dial(addr, budget_s=30.0, retry_s=1.0, connect_timeout_s=2.0, log=None, sleep=time.sleep):
    host, port = parse_addr(addr)
    deadline = time.monotonic() + budget_s
    attempt = 0
    while True:
        attempt += 1
        try:
            sock = socket.create_connection((host, port), timeout=connect_timeout_s)
            sock.settimeout(None)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            return sock
        except OSError as e:
            if log:
                log("link_dial_failed", attempt=attempt, error=type(e).__name__)
            if time.monotonic() + retry_s > deadline:
                raise LinkError(f"dial {addr} failed after {attempt} attempts") from e
            sleep(retry_s)


class Link:
    """One agent link. `send` is safe from any thread; `run` reads and dispatches on the caller's thread."""

    def __init__(self, sock, log=None):
        self._sock = sock
        self._reader = sock.makefile("rb", buffering=1 << 16)
        self._lock = threading.Lock()
        self._seq = 0
        self._t0 = time.monotonic_ns()
        self._log = log or (lambda *a, **k: None)
        self.closed = threading.Event()
        self.welcome = None
        self.recv_seq = None

    def now_us(self):
        return (time.monotonic_ns() - self._t0) // 1000

    def send(self, ftype, payload=b"", flags=0, timestamp_us=None):
        ts = self.now_us() if timestamp_us is None else timestamp_us
        with self._lock:
            if self.closed.is_set():
                raise LinkError("link closed")
            data = frames.encode(ftype, flags, self._seq, ts, payload)
            self._seq = (self._seq + 1) % frames.U32
            try:
                self._sock.sendall(data)
            except OSError as e:
                self._mark_closed()
                raise LinkError("send failed") from e

    def send_json(self, ftype, obj, flags=0):
        self.send(ftype, frames.json_bytes(obj), flags)

    def read(self):
        fr = frames.read_frame(self._reader)
        if fr is not None:
            if self.recv_seq is not None and fr.seq != (self.recv_seq + 1) % frames.U32:
                self._log("link_seq_gap", expected=(self.recv_seq + 1) % frames.U32, got=fr.seq)
            self.recv_seq = fr.seq
        return fr

    def handshake(self, hello, timeout_s=15.0):
        self.send_json(frames.AGENT_HELLO, hello)
        self._sock.settimeout(timeout_s)
        try:
            fr = self.read()
        except (OSError, frames.FrameError) as e:
            self.close()
            raise LinkError("no AGENT_WELCOME") from e
        finally:
            if not self.closed.is_set():
                self._sock.settimeout(None)
        if fr is None or fr.type != frames.AGENT_WELCOME:
            self.close()
            raise LinkError("expected AGENT_WELCOME")
        welcome = fr.json()
        if not welcome.get("ok"):
            self.close()
            raise WelcomeRejected(str(welcome.get("error", "rejected")))
        self.welcome = welcome
        return welcome

    def run(self, on_control, on_input, on_other=None):
        """Read until EOF or error. Returns a reason string."""
        try:
            while True:
                fr = self.read()
                if fr is None:
                    return "eof"
                try:
                    if fr.type in (frames.AGENT_CONTROL, frames.EXT_COMMAND):
                        if on_control(fr.json()) == "stop":
                            return "shutdown"
                    elif fr.type == frames.INPUT_INJECT:
                        on_input(fr.json())
                    elif on_other:
                        on_other(fr)
                    else:
                        self._log("link_frame_ignored", type=fr.type)
                except ValueError as e:
                    self._log("link_bad_payload", type=fr.type, error=str(e)[:200])
        except frames.FrameError as e:
            self._log("link_protocol_error", code=e.code)
            return e.code
        except OSError as e:
            if self.closed.is_set():
                return "closed"
            self._log("link_read_error", error=type(e).__name__)
            return "read_error"

    def _mark_closed(self):
        self.closed.set()

    def close(self):
        self._mark_closed()
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._sock.close()


def build_hello(cfg):
    return {
        "sessionId": cfg.session_id,
        "runnerToken": cfg.runner_token,
        "agentVersion": AGENT_VERSION,
        "imageDigest": cfg.image_digest,
        "liveCodecs": list(CODECS),
        "recordingCodec": "h264",
        "encoderMode": "dual",
        "display": {"width": cfg.width, "height": cfg.height, "framerate": cfg.fps},
    }


_Pending = collections.namedtuple("_Pending", "ftype payload flags ts span")
_Span = collections.namedtuple("_Span", "start_us end_us frames")


def _is_segment(item):
    return item.span is not None


def _is_droppable_other(item):
    return item.span is None and item.ftype not in (frames.REC_INIT, frames.REC_LOSS)


class Outbox:
    """Agent->gateway frames. While no welcomed link is attached (before WELCOME, or after a link loss until the
    reconnect is welcomed) buffered frames are kept: REC_SEGMENTs up to `backlog_us` of media (the oldest overflow
    and are reported as one `REC_LOSS agent_restart` per contiguous range after the next WELCOME), other frames up to
    `max_other`. Live frames (`buffer=False`) are dropped while detached."""

    def __init__(self, log=None, backlog_us=60_000_000, max_other=512):
        self._lock = threading.Lock()
        self._pending = collections.deque()
        self._link = None
        self._log = log or (lambda *a, **k: None)
        self.backlog_us = backlog_us
        self.max_other = max_other
        self._seg_us = 0
        self._other = 0
        self.lost = []
        self.dropped_other = 0

    def attach(self, link):
        """Send any overflow REC_LOSS, then the backlog in order. Returns False if the link failed meanwhile."""
        with self._lock:
            out = [(frames.REC_LOSS, frames.json_bytes(loss), 0, None) for loss in self.lost]
            if self.lost:
                self._log("outbox_backlog_overflow", ranges=len(self.lost),
                          framesLost=sum(x["framesLost"] for x in self.lost))
            self.lost = []
            out += [(p.ftype, p.payload, p.flags, p.ts) for p in self._pending]
            self._pending.clear()
            self._seg_us = self._other = 0
            for k, item in enumerate(out):
                try:
                    link.send(*item)
                except LinkError:
                    for rest in out[k:]:
                        self._buffer_locked(*rest)
                    return False
            self._link = link
            if out:
                self._log("outbox_flushed", frames=len(out))
            return True

    def detach(self):
        with self._lock:
            self._link = None

    @property
    def connected(self):
        link = self._link
        return link is not None and not link.closed.is_set()

    def send(self, ftype, payload, flags=0, timestamp_us=None, buffer=True):
        """Returns True when sent or buffered."""
        with self._lock:
            link = self._link
            if link is not None and not link.closed.is_set():
                try:
                    link.send(ftype, payload, flags, timestamp_us)
                    return True
                except LinkError:
                    self._link = None
            else:
                self._link = None
            if buffer:
                self._buffer_locked(ftype, payload, flags, timestamp_us)
            return buffer

    def _buffer_locked(self, ftype, payload, flags, ts):
        span = None
        if ftype == frames.REC_SEGMENT:
            meta, _ = frames.split_meta(payload)
            span = _Span(meta["startPtsUs"], meta["endPtsUs"], meta["frameCount"])
            self._seg_us += span.end_us - span.start_us
        else:
            self._other += 1
        self._pending.append(_Pending(ftype, payload, flags, ts, span))
        while self._seg_us > self.backlog_us:
            self._drop_oldest_locked(_is_segment)
        while self._other > self.max_other:
            self._drop_oldest_locked(_is_droppable_other)

    def _drop_oldest_locked(self, match):
        for k, item in enumerate(self._pending):
            if match(item):
                del self._pending[k]
                break
        else:
            self._other = min(self._other, self.max_other)
            return
        span = item.span
        if span is None:
            self._other -= 1
            self.dropped_other += 1
            return
        self._seg_us -= span.end_us - span.start_us
        if self.lost and self.lost[-1]["toPtsUs"] == span.start_us:
            self.lost[-1]["toPtsUs"] = span.end_us
            self.lost[-1]["framesLost"] += span.frames
        else:
            self.lost.append({"fromPtsUs": span.start_us, "toPtsUs": span.end_us, "framesLost": span.frames,
                              "reason": "agent_restart"})
