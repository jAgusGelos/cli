"""Agent <-> gateway link (CONTRACTS 1 and 4): dial, handshake, framed send with one writer lock, reader dispatch."""
import socket
import threading
import time

from . import frames

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
                    if fr.type == frames.AGENT_CONTROL:
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
        "liveCodecs": ["h264"],
        "recordingCodec": "h264",
        "encoderMode": "dual",
        "display": {"width": cfg.width, "height": cfg.height, "framerate": cfg.fps},
    }


class Outbox:
    """Holds agent->gateway frames until the link is welcomed, then sends directly."""

    def __init__(self, log=None):
        self._lock = threading.Lock()
        self._pending = []
        self._link = None
        self._log = log or (lambda *a, **k: None)

    def attach(self, link):
        with self._lock:
            pending, self._pending = self._pending, []
            self._link = link
            for ftype, payload, flags, ts in pending:
                link.send(ftype, payload, flags, ts)

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
            if link is None:
                if buffer:
                    self._pending.append((ftype, payload, flags, timestamp_us))
                return buffer
        try:
            link.send(ftype, payload, flags, timestamp_us)
            return True
        except LinkError:
            return False
