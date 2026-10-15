"""Runner agent entry point: env, capture + recorder at start, link handshake, control dispatch, shutdown."""
import json
import os
import re
import signal
import sys
import threading
import time
from dataclasses import dataclass

from .link import Link, LinkError, Outbox, WelcomeRejected, build_hello, dial

SECRET_KEYS = {"password", "runnertoken", "capem", "iwa_runner_token", "iwa_ca_pem"}
REDACTED = "[redacted]"
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
DISPLAY_RE = re.compile(r"^(\d{3,4})x(\d{3,4})@(\d{1,2})$")
ADDR_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}:\d{1,5}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def redact(obj):
    if isinstance(obj, dict):
        return {k: (REDACTED if str(k).lower() in SECRET_KEYS else redact(v)) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact(v) for v in obj]
    return obj


def format_log(level, event, fields):
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z", "level": level, "event": event}
    rec.update(redact(fields))
    return json.dumps(rec, separators=(",", ":"), default=str)


_log_lock = threading.Lock()


def log(event, level="info", **fields):
    line = format_log(level, event, fields)
    with _log_lock:
        sys.stderr.write(line + "\n")
        sys.stderr.flush()


@dataclass
class Config:
    session_id: str
    runner_token: str
    gateway_addr: str
    proxy_addr: str
    start_url: str
    allowed_hosts: list
    policy: dict
    width: int
    height: int
    fps: int
    segment_seconds: int
    bitrate_kbps: int
    crf: int
    watermark: str
    image_digest: str


def load_config(env):
    def req(name):
        v = env.get(name, "")
        if not v:
            raise ValueError(f"missing {name}")
        return v

    session_id = req("IWA_SESSION_ID")
    if not UUID_RE.match(session_id):
        raise ValueError("invalid IWA_SESSION_ID")
    token = req("IWA_RUNNER_TOKEN")
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}={0,2}", token):
        raise ValueError("invalid IWA_RUNNER_TOKEN")
    for name in ("IWA_GATEWAY_AGENT_ADDR", "IWA_PROXY_ADDR"):
        if not ADDR_RE.match(req(name)):
            raise ValueError(f"invalid {name}")
    m = DISPLAY_RE.match(req("IWA_DISPLAY"))
    if not m:
        raise ValueError("invalid IWA_DISPLAY")
    width, height, fps = (int(g) for g in m.groups())
    if not (320 <= width <= 3840 and 240 <= height <= 2160 and 1 <= fps <= 60) or width % 2 or height % 2:
        raise ValueError("IWA_DISPLAY out of range")
    hosts = json.loads(req("IWA_ALLOWED_HOSTS"))
    if not isinstance(hosts, list) or not all(isinstance(h, str) and h for h in hosts):
        raise ValueError("invalid IWA_ALLOWED_HOSTS")
    policy = json.loads(env.get("IWA_POLICY") or "{}")
    if not isinstance(policy, dict):
        raise ValueError("invalid IWA_POLICY")
    rec = json.loads(env.get("IWA_RECORDING") or "{}")
    if not isinstance(rec, dict):
        raise ValueError("invalid IWA_RECORDING")
    seg = int(rec.get("segmentSeconds", 10))
    kbps = int(rec.get("bitrateKbps", 1500))
    crf = int(rec.get("crf", 26))
    if not (2 <= seg <= 60 and 100 <= kbps <= 20000 and 0 <= crf <= 51):
        raise ValueError("IWA_RECORDING out of range")
    digest = req("IWA_IMAGE_DIGEST")
    if not DIGEST_RE.match(digest):
        raise ValueError("invalid IWA_IMAGE_DIGEST")
    return Config(session_id, token, env["IWA_GATEWAY_AGENT_ADDR"], env["IWA_PROXY_ADDR"], req("IWA_START_URL"),
                  hosts, policy, width, height, fps, seg, kbps, crf, env.get("IWA_WATERMARK", ""), digest)


def wait_for_display(name=":99", timeout_s=15):
    from Xlib import display
    from Xlib.error import DisplayError
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            display.Display(name).close()
            return
        except (DisplayError, OSError):
            if time.monotonic() > deadline:
                raise
            time.sleep(0.2)


class Terminate(Exception):
    pass


class Agent:
    def __init__(self, cfg):
        self.cfg = cfg
        self.outbox = Outbox(log)
        self.capture = None
        self.recorder = None
        self.live = None
        self.injector = None
        self.epoch = 0
        self._live_lock = threading.Lock()

    def start_media(self):
        from .capture import Capture
        from .recorder import Recorder
        c = self.cfg
        self.recorder = Recorder(c.width, c.height, c.fps, c.segment_seconds, c.crf, c.bitrate_kbps,
                                 emit=lambda t, p: self.outbox.send(t, p), log=log)
        self.recorder.start()
        self.capture = Capture(c.width, c.height, c.fps, c.watermark, log=log)
        self.capture.add_consumer(self.recorder.offer)
        self.capture.start()

    def start_live(self, msg):
        from .live import LiveEncoder
        codec = msg.get("codec", "h264")
        if codec != "h264":
            log("live_codec_unsupported", level="warn", codec=codec)
        kbps = int(msg.get("bitrateKbps") or 2500)
        with self._live_lock:
            self._stop_live_locked()
            self.epoch += 1
            c = self.cfg
            self.live = LiveEncoder(c.width, c.height, c.fps,
                                    emit=lambda t, p, f, ts: self.outbox.send(t, p, f, ts, buffer=False),
                                    epoch=self.epoch, bitrate_kbps=kbps, log=log)
            self.live.start()
            self.capture.add_consumer(self.live.offer)

    def _stop_live_locked(self):
        if self.live is not None:
            self.capture.remove_consumer(self.live.offer)
            self.live.stop()
            self.live = None

    def on_control(self, msg):
        kind = msg.get("kind")
        log("agent_control", kind=kind)
        if kind == "live_start":
            self.start_live(msg)
        elif kind == "keyframe":
            if self.live is not None:
                self.live.request_keyframe()
        elif kind == "input_enabled":
            if self.injector is not None:
                self.injector.set_enabled(bool(msg.get("enabled")))
        elif kind == "shutdown":
            log("shutdown_requested", reason=msg.get("reason"))
            return "stop"
        else:
            log("agent_control_ignored", level="warn", kind=kind)
        return None

    def on_input(self, batch):
        if self.injector is not None:
            self.injector.inject_batch(batch)

    def stop_media(self):
        with self._live_lock:
            if self.live is not None and self.capture is not None:
                self._stop_live_locked()
        if self.capture is not None:
            self.capture.stop()
        if self.recorder is not None:
            self.recorder.stop()
        log("media_stopped", frames=self.capture.frames if self.capture else 0,
            injected=self.injector.state.counts if self.injector else None)


def _on_sigterm(signum, frame):
    raise Terminate()


def run(env):
    try:
        cfg = load_config(env)
    except (ValueError, KeyError) as e:
        log("config_invalid", level="error", error=str(e))
        return 1
    log("agent_starting", sessionId=cfg.session_id, display=f"{cfg.width}x{cfg.height}@{cfg.fps}",
        imageDigest=cfg.image_digest)
    signal.signal(signal.SIGTERM, _on_sigterm)
    agent = Agent(cfg)
    link = None
    code = 1
    try:
        wait_for_display()
        from .inject import XInjector
        agent.injector = XInjector(cfg.width, cfg.height, log=log)
        agent.start_media()
        sock = dial(cfg.gateway_addr, log=log)
        link = Link(sock, log=log)
        welcome = link.handshake(build_hello(cfg))
        log("agent_welcomed", recording=welcome.get("recording"))
        agent.outbox.attach(link)
        reason = link.run(agent.on_control, agent.on_input)
        log("link_ended", reason=reason)
        code = 0 if reason == "shutdown" else 2
    except Terminate:
        log("sigterm")
        code = 0
    except WelcomeRejected as e:
        log("welcome_rejected", level="error", error=str(e))
        code = 1
    except LinkError as e:
        log("link_failed", level="error", error=str(e))
        code = 1
    except Exception as e:
        log("agent_failed", level="error", error=f"{type(e).__name__}: {e}"[:300])
        code = 1
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        agent.stop_media()
        if link is not None:
            link.close()
        log("agent_exit", code=code)
    return code


if __name__ == "__main__":
    sys.exit(run(dict(os.environ)))
