"""Recording encoder (AD-3): ffmpeg child fed raw yuv420p, fMP4 on stdout split into REC_INIT / REC_SEGMENT."""
import collections
import hashlib
import queue
import struct
import subprocess
import threading

from . import frames

CONTAINERS = {b"moov", b"trak", b"mdia", b"minf", b"stbl", b"moof", b"traf", b"mvex", b"edts", b"dinf"}


class BoxError(Exception):
    pass


def iter_boxes(buf, start=0, end=None):
    """Yield (type, offset, size, header_len) for the boxes in buf[start:end]."""
    end = len(buf) if end is None else end
    off = start
    while off + 8 <= end:
        size, btype = struct.unpack(">I4s", buf[off:off + 8])
        hdr = 8
        if size == 1:
            if off + 16 > end:
                raise BoxError("truncated largesize")
            size = struct.unpack(">Q", buf[off + 8:off + 16])[0]
            hdr = 16
        elif size == 0:
            size = end - off
        if size < hdr or off + size > end:
            raise BoxError(f"bad box {btype!r} size {size}")
        yield btype, off, size, hdr
        off += size


def find_box(buf, path, start=0, end=None):
    """Find a nested box by path of types; returns (offset, size, header_len) or None."""
    for btype, off, size, hdr in iter_boxes(buf, start, end):
        if btype == path[0]:
            if len(path) == 1:
                return off, size, hdr
            if btype in CONTAINERS:
                found = find_box(buf, path[1:], off + hdr, off + size)
                if found:
                    return found
    return None


def read_boxes(stream):
    """Yield (type, bytes) top-level boxes from a binary stream until EOF."""
    while True:
        head = _read(stream, 8)
        if not head:
            return
        if len(head) < 8:
            raise BoxError("truncated box header")
        size, btype = struct.unpack(">I4s", head)
        extra = b""
        if size == 1:
            extra = _read(stream, 8)
            if len(extra) < 8:
                raise BoxError("truncated largesize")
            size = struct.unpack(">Q", extra)[0]
            hdr = 16
        elif size == 0:
            yield btype, head + _read_all(stream)
            return
        else:
            hdr = 8
        if size < hdr:
            raise BoxError(f"bad size {size}")
        body = _read(stream, size - hdr)
        if len(body) != size - hdr:
            raise BoxError(f"truncated {btype!r}")
        yield btype, head + extra + body


def _read(stream, n):
    out = []
    got = 0
    while got < n:
        chunk = stream.read(n - got)
        if not chunk:
            break
        out.append(chunk)
        got += len(chunk)
    return b"".join(out)


def _read_all(stream):
    out = []
    while True:
        chunk = stream.read(1 << 16)
        if not chunk:
            return b"".join(out)
        out.append(chunk)


def parse_init(init):
    """Codec string from avcC and timescale from mdhd of an fMP4 init segment."""
    info = {}
    path = [b"moov", b"trak", b"mdia", b"mdhd"]
    found = find_box(init, path)
    if not found:
        raise BoxError("no mdhd")
    off, size, hdr = found
    version = init[off + hdr]
    ts_off = off + hdr + (20 if version == 1 else 12)
    info["timescale"] = struct.unpack(">I", init[ts_off:ts_off + 4])[0]
    i = init.find(b"avcC")
    if i < 0 or i + 8 > len(init):
        raise BoxError("no avcC")
    info["codec"] = "avc1.%02x%02x%02x" % (init[i + 5], init[i + 6], init[i + 7])
    return info


def moof_sample_count(moof):
    """Sum of trun sample_count over every traf in a moof box."""
    total = 0
    for btype, off, size, hdr in iter_boxes(moof):
        if btype != b"moof":
            continue
        for t2, o2, s2, h2 in iter_boxes(moof, off + hdr, off + size):
            if t2 != b"traf":
                continue
            for t3, o3, s3, h3 in iter_boxes(moof, o2 + h2, o2 + s2):
                if t3 == b"trun":
                    total += struct.unpack(">I", moof[o3 + h3 + 4:o3 + h3 + 8])[0]
    return total


class Splitter:
    """Groups top-level boxes: ftyp+moov -> ('init', bytes); moof+mdat -> ('segment', bytes, samples)."""

    def __init__(self):
        self._init = []
        self._moof = None
        self.init_done = False
        self.ignored = []

    def feed(self, btype, data):
        if not self.init_done and btype in (b"ftyp", b"moov"):
            self._init.append(data)
            if btype == b"moov":
                self.init_done = True
                return [("init", b"".join(self._init))]
            return []
        if btype == b"moof":
            self._moof = data
            return []
        if btype == b"mdat" and self._moof is not None:
            moof, self._moof = self._moof, None
            return [("segment", moof + data, moof_sample_count(moof))]
        self.ignored.append(btype)
        return []


def ffmpeg_argv(width, height, fps, segment_seconds, crf, bitrate_kbps, ffmpeg="ffmpeg"):
    gop = fps * segment_seconds
    return [
        ffmpeg, "-hide_banner", "-loglevel", "error", "-nostats",
        "-f", "rawvideo", "-pix_fmt", "yuv420p", "-video_size", f"{width}x{height}", "-framerate", str(fps),
        "-i", "pipe:0", "-an",
        "-c:v", "libx264", "-preset", "veryfast", "-profile:v", "high", "-pix_fmt", "yuv420p",
        "-crf", str(crf), "-maxrate", f"{bitrate_kbps}k", "-bufsize", f"{bitrate_kbps * 2}k",
        "-g", str(gop), "-keyint_min", str(gop), "-sc_threshold", "0",
        "-force_key_frames", f"expr:gte(t,n_forced*{segment_seconds})",
        "-video_track_timescale", "90000",
        "-f", "mp4", "-movflags", "frag_keyframe+empty_moov+default_base_moof", "pipe:1",
    ]


class SegmentAccounting:
    """Maps encoder output samples back to capture frame indexes for the REC_SEGMENT meta."""

    def __init__(self, fps):
        self.fps = fps
        self._fed = collections.deque()
        self._lock = threading.Lock()
        self.next_first = None
        self.index = 0

    def pts_us(self, frame_idx):
        return frame_idx * 1_000_000 // self.fps

    def fed(self, idx):
        with self._lock:
            self._fed.append(idx)
            if self.next_first is None:
                self.next_first = idx

    def segment_meta(self, samples, body):
        with self._lock:
            taken = [self._fed.popleft() for _ in range(min(samples, len(self._fed)))]
            first = self.next_first if self.next_first is not None else 0
            last = taken[-1] if taken else first - 1
            self.next_first = last + 1
        self.index += 1
        captured = last + 1 - first
        return {
            "segmentIndex": self.index,
            "startPtsUs": self.pts_us(first),
            "endPtsUs": self.pts_us(last + 1),
            "firstFrame": first,
            "frameCount": samples,
            "framesCaptured": captured,
            "framesDropped": max(0, captured - samples),
            "sha256": hashlib.sha256(body).hexdigest(),
        }


class Recorder:
    """`emit(ftype, payload)` delivers REC_* frames (buffered by the outbox until WELCOME)."""

    def __init__(self, width, height, fps, segment_seconds, crf, bitrate_kbps, emit, log=None, ffmpeg="ffmpeg"):
        self.width, self.height, self.fps = width, height, fps
        self.argv = ffmpeg_argv(width, height, fps, segment_seconds, crf, bitrate_kbps, ffmpeg)
        self.emit = emit
        self._log = log or (lambda *a, **k: None)
        self._q = queue.Queue(maxsize=fps * 3)
        self.acct = SegmentAccounting(fps)
        self._loss = None
        self.lost_total = 0
        self.pts_zero_unix_ms = None
        self.proc = None
        self._threads = []
        self.segments = 0
        self.failed = False

    def start(self):
        self.proc = subprocess.Popen(self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for name, fn in (("rec-writer", self._writer), ("rec-reader", self._reader), ("rec-stderr", self._stderr)):
            t = threading.Thread(target=fn, name=name, daemon=True)
            t.start()
            self._threads.append(t)
        self._log("recorder_started", argv=" ".join(self.argv[1:]))

    def offer(self, idx, pts_us, wall_ms, frame, raw_fn):
        if self.pts_zero_unix_ms is None:
            self.pts_zero_unix_ms = wall_ms - idx * 1000 // self.fps
        if not self.failed:
            try:
                self._q.put_nowait((idx, raw_fn()))
                self._flush_loss()
                return
            except queue.Full:
                pass
        if self._loss is None:
            self._loss = [idx, idx, 0]
        self._loss[1] = idx
        self._loss[2] += 1

    def _flush_loss(self):
        if self._loss is None:
            return
        first, last, n = self._loss
        self._loss = None
        self.lost_total += n
        loss = {"fromPtsUs": self.acct.pts_us(first), "toPtsUs": self.acct.pts_us(last + 1),
                "framesLost": n, "reason": "encoder_overflow"}
        self._log("recorder_loss", **loss)
        self.emit(frames.REC_LOSS, frames.json_bytes(loss))

    def _writer(self):
        stdin = self.proc.stdin
        try:
            while True:
                item = self._q.get()
                if item is None:
                    break
                idx, raw = item
                stdin.write(raw)
                self.acct.fed(idx)
        except (BrokenPipeError, OSError) as e:
            self.failed = True
            self._log("recorder_write_failed", error=type(e).__name__)
        finally:
            try:
                stdin.close()
            except OSError:
                pass

    def _reader(self):
        splitter = Splitter()
        try:
            for btype, data in read_boxes(self.proc.stdout):
                for ev in splitter.feed(btype, data):
                    if ev[0] == "init":
                        self._emit_init(ev[1])
                    else:
                        self._emit_segment(ev[1], ev[2])
        except BoxError as e:
            self.failed = True
            self._log("recorder_parse_failed", error=str(e))
        if splitter.ignored:
            self._log("recorder_boxes_ignored", types=sorted({t.decode("latin-1") for t in splitter.ignored}))

    def _emit_init(self, body):
        info = parse_init(body)
        codec = info["codec"]
        meta = {"codec": codec, "mime": f'video/mp4; codecs="{codec}"', "width": self.width, "height": self.height,
                "timescale": info["timescale"], "ptsZeroUnixMs": self.pts_zero_unix_ms}
        self._log("recorder_init", **meta)
        self.emit(frames.REC_INIT, frames.meta_payload(meta, body))

    def _emit_segment(self, body, samples):
        meta = self.acct.segment_meta(samples, body)
        self.segments += 1
        self._log("recorder_segment", bytes=len(body), **meta)
        self.emit(frames.REC_SEGMENT, frames.meta_payload(meta, body))

    def _stderr(self):
        for line in self.proc.stderr:
            self._log("recorder_ffmpeg", line=line.decode("utf-8", "replace").strip()[:300])

    def stop(self, timeout=15):
        """Close the encoder input so ffmpeg flushes the last partial fragment, then wait for it."""
        self._flush_loss_safe()
        self._q.put(None)
        for t in self._threads:
            t.join(timeout)
        if self.proc:
            try:
                self.proc.wait(timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self._log("recorder_stopped", segments=self.segments, lost=self.lost_total,
                  exit=self.proc.returncode if self.proc else None)

    def _flush_loss_safe(self):
        try:
            self._flush_loss()
        except Exception as e:
            self._log("recorder_loss_emit_failed", error=type(e).__name__)
