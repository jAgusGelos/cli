"""Live encoders (AD-3): H.264 (libx264 constrained baseline, Annex B, SPS/PPS before every IDR) and VP9
(libvpx-vp9 realtime), both with on-demand keyframes. PyAV is imported only inside the encoder thread."""
import queue
import threading
from fractions import Fraction

from . import frames

LIVE_QUEUE = 8
GOP = 300
DEFAULT_CODEC = "avc1.42E01F"
VP9_CODEC = "vp09.00.10.08"
CODECS = ("vp9", "h264")


def annexb_nals(data):
    """Split an Annex B byte string into NAL units (start codes removed)."""
    out = []
    i, n = 0, len(data)
    starts = []
    while i + 3 <= n:
        if data[i] == 0 and data[i + 1] == 0 and data[i + 2] == 1:
            starts.append(i + 3)
            i += 3
        else:
            i += 1
    for k, s in enumerate(starts):
        e = starts[k + 1] - 3 if k + 1 < len(starts) else n
        while e > s and data[e - 1] == 0:
            e -= 1
        out.append(data[s:e])
    return out


def nal_types(data):
    return [nal[0] & 0x1F for nal in annexb_nals(data) if nal]


def codec_from_sps(sps):
    """WebCodecs codec string from an SPS NAL (profile_idc, constraint flags, level_idc)."""
    return "avc1.%02X%02X%02X" % (sps[1], sps[2], sps[3])


def codec_from_annexb(data):
    for nal in annexb_nals(data):
        if nal and nal[0] & 0x1F == 7 and len(nal) >= 4:
            return codec_from_sps(nal)
    return None


class _LiveBase:
    """`emit(ftype, payload, flags, timestamp_us)` sends a frame on the agent link."""

    name = None

    def __init__(self, width, height, fps, emit, epoch, bitrate_kbps=2500, log=None):
        self.width, self.height, self.fps = width, height, fps
        self.emit = emit
        self.epoch = epoch
        self.bitrate_kbps = bitrate_kbps
        self._log = log or (lambda *a, **k: None)
        self._q = queue.Queue(maxsize=LIVE_QUEUE)
        self._force = threading.Event()
        self._stop = threading.Event()
        self._thread = None
        self.dropped = 0
        self.sent = 0
        self.keyframes = 0
        self.codec = None

    def request_keyframe(self):
        self._force.set()

    def offer(self, idx, pts_us, wall_ms, frame, raw_fn):
        try:
            self._q.put_nowait((idx, pts_us, frame))
        except queue.Full:
            drained = 0
            while True:
                try:
                    self._q.get_nowait()
                    drained += 1
                except queue.Empty:
                    break
            self.dropped += drained + 1
            self._force.set()
            self._log("live_overflow", dropped=drained + 1, total_dropped=self.dropped)

    def start(self):
        self._thread = threading.Thread(target=self._run, name="live", daemon=True)
        self._thread.start()

    def stop(self, timeout=3):
        self._stop.set()
        try:
            self._q.put_nowait(None)
        except queue.Full:
            pass
        if self._thread:
            self._thread.join(timeout)

    def _encoder(self, av):
        raise NotImplementedError

    def _config(self, data):
        raise NotImplementedError

    def _run(self):
        import av
        I = av.video.frame.PictureType.I
        NONE = av.video.frame.PictureType.NONE
        pts_by_n = {}
        n = 0
        config_sent = False
        self._force.set()
        try:
            enc = self._encoder(av)
            self._log("live_started", codec=self.name, epoch=self.epoch, bitrateKbps=self.bitrate_kbps)
            while not self._stop.is_set():
                item = self._q.get()
                if item is None:
                    break
                idx, pts_us, frame = item
                forced = self._force.is_set()
                if forced:
                    self._force.clear()
                frame.pict_type = I if forced else NONE
                frame.pts = n
                frame.time_base = enc.time_base
                pts_by_n[n] = pts_us
                n += 1
                for pkt in enc.encode(frame):
                    data = bytes(pkt)
                    ts = pts_by_n.pop(pkt.pts, pts_us) if pkt.pts is not None else pts_us
                    key = bool(pkt.is_keyframe)
                    if not config_sent:
                        if not key:
                            continue
                        cfg = self._config(data)
                        self.emit(frames.VIDEO_CONFIG, frames.json_bytes(cfg), 0, ts)
                        config_sent = True
                        self._log("live_config", **cfg)
                    if key:
                        self.keyframes += 1
                    self.emit(frames.VIDEO_CHUNK, data, frames.FLAG_KEYFRAME if key else 0, ts)
                    self.sent += 1
                if len(pts_by_n) > 4 * GOP:
                    pts_by_n.clear()
        except Exception as e:
            self._log("live_failed", codec=self.name, error=f"{type(e).__name__}: {e}"[:300])
        finally:
            self._log("live_stopped", codec=self.name, epoch=self.epoch, sent=self.sent, dropped=self.dropped,
                      keyframes=self.keyframes)


class LiveEncoder(_LiveBase):
    """H.264 live encoder."""

    name = "h264"

    def _encoder(self, av):
        enc = av.CodecContext.create("libx264", "w")
        enc.width, enc.height, enc.pix_fmt = self.width, self.height, "yuv420p"
        enc.time_base = Fraction(1, self.fps)
        enc.framerate = Fraction(self.fps, 1)
        enc.gop_size = GOP
        enc.bit_rate = self.bitrate_kbps * 1000
        enc.options = {
            "preset": "veryfast",
            "tune": "zerolatency",
            "profile": "baseline",
            "level": "3.1",
            "forced-idr": "1",
            "sc_threshold": "0",
            "maxrate": f"{self.bitrate_kbps}k",
            "bufsize": f"{self.bitrate_kbps}k",
            "x264-params": "repeat-headers=1:annexb=1",
        }
        enc.open()
        return enc

    def _config(self, data):
        # CONTRACTS 1.6: the exact WebCodecs string, derived from the SPS x264 actually emits.
        self.codec = codec_from_annexb(data) or DEFAULT_CODEC
        return {"codec": self.codec, "format": "annexb", "width": self.width, "height": self.height,
                "framerate": self.fps, "epoch": self.epoch}


class VP9LiveEncoder(_LiveBase):
    """VP9 live encoder: profile 0, 8 bit 4:2:0, one VIDEO_CHUNK per frame (lag 0, no alt-ref)."""

    name = "vp9"

    def _encoder(self, av):
        enc = av.CodecContext.create("libvpx-vp9", "w")
        enc.width, enc.height, enc.pix_fmt = self.width, self.height, "yuv420p"
        enc.time_base = Fraction(1, self.fps)
        enc.framerate = Fraction(self.fps, 1)
        enc.gop_size = GOP
        enc.bit_rate = self.bitrate_kbps * 1000
        enc.options = {
            "deadline": "realtime",
            "cpu-used": "8",
            "row-mt": "1",
            "lag-in-frames": "0",
            "error-resilient": "1",
            "auto-alt-ref": "0",
            "tile-columns": "2",
            "static-thresh": "0",
            "maxrate": f"{self.bitrate_kbps}k",
            "minrate": f"{self.bitrate_kbps // 4}k",
            "bufsize": f"{self.bitrate_kbps}k",
        }
        enc.open()
        return enc

    def _config(self, data):
        self.codec = VP9_CODEC
        return {"codec": self.codec, "width": self.width, "height": self.height, "framerate": self.fps,
                "epoch": self.epoch}


def encoder_class(codec):
    """Live encoder class for a `live_start.codec` value, or None."""
    return {"h264": LiveEncoder, "vp9": VP9LiveEncoder}.get(codec)
