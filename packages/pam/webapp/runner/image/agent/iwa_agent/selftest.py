"""In-image encoder self tests against the running Xvfb :99.
Usage: python3 -m iwa_agent.selftest live|live-vp9|recorder [outdir]"""
import json
import os
import struct
import subprocess
import sys
import threading
import time

from . import frames
from .capture import Capture
from .live import VP9_CODEC, LiveEncoder, VP9LiveEncoder, nal_types
from .recorder import Recorder

W, H, FPS = 1280, 720, 30
FORCE_AT = 45


def log(event, **fields):
    sys.stderr.write(json.dumps({"event": event, **fields}) + "\n")


def ffprobe_frames(path):
    out = subprocess.run(
        ["ffprobe", "-v", "error", "-select_streams", "v:0", "-show_entries",
         "frame=pict_type,key_frame,width,height,pts_time", "-of", "json", path],
        capture_output=True, check=True, text=True).stdout
    return json.loads(out).get("frames", [])


def headers_before_idr(types):
    return 5 in types and 7 in types and 8 in types and max(types.index(7), types.index(8)) < types.index(5)


def _run_live(encoder_cls, watermark, epoch):
    chunks = []
    done = threading.Event()

    def emit(ftype, payload, flags, ts):
        chunks.append((ftype, payload, flags, ts))
        if sum(1 for c in chunks if c[0] == frames.VIDEO_CHUNK) >= 3 * FPS:
            done.set()

    cap = Capture(W, H, FPS, watermark, log=log)
    live = encoder_cls(W, H, FPS, emit, epoch=epoch, log=log)
    seen = [0]

    def offer(idx, pts, wall, frame, raw_fn):
        seen[0] += 1
        if seen[0] == FORCE_AT + 1:
            live.request_keyframe()
        live.offer(idx, pts, wall, frame, raw_fn)

    started = time.monotonic()
    live.start()
    cap.add_consumer(offer)
    cap.start()
    done.wait(15)
    elapsed = time.monotonic() - started
    cap.stop()
    live.stop()
    vchunks = [c for c in chunks if c[0] == frames.VIDEO_CHUNK]
    config = json.loads(chunks[0][1]) if chunks and chunks[0][0] == frames.VIDEO_CONFIG else None
    return vchunks, config, elapsed


def _keyframe_fields(probe, vchunks):
    return {
        "ffprobeFrames": len(probe),
        "size": f"{probe[0]['width']}x{probe[0]['height']}" if probe else None,
        "firstPictType": probe[0]["pict_type"] if probe else None,
        "keyframeIndexes": [i for i, fr in enumerate(probe) if fr.get("key_frame") == 1],
        "keyframeFlagIndexes": [i for i, c in enumerate(vchunks) if c[2] & frames.FLAG_KEYFRAME],
        "forcedRequestedAtFrame": FORCE_AT,
    }


def _forced_keyframe_ok(key_idx):
    return any(FORCE_AT <= k <= FORCE_AT + 2 for k in key_idx)


def _monotonic(vchunks):
    return all(vchunks[i][3] < vchunks[i + 1][3] for i in range(len(vchunks) - 1))


def live_test(outdir):
    vchunks, config, _ = _run_live(LiveEncoder, "selftest live watermark", epoch=1)
    path = os.path.join(outdir, "selftest-live.h264")
    with open(path, "wb") as f:
        for c in vchunks:
            f.write(c[1])
    probe = ffprobe_frames(path)
    headers_ok = all(headers_before_idr(nal_types(c[1])) for c in vchunks if c[2] & frames.FLAG_KEYFRAME)
    result = {
        "test": "live", "file": path, "bytes": os.path.getsize(path), "chunks": len(vchunks),
        "videoConfig": config, **_keyframe_fields(probe, vchunks),
        "spsPpsBeforeEveryIdr": headers_ok, "startsWithStartCode": bool(vchunks) and vchunks[0][1][:4] == b"\0\0\0\1",
        "monotonicTimestamps": _monotonic(vchunks),
    }
    key_idx = result["keyframeIndexes"]
    result["ok"] = bool(probe) and result["size"] == f"{W}x{H}" and result["firstPictType"] == "I" \
        and key_idx[:1] == [0] and _forced_keyframe_ok(key_idx) and headers_ok and result["startsWithStartCode"]
    return result


def write_ivf(path, payloads, fps):
    """Minimal IVF container (VP90) so ffprobe can decode raw VP9 frames."""
    with open(path, "wb") as f:
        f.write(b"DKIF" + struct.pack("<HH4sHHIIII", 0, 32, b"VP90", W, H, fps, 1, len(payloads), 0))
        for n, data in enumerate(payloads):
            f.write(struct.pack("<IQ", len(data), n) + data)


def live_vp9_test(outdir):
    vchunks, config, elapsed = _run_live(VP9LiveEncoder, "selftest vp9 watermark", epoch=2)
    path = os.path.join(outdir, "selftest-live.ivf")
    write_ivf(path, [c[1] for c in vchunks], FPS)
    probe = ffprobe_frames(path)
    codec = subprocess.run(["ffprobe", "-v", "error", "-select_streams", "v:0", "-show_entries",
                            "stream=codec_name,profile,pix_fmt", "-of", "json", path],
                           capture_output=True, text=True).stdout
    result = {
        "test": "live-vp9", "file": path, "bytes": os.path.getsize(path), "chunks": len(vchunks),
        "videoConfig": config, "stream": json.loads(codec or "{}").get("streams"),
        **_keyframe_fields(probe, vchunks),
        "kbpsMeasured": round(sum(len(c[1]) for c in vchunks) * 8 / 1000 / max(elapsed, 0.001)),
        "monotonicTimestamps": _monotonic(vchunks),
    }
    key_idx = result["keyframeIndexes"]
    result["ok"] = bool(probe) and len(probe) == len(vchunks) and result["size"] == f"{W}x{H}" \
        and key_idx[:1] == [0] and result["keyframeFlagIndexes"] == key_idx and _forced_keyframe_ok(key_idx) \
        and config is not None and config.get("codec") == VP9_CODEC and "format" not in config
    return result


def recorder_test(outdir, seconds=21):
    out = []
    rec = Recorder(W, H, FPS, 10, 26, 1500, emit=lambda t, p: out.append((t, p)), log=log)
    cap = Capture(W, H, FPS, "selftest recorder watermark", log=log)
    rec.start()
    cap.add_consumer(rec.offer)
    cap.start()
    time.sleep(seconds)
    cap.stop()
    rec.stop()
    init = None
    segs = []
    for t, p in out:
        meta, body = frames.split_meta(p) if t in (frames.REC_INIT, frames.REC_SEGMENT) else (json.loads(p), b"")
        if t == frames.REC_INIT:
            init = (meta, body)
            with open(os.path.join(outdir, "init.mp4"), "wb") as f:
                f.write(body)
        elif t == frames.REC_SEGMENT:
            segs.append((meta, body))
    results = []
    for meta, body in segs:
        path = os.path.join(outdir, "seg%03d.mp4" % meta["segmentIndex"])
        with open(path, "wb") as f:
            f.write(init[1] + body)
        probe = ffprobe_frames(path)
        dur = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", path],
                             capture_output=True, text=True).stdout.strip()
        results.append({"meta": meta, "file": path, "ffprobeFrames": len(probe), "durationS": dur,
                        "firstPictType": probe[0]["pict_type"] if probe else None,
                        "firstKey": probe[0]["key_frame"] if probe else None,
                        "keyframes": sum(1 for fr in probe if fr.get("key_frame") == 1)})
    full = [r for r in results if r["meta"]["frameCount"] == 10 * FPS]
    ok = init is not None and len(full) >= 2 and all(r["firstPictType"] == "I" and r["ffprobeFrames"] ==
                                                     r["meta"]["frameCount"] for r in results)
    return {"test": "recorder", "seconds": seconds, "init": init[0] if init else None, "segments": results,
            "recLoss": [json.loads(p) for t, p in out if t == frames.REC_LOSS], "ok": ok}


def main(argv):
    tests = {"live": live_test, "live-vp9": live_vp9_test, "recorder": recorder_test}
    if not argv or argv[0] not in tests:
        print(__doc__, file=sys.stderr)
        return 2
    outdir = argv[1] if len(argv) > 1 else "/tmp/iwa/selftest"
    os.makedirs(outdir, exist_ok=True)
    result = tests[argv[0]](outdir)
    print(json.dumps(result, indent=1))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
