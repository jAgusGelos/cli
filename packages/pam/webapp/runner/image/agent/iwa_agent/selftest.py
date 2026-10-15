"""In-image encoder self tests against the running Xvfb :99. Usage: python3 -m iwa_agent.selftest live|recorder [outdir]"""
import json
import os
import subprocess
import sys
import threading
import time

from . import frames
from .capture import Capture
from .live import LiveEncoder, nal_types
from .recorder import Recorder

W, H, FPS = 1280, 720, 30


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


def live_test(outdir):
    chunks = []
    done = threading.Event()
    force_at = 45

    def emit(ftype, payload, flags, ts):
        chunks.append((ftype, payload, flags, ts))
        if sum(1 for c in chunks if c[0] == frames.VIDEO_CHUNK) >= 3 * FPS:
            done.set()

    cap = Capture(W, H, FPS, "selftest live watermark", log=log)
    live = LiveEncoder(W, H, FPS, emit, epoch=1, log=log)
    seen = [0]

    def offer(idx, pts, wall, frame, raw_fn):
        seen[0] += 1
        if seen[0] == force_at + 1:
            live.request_keyframe()
        live.offer(idx, pts, wall, frame, raw_fn)

    live.start()
    cap.add_consumer(offer)
    cap.start()
    done.wait(15)
    cap.stop()
    live.stop()
    path = os.path.join(outdir, "selftest-live.h264")
    vchunks = [c for c in chunks if c[0] == frames.VIDEO_CHUNK]
    with open(path, "wb") as f:
        for c in vchunks:
            f.write(c[1])
    probe = ffprobe_frames(path)
    key_idx = [i for i, fr in enumerate(probe) if fr.get("key_frame") == 1]
    headers_ok = all(headers_before_idr(nal_types(c[1])) for c in vchunks if c[2] & frames.FLAG_KEYFRAME)
    flagged = [i for i, c in enumerate(vchunks) if c[2] & frames.FLAG_KEYFRAME]
    config = json.loads(chunks[0][1]) if chunks and chunks[0][0] == frames.VIDEO_CONFIG else None
    result = {
        "test": "live", "file": path, "bytes": os.path.getsize(path), "chunks": len(vchunks),
        "videoConfig": config, "ffprobeFrames": len(probe),
        "size": f"{probe[0]['width']}x{probe[0]['height']}" if probe else None,
        "firstPictType": probe[0]["pict_type"] if probe else None,
        "keyframeIndexes": key_idx, "keyframeFlagIndexes": flagged, "forcedRequestedAtFrame": force_at,
        "spsPpsBeforeEveryIdr": headers_ok, "startsWithStartCode": bool(vchunks) and vchunks[0][1][:4] == b"\0\0\0\1",
        "monotonicTimestamps": all(vchunks[i][3] < vchunks[i + 1][3] for i in range(len(vchunks) - 1)),
    }
    forced_ok = any(force_at <= k <= force_at + 2 for k in key_idx)
    result["ok"] = bool(probe) and result["size"] == f"{W}x{H}" and result["firstPictType"] == "I" \
        and key_idx[:1] == [0] and forced_ok and headers_ok and result["startsWithStartCode"]
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
    if not argv or argv[0] not in ("live", "recorder"):
        print(__doc__, file=sys.stderr)
        return 2
    outdir = argv[1] if len(argv) > 1 else "/tmp/iwa/selftest"
    os.makedirs(outdir, exist_ok=True)
    result = live_test(outdir) if argv[0] == "live" else recorder_test(outdir)
    print(json.dumps(result, indent=1))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
