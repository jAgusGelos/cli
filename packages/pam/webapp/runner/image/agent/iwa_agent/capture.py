"""One x11grab capture with the watermark burned in once, converted to yuv420p, fanned out to consumers (AD-3)."""
import os
import threading
import time

FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"


def yuv420p_bytes(frame):
    """Tightly packed yuv420p bytes of a PyAV frame (strips line padding)."""
    out = []
    for plane in frame.planes:
        data = bytes(plane)
        w, h, ls = plane.width, plane.height, plane.line_size
        if ls == w:
            out.append(data[: w * h])
        else:
            out.append(b"".join(data[r * ls: r * ls + w] for r in range(h)))
    return b"".join(out)


def drawtext_args(textfile):
    return (
        f"fontfile={FONT}:textfile={textfile}:expansion=none:fontsize=18:fontcolor=white@0.55:"
        "box=1:boxcolor=black@0.35:boxborderw=6:x=w-tw-16:y=h-th-16"
    )


class Capture:
    """Consumers are callables `(index, pts_us, wall_ms, frame, raw_fn)`; raw_fn() returns yuv420p bytes (cached)."""

    def __init__(self, width, height, fps, watermark, display=":99", run_dir="/tmp/iwa", log=None):
        self.width, self.height, self.fps = width, height, fps
        self.watermark = watermark or ""
        self.display = display
        self.run_dir = run_dir
        self._log = log or (lambda *a, **k: None)
        self._consumers = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self.frames = 0
        self.error = None
        self.t0_ns = None

    def add_consumer(self, fn):
        with self._lock:
            self._consumers.append(fn)

    def remove_consumer(self, fn):
        with self._lock:
            if fn in self._consumers:
                self._consumers.remove(fn)

    def start(self):
        self._thread = threading.Thread(target=self._run, name="capture", daemon=True)
        self._thread.start()

    def stop(self, timeout=5):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout)

    def _graph(self, av, stream):
        graph = av.filter.Graph()
        src = graph.add_buffer(template=stream)
        last = src
        if self.watermark:
            os.makedirs(self.run_dir, exist_ok=True)
            path = os.path.join(self.run_dir, "watermark.txt")
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.watermark)
            node = graph.add("drawtext", drawtext_args(path))
            last.link_to(node)
            last = node
        fmt = graph.add("format", "pix_fmts=yuv420p")
        last.link_to(fmt)
        sink = graph.add("buffersink")
        fmt.link_to(sink)
        graph.configure()
        return graph, src, sink

    def _run(self):
        import av
        container = None
        try:
            container = av.open(
                f"{self.display}.0",
                format="x11grab",
                options={"framerate": str(self.fps), "video_size": f"{self.width}x{self.height}", "draw_mouse": "1"},
            )
            stream = container.streams.video[0]
            graph, src, sink = self._graph(av, stream)
            self._log("capture_started", width=self.width, height=self.height, fps=self.fps)
            for raw in container.decode(stream):
                if self._stop.is_set():
                    break
                now_ns = time.monotonic_ns()
                if self.t0_ns is None:
                    self.t0_ns = now_ns
                pts_us = (now_ns - self.t0_ns) // 1000
                wall_ms = int(time.time() * 1000)
                src.push(raw)
                frame = sink.pull()
                idx = self.frames
                self.frames += 1
                cache = []

                def raw_fn(frame=frame, cache=cache):
                    if not cache:
                        cache.append(yuv420p_bytes(frame))
                    return cache[0]

                with self._lock:
                    consumers = list(self._consumers)
                for fn in consumers:
                    try:
                        fn(idx, pts_us, wall_ms, frame, raw_fn)
                    except Exception as e:  # a consumer must never stop the capture
                        self._log("capture_consumer_error", error=f"{type(e).__name__}: {e}"[:200])
        except Exception as e:
            self.error = e
            self._log("capture_failed", error=f"{type(e).__name__}: {e}"[:300])
        finally:
            if container is not None:
                container.close()
            self._log("capture_stopped", frames=self.frames)
