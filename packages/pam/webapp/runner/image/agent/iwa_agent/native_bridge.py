"""Small Unix-socket bridge for Chrome native messaging."""
import json, os, socket, struct, threading

SOCKET = "/tmp/iwa/native.sock"

def _read(stream):
    h = stream.recv(4)
    if len(h) != 4: return None
    n = struct.unpack("<I", h)[0]
    if n > 4 * 1024 * 1024: return None
    data = b""
    while len(data) < n:
        part = stream.recv(n - len(data))
        if not part: return None
        data += part
    return json.loads(data.decode())

def _write(stream, value):
    data = json.dumps(value, separators=(",", ":")).encode()
    stream.sendall(struct.pack("<I", len(data)) + data)

class NativeBridge:
    def __init__(self, on_message, log):
        self.on_message, self.log = on_message, log
        self._out = []
        self._lock = threading.Lock()
        self._ready = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        os.makedirs(os.path.dirname(SOCKET), exist_ok=True)
        try: os.unlink(SOCKET)
        except FileNotFoundError: pass
        self._thread.start()

    def send(self, message):
        with self._lock: self._out.append(message)

    @property
    def ready(self): return self._ready.is_set()

    def stop(self):
        self._stop.set()
        try: os.unlink(SOCKET)
        except FileNotFoundError: pass

    def _serve(self):
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(SOCKET); os.chmod(SOCKET, 0o600); server.listen(1); server.settimeout(0.5)
        try:
            while not self._stop.is_set():
                try: conn, _ = server.accept()
                except socket.timeout: continue
                conn.settimeout(0.2); self._ready.set()
                try:
                    while not self._stop.is_set():
                        with self._lock: pending = self._out[:]; self._out.clear()
                        for message in pending: _write(conn, message)
                        try: message = _read(conn)
                        except socket.timeout: message = False
                        if message is None: break
                        if message is not False: self.on_message(message)
                finally: conn.close(); self._ready.clear()
        finally: server.close()
