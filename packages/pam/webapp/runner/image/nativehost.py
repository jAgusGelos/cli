#!/usr/bin/env python3
"""Chrome native-messaging bridge backed by the agent's local Unix socket."""
import json, os, socket, struct, sys, threading

SOCKET = "/tmp/iwa/native.sock"

def read_message(stream):
    header = stream.read(4)
    if len(header) != 4: return None
    size = struct.unpack("<I", header)[0]
    if size > 4 * 1024 * 1024: raise ValueError("native message too large")
    data = stream.read(size)
    if len(data) != size: return None
    return json.loads(data.decode())

def write_message(stream, value):
    data = json.dumps(value, separators=(",", ":")).encode()
    stream.write(struct.pack("<I", len(data)) + data); stream.flush()

def main():
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.connect(SOCKET)
        stop = threading.Event()
        def forward_to_agent():
            try:
                while not stop.is_set():
                    message = read_message(sys.stdin.buffer)
                    if message is None: break
                    data = json.dumps(message, separators=(",", ":")).encode()
                    sock.sendall(struct.pack("<I", len(data)) + data)
            finally: stop.set()
        def forward_to_chrome():
            try:
                while not stop.is_set():
                    message = read_message(sock)
                    if message is None: break
                    write_message(sys.stdout.buffer, message)
            finally: stop.set()
        threads = [threading.Thread(target=forward_to_agent, daemon=True), threading.Thread(target=forward_to_chrome, daemon=True)]
        for thread in threads: thread.start()
        threads[0].join()
        stop.set()
        try: sock.shutdown(socket.SHUT_RDWR)
        except OSError: pass
        return 0

if __name__ == "__main__": raise SystemExit(main())
