#!/usr/bin/env python3
"""Chrome native-messaging bridge backed by the agent's local Unix socket."""
import json, os, socket, struct, sys

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
        reader = sock.makefile("rwb", buffering=0)
        hello = read_message(sys.stdin.buffer)
        if hello is not None:
            write_message(reader, hello)
        while True:
            message = read_message(sys.stdin.buffer)
            if message is None: return 0
            reader.write(struct.pack("<I", len(json.dumps(message).encode())) + json.dumps(message, separators=(",", ":")).encode()); reader.flush()
            response = read_message(reader)
            if response is None: return 0
            write_message(sys.stdout.buffer, response)

if __name__ == "__main__": raise SystemExit(main())
