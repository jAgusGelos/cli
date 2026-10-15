"""Stream frame codec (CONTRACTS section 1). Stdlib only so it runs on the host python3."""
import json
import struct
from dataclasses import dataclass

VERSION = 1
HEADER = struct.Struct(">BBHIQI")
HEADER_SIZE = HEADER.size
MAX_AGENT_PAYLOAD = 32 * 1024 * 1024

VIDEO_CONFIG = 0x01
VIDEO_CHUNK = 0x02
CONTROL = 0x03
CLIPBOARD_DOWN = 0x04
HELLO = 0x20
INPUT = 0x21
ACK = 0x22
KEYFRAME_REQUEST = 0x23
CONTROL_UP = 0x24
CLIPBOARD_UP = 0x25
AGENT_HELLO = 0x80
AGENT_WELCOME = 0x81
REC_INIT = 0x82
REC_SEGMENT = 0x83
REC_LOSS = 0x84
INPUT_INJECT = 0x85
AGENT_CONTROL = 0x86
AGENT_EVENT = 0x87
EXT_COMMAND = 0x88

FLAG_KEYFRAME = 0x0001
FLAG_ORIGIN_BACKEND = 0x0001

U32 = 1 << 32


class FrameError(Exception):
    """Protocol error; `code` follows CONTRACTS error codes."""

    def __init__(self, code, message=""):
        super().__init__(f"{code}: {message}" if message else code)
        self.code = code


@dataclass(frozen=True)
class Frame:
    type: int
    flags: int
    seq: int
    timestamp_us: int
    payload: bytes

    def json(self):
        return json.loads(self.payload.decode("utf-8"))


def encode(ftype, flags, seq, timestamp_us, payload=b"", limit=MAX_AGENT_PAYLOAD):
    if len(payload) > limit:
        raise FrameError("frame_too_large", f"{len(payload)} > {limit}")
    return HEADER.pack(VERSION, ftype, flags, seq % U32, timestamp_us, len(payload)) + payload


def parse_header(header, limit=MAX_AGENT_PAYLOAD):
    version, ftype, flags, seq, ts, length = HEADER.unpack(header)
    if version != VERSION:
        raise FrameError("protocol_error", f"version {version}")
    if length > limit:
        raise FrameError("frame_too_large", f"{length} > {limit}")
    return ftype, flags, seq, ts, length


def decode(buf, limit=MAX_AGENT_PAYLOAD):
    """Decode exactly one frame from `buf`."""
    if len(buf) < HEADER_SIZE:
        raise FrameError("protocol_error", "short header")
    ftype, flags, seq, ts, length = parse_header(buf[:HEADER_SIZE], limit)
    if len(buf) != HEADER_SIZE + length:
        raise FrameError("protocol_error", "length mismatch")
    return Frame(ftype, flags, seq, ts, bytes(buf[HEADER_SIZE:]))


def _read_exact(reader, n):
    chunks = []
    remaining = n
    while remaining:
        chunk = reader.read(remaining)
        if not chunk:
            return None if remaining == n else b""
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_frame(reader, limit=MAX_AGENT_PAYLOAD):
    """Read one frame from a binary file-like object. Returns None on clean EOF at a frame boundary."""
    header = _read_exact(reader, HEADER_SIZE)
    if header is None:
        return None
    if len(header) != HEADER_SIZE:
        raise FrameError("protocol_error", "truncated header")
    ftype, flags, seq, ts, length = parse_header(header, limit)
    payload = _read_exact(reader, length) if length else b""
    if payload is None or len(payload) != length:
        raise FrameError("protocol_error", "truncated payload")
    return Frame(ftype, flags, seq, ts, payload)


def json_bytes(obj):
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


def meta_payload(meta, body):
    """Meta-prefixed payload (CONTRACTS 1.10): metaLen u32 + meta JSON + body."""
    m = json_bytes(meta)
    return struct.pack(">I", len(m)) + m + body


def split_meta(payload):
    if len(payload) < 4:
        raise FrameError("protocol_error", "short meta prefix")
    (n,) = struct.unpack(">I", payload[:4])
    if 4 + n > len(payload):
        raise FrameError("protocol_error", "metaLen exceeds payload")
    return json.loads(payload[4:4 + n].decode("utf-8")), payload[4 + n:]
