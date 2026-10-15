// Package contract implements the INF-WEBAPP wire and data contracts (CONTRACTS.md v1): stream frames, the D-06 event
// envelope and hash chain, session key certificates, signed checkpoints, chunk encryption and the gateway input filter.
package contract

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	FrameVersion    = 1
	FrameHeaderSize = 20

	MaxUpstreamPayload   = 61440            // viewer -> gateway
	MaxDownstreamPayload = 4 * 1024 * 1024  // gateway -> viewer
	MaxAgentPayload      = 32 * 1024 * 1024 // runner agent <-> gateway
)

type FrameType uint8

const (
	FrameVideoConfig     FrameType = 0x01
	FrameVideoChunk      FrameType = 0x02
	FrameControl         FrameType = 0x03
	FrameClipboardDown   FrameType = 0x04
	FrameHello           FrameType = 0x20
	FrameInput           FrameType = 0x21
	FrameAck             FrameType = 0x22
	FrameKeyframeRequest FrameType = 0x23
	FrameControlUp       FrameType = 0x24
	FrameClipboardUp     FrameType = 0x25
	FrameAgentHello      FrameType = 0x80
	FrameAgentWelcome    FrameType = 0x81
	FrameRecInit         FrameType = 0x82
	FrameRecSegment      FrameType = 0x83
	FrameRecLoss         FrameType = 0x84
	FrameInputInject     FrameType = 0x85
	FrameAgentControl    FrameType = 0x86
	FrameAgentEvent      FrameType = 0x87
	FrameExtCommand      FrameType = 0x88
)

const (
	FlagKeyframe      uint16 = 1 << 0 // VIDEO_CHUNK
	FlagOriginBackend uint16 = 1 << 0 // CONTROL
)

// IsDownstream reports whether t may travel gateway -> viewer.
func (t FrameType) IsDownstream() bool { return t >= 0x01 && t <= 0x1F }

// IsUpstream reports whether t may travel viewer -> gateway.
func (t FrameType) IsUpstream() bool { return t >= 0x20 && t <= 0x3F }

// IsAgentOnly reports whether t is confined to the runner agent <-> gateway link.
func (t FrameType) IsAgentOnly() bool { return t >= 0x80 && t <= 0x9F }

var (
	ErrBadVersion    = errors.New("contract: unsupported frame version")
	ErrFrameTooLarge = errors.New("contract: frame too large")
	ErrShortFrame    = errors.New("contract: short frame")
)

type Frame struct {
	Type        FrameType
	Flags       uint16
	Seq         uint32
	TimestampUs uint64
	Payload     []byte
}

// Marshal encodes the frame: 20-byte big-endian header followed by the payload.
func (f *Frame) Marshal() []byte {
	out := make([]byte, FrameHeaderSize+len(f.Payload))
	out[0] = FrameVersion
	out[1] = byte(f.Type)
	binary.BigEndian.PutUint16(out[2:4], f.Flags)
	binary.BigEndian.PutUint32(out[4:8], f.Seq)
	binary.BigEndian.PutUint64(out[8:16], f.TimestampUs)
	binary.BigEndian.PutUint32(out[16:20], uint32(len(f.Payload)))
	copy(out[FrameHeaderSize:], f.Payload)
	return out
}

func parseHeader(h []byte, maxPayload int) (Frame, uint32, error) {
	if h[0] != FrameVersion {
		return Frame{}, 0, ErrBadVersion
	}
	length := binary.BigEndian.Uint32(h[16:20])
	if int64(length) > int64(maxPayload) {
		return Frame{}, 0, ErrFrameTooLarge
	}
	return Frame{
		Type:        FrameType(h[1]),
		Flags:       binary.BigEndian.Uint16(h[2:4]),
		Seq:         binary.BigEndian.Uint32(h[4:8]),
		TimestampUs: binary.BigEndian.Uint64(h[8:16]),
	}, length, nil
}

// UnmarshalFrame decodes exactly one frame (one WebSocket message). The buffer length must equal header + length.
func UnmarshalFrame(b []byte, maxPayload int) (*Frame, error) {
	if len(b) < FrameHeaderSize {
		return nil, ErrShortFrame
	}
	f, length, err := parseHeader(b[:FrameHeaderSize], maxPayload)
	if err != nil {
		return nil, err
	}
	if len(b) != FrameHeaderSize+int(length) {
		return nil, fmt.Errorf("contract: frame length %d does not match buffer %d", length, len(b)-FrameHeaderSize)
	}
	f.Payload = append([]byte(nil), b[FrameHeaderSize:]...)
	return &f, nil
}

// ReadFrame reads one frame from a byte stream (TCP tunnel or agent link).
func ReadFrame(r io.Reader, maxPayload int) (*Frame, error) {
	var h [FrameHeaderSize]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	f, length, err := parseHeader(h[:], maxPayload)
	if err != nil {
		return nil, err
	}
	f.Payload = make([]byte, length)
	if _, err := io.ReadFull(r, f.Payload); err != nil {
		return nil, err
	}
	return &f, nil
}

// WriteFrame writes one frame to a byte stream.
func WriteFrame(w io.Writer, f *Frame) error {
	_, err := w.Write(f.Marshal())
	return err
}

// Ack is the binary ACK payload (8 bytes).
type Ack struct {
	AckSeq      uint32
	DecodeQueue uint16
}

func (a Ack) Marshal() []byte {
	out := make([]byte, 8)
	binary.BigEndian.PutUint32(out[0:4], a.AckSeq)
	binary.BigEndian.PutUint16(out[4:6], a.DecodeQueue)
	return out
}

func UnmarshalAck(b []byte) (Ack, error) {
	if len(b) != 8 {
		return Ack{}, fmt.Errorf("contract: ack payload must be 8 bytes, got %d", len(b))
	}
	return Ack{AckSeq: binary.BigEndian.Uint32(b[0:4]), DecodeQueue: binary.BigEndian.Uint16(b[4:6])}, nil
}

// MarshalMetaPrefixed builds a REC_INIT / REC_SEGMENT payload: u32 metaLen, JSON meta, body.
func MarshalMetaPrefixed(meta any, body []byte) ([]byte, error) {
	m, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 4+len(m)+len(body))
	binary.BigEndian.PutUint32(out[0:4], uint32(len(m)))
	copy(out[4:], m)
	copy(out[4+len(m):], body)
	return out, nil
}

// UnmarshalMetaPrefixed splits a meta-prefixed payload and decodes the meta JSON into meta.
func UnmarshalMetaPrefixed(payload []byte, meta any) ([]byte, error) {
	if len(payload) < 4 {
		return nil, ErrShortFrame
	}
	n := binary.BigEndian.Uint32(payload[0:4])
	if uint64(n) > uint64(len(payload)-4) {
		return nil, fmt.Errorf("contract: meta length %d exceeds payload", n)
	}
	if err := json.Unmarshal(payload[4:4+n], meta); err != nil {
		return nil, err
	}
	return payload[4+n:], nil
}
