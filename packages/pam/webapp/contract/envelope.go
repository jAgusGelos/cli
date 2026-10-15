package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// D-06 event envelope v1 (CONTRACTS.md 6.1, 6.2).

const (
	EnvelopeHeaderSize = 68
	MaxEnvelopeBody    = 8 * 1024 * 1024
	AlgV1              = 1

	domainEvent      = "infisical-webapp/event/v1"
	domainKeyCert    = "infisical-webapp/key-cert/v1"
	domainCheckpoint = "infisical-webapp/checkpoint/v1"
	domainAAD        = "infisical-webapp/aad/v1"
	domainKeyCommit  = "infisical-webapp/key-commit/v1"
)

var envelopeMagic = [4]byte{'I', 'W', 'E', '1'}

type EventType uint16

const (
	EventSessionOpen       EventType = 0x0001
	EventHeartbeat         EventType = 0x0002
	EventSessionEnd        EventType = 0x0003
	EventLoss              EventType = 0x0004
	EventContinuityUnknown EventType = 0x0005
	EventViewerDegraded    EventType = 0x0006
	EventLiveCodec         EventType = 0x0007
	EventVInit             EventType = 0x0100
	EventVSegment          EventType = 0x0101
	EventL1Request         EventType = 0x0200
	EventL1Response        EventType = 0x0201
	EventL1WsFrame         EventType = 0x0202
	EventL1Blocked         EventType = 0x0203
	EventL3Input           EventType = 0x0300
	EventExtEvent          EventType = 0x0301
	EventRrweb             EventType = 0x0400
)

var eventTypeNames = map[EventType]string{
	EventSessionOpen: "session_open", EventHeartbeat: "heartbeat", EventSessionEnd: "session_end",
	EventLoss: "loss", EventContinuityUnknown: "continuity_unknown", EventViewerDegraded: "viewer_degraded", EventLiveCodec: "live_codec",
	EventVInit: "v_init", EventVSegment: "v_segment", EventL1Request: "l1_request", EventL1Response: "l1_response",
	EventL1WsFrame: "l1_ws_frame", EventL1Blocked: "l1_blocked", EventL3Input: "l3_input", EventExtEvent: "ext_event",
	EventRrweb: "rrweb",
}

func (t EventType) String() string {
	if n, ok := eventTypeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("0x%04x", uint16(t))
}

// Envelope is one chained event. Body is the exact JSON bytes that get hashed and stored.
type Envelope struct {
	Type           EventType
	Seq            uint64
	WallTimeUnixMs int64
	MonoElapsedUs  uint64
	PrevHash       [32]byte
	Body           []byte
}

func (e *Envelope) Marshal() []byte {
	out := make([]byte, EnvelopeHeaderSize+len(e.Body))
	copy(out[0:4], envelopeMagic[:])
	out[4] = 1
	out[5] = AlgV1
	binary.BigEndian.PutUint16(out[6:8], uint16(e.Type))
	binary.BigEndian.PutUint64(out[8:16], e.Seq)
	binary.BigEndian.PutUint64(out[16:24], uint64(e.WallTimeUnixMs))
	binary.BigEndian.PutUint64(out[24:32], e.MonoElapsedUs)
	copy(out[32:64], e.PrevHash[:])
	binary.BigEndian.PutUint32(out[64:68], uint32(len(e.Body)))
	copy(out[68:], e.Body)
	return out
}

// Hash returns eventHash = SHA-256(domain || 0x00 || envelope bytes).
func (e *Envelope) Hash() [32]byte { return EventHash(e.Marshal()) }

func EventHash(envelopeBytes []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(domainEvent))
	h.Write([]byte{0})
	h.Write(envelopeBytes)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ParseEnvelopes splits an E chunk plaintext (concatenated envelopes) into envelopes, keeping each raw encoding.
func ParseEnvelopes(b []byte) ([]Envelope, [][]byte, error) {
	var envs []Envelope
	var raws [][]byte
	for off := 0; off < len(b); {
		if len(b)-off < EnvelopeHeaderSize {
			return nil, nil, errors.New("contract: truncated envelope header")
		}
		h := b[off : off+EnvelopeHeaderSize]
		if !bytes.Equal(h[0:4], envelopeMagic[:]) || h[4] != 1 || h[5] != AlgV1 {
			return nil, nil, fmt.Errorf("contract: bad envelope magic/version at offset %d", off)
		}
		bodyLen := int(binary.BigEndian.Uint32(h[64:68]))
		if bodyLen > MaxEnvelopeBody || len(b)-off-EnvelopeHeaderSize < bodyLen {
			return nil, nil, fmt.Errorf("contract: bad envelope body length at offset %d", off)
		}
		var e Envelope
		e.Type = EventType(binary.BigEndian.Uint16(h[6:8]))
		e.Seq = binary.BigEndian.Uint64(h[8:16])
		e.WallTimeUnixMs = int64(binary.BigEndian.Uint64(h[16:24]))
		e.MonoElapsedUs = binary.BigEndian.Uint64(h[24:32])
		copy(e.PrevHash[:], h[32:64])
		end := off + EnvelopeHeaderSize + bodyLen
		e.Body = append([]byte(nil), b[off+EnvelopeHeaderSize:end]...)
		envs = append(envs, e)
		raws = append(raws, b[off:end])
		off = end
	}
	return envs, raws, nil
}

// Chain appends events and tracks seq and head. It is the producer side (gateway).
type Chain struct {
	nextSeq uint64
	head    [32]byte
}

// NewChain starts a chain; resume a persisted chain with ResumeChain.
func NewChain() *Chain { return &Chain{} }

func ResumeChain(nextSeq uint64, head [32]byte) *Chain { return &Chain{nextSeq: nextSeq, head: head} }

// Append builds the next envelope, advances the chain and returns the envelope with its encoding and hash.
func (c *Chain) Append(t EventType, wallTimeUnixMs int64, monoElapsedUs uint64, body []byte) (Envelope, []byte, [32]byte) {
	e := Envelope{Type: t, Seq: c.nextSeq, WallTimeUnixMs: wallTimeUnixMs, MonoElapsedUs: monoElapsedUs, PrevHash: c.head, Body: body}
	raw := e.Marshal()
	h := EventHash(raw)
	c.nextSeq++
	c.head = h
	return e, raw, h
}

func (c *Chain) NextSeq() uint64 { return c.nextSeq }
func (c *Chain) Head() [32]byte  { return c.head }

// VerifyChainSegment verifies envelopes that start at firstSeq with prevHash; it returns the resulting head.
// For the first chunk of a session pass firstSeq 0 and a zero prevHash.
func VerifyChainSegment(chunkPlaintext []byte, firstSeq uint64, prevHash [32]byte) (head [32]byte, lastSeq uint64, err error) {
	envs, raws, err := ParseEnvelopes(chunkPlaintext)
	if err != nil {
		return head, 0, err
	}
	if len(envs) == 0 {
		return head, 0, errors.New("contract: empty chunk")
	}
	expected := firstSeq
	prev := prevHash
	for i, e := range envs {
		if e.Seq != expected {
			return head, 0, fmt.Errorf("contract: seq gap: expected %d got %d", expected, e.Seq)
		}
		if e.PrevHash != prev {
			return head, 0, fmt.Errorf("contract: prevHash mismatch at seq %d", e.Seq)
		}
		prev = EventHash(raws[i])
		expected++
	}
	return prev, expected - 1, nil
}
