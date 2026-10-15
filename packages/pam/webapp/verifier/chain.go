package verifier

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/Infisical/infisical-merge/packages/pam/webapp/contract"
)

type chainEvent struct {
	envelope contract.Envelope
	hash     [32]byte
}

func seqSubject(seq uint64) string { return fmt.Sprintf("seq %d", seq) }

// verifyChain recomputes the hash chain across the event chunks. Missing chunks and seq gaps are a Gap
// (Incomplete, CONTRACTS.md 6.10); a broken hash is Tampered.
func (v *verification) verifyChain(chunks []checkedObject) {
	if len(chunks) == 0 {
		v.report.incomplete("E", "no event chunks in the bundle")
		return
	}
	var prevHash [32]byte
	nextSeq, nextIndex := uint64(0), uint32(0)
	v.eventsComplete = true
	for _, chunk := range chunks {
		c := chunk.checkpoint
		subject := objectSubject(contract.SeriesE, c.ObjectIndex)
		if c.ObjectIndex != nextIndex {
			v.chainGap = true
			v.report.incomplete(subject, "gap: event chunks %d..%d are not in the bundle", nextIndex, c.ObjectIndex-1)
		}
		if v.verifyChunk(subject, chunk, nextSeq, prevHash) {
			v.eventsComplete = false
		}
		prevHash, nextSeq, nextIndex = c.ChainHead, c.LastSeq+1, c.ObjectIndex+1
	}
	v.seqs = make([]uint64, 0, len(v.events))
	for seq := range v.events {
		v.seqs = append(v.seqs, seq)
	}
	slices.Sort(v.seqs)
	v.report.Events = len(v.seqs)
}

// verifyChunk checks one chunk against the chain cursor and collects its events. It returns true when the chunk's
// events are unavailable. The cursor always advances from the signed checkpoint, so one bad chunk is reported once.
func (v *verification) verifyChunk(subject string, chunk checkedObject, nextSeq uint64, prevHash [32]byte) bool {
	c := chunk.checkpoint
	if chunk.plaintext == nil {
		return true
	}
	envelopes, raws, err := contract.ParseEnvelopes(chunk.plaintext)
	if err != nil || len(envelopes) == 0 {
		v.report.tampered(subject, "event chunk does not parse: %v", err)
		return true
	}
	if c.FirstSeq != nextSeq {
		v.chainGap = true
		v.report.incomplete(subject, "gap: expected first seq %d, checkpoint starts at %d", nextSeq, c.FirstSeq)
		prevHash = envelopes[0].PrevHash
	}
	head, lastSeq, err := contract.VerifyChainSegment(chunk.plaintext, c.FirstSeq, prevHash)
	switch {
	case err != nil:
		v.report.tampered(subject, "hash chain: %v", err)
	case head != c.ChainHead:
		v.report.tampered(subject, "chain head does not match the checkpoint")
	case lastSeq != c.LastSeq:
		v.report.tampered(subject, "last seq %d, checkpoint says %d", lastSeq, c.LastSeq)
	}
	for i, e := range envelopes {
		v.events[e.Seq] = chainEvent{envelope: e, hash: contract.EventHash(raws[i])}
	}
	return false
}

func (v *verification) verifyLifecycle(listedChunks, listedVideos int) {
	if len(v.seqs) == 0 {
		return
	}
	v.verifySessionOpen()
	for _, seq := range v.seqs {
		e := v.events[seq]
		switch e.envelope.Type {
		case contract.EventLoss:
			v.reportLoss(seq, e.envelope.Body)
		case contract.EventContinuityUnknown:
			v.report.incomplete(seqSubject(seq), "gateway-reported continuity gap: %s", e.envelope.Body)
		case contract.EventSessionEnd:
			v.verifySessionEnd(seq, e.envelope.Body, listedChunks, listedVideos)
		}
	}
	if !v.ended {
		v.report.incomplete(seqSubject(v.lastSeq()), "no session_end record after the last event")
	}
}

func (v *verification) lastSeq() uint64 { return v.seqs[len(v.seqs)-1] }

type sessionOpenBody struct {
	RecordingKey      RecordingKey `json:"recordingKey"`
	SessionKeyCert    string       `json:"sessionKeyCert"`
	SessionKeyCertSig string       `json:"sessionKeyCertSig"`
}

func (v *verification) verifySessionOpen() {
	e, ok := v.events[0]
	if !ok {
		return
	}
	if e.envelope.Type != contract.EventSessionOpen {
		v.report.tampered(seqSubject(0), "the chain does not start with session_open")
		return
	}
	var body sessionOpenBody
	if err := json.Unmarshal(e.envelope.Body, &body); err != nil {
		v.report.tampered(seqSubject(0), "session_open body: %v", err)
		return
	}
	// Absent fields are allowed (F0's vectors omit some); a field the gateway did record must match the verified keys.
	recorded := []struct{ name, got, want string }{
		{"recording public key", body.RecordingKey.PublicKey, v.bundle.Replay.RecordingKey.PublicKey},
		{"recording key fingerprint", body.RecordingKey.Fingerprint, contract.Fingerprint(v.recordingPub)},
		{"recording key id", body.RecordingKey.KeyID, contract.KeyIDHex(v.recordingPub)},
		{"session key certificate", body.SessionKeyCert, v.bundle.Replay.KeyCert},
		{"session key certificate signature", body.SessionKeyCertSig, v.bundle.Replay.KeyCertSig},
	}
	for _, field := range recorded {
		if field.got != "" && field.got != field.want {
			v.report.tampered(seqSubject(0), "session_open records a different %s", field.name)
		}
	}
}

type lossBody struct {
	Stream string `json:"stream"`
	Count  int64  `json:"count"`
	Reason string `json:"reason"`
}

func (v *verification) reportLoss(seq uint64, raw []byte) {
	var body lossBody
	if err := json.Unmarshal(raw, &body); err != nil {
		v.report.tampered(seqSubject(seq), "loss body: %v", err)
		return
	}
	if body.Stream == contract.SeriesV.Letter() && body.Count > 0 {
		v.videoLossCount += body.Count
	}
	v.report.incomplete(seqSubject(seq), "gateway-reported loss on stream %s: %d lost (%s)", body.Stream, body.Count, body.Reason)
}

type sessionEndBody struct {
	FinalSeq *uint64 `json:"finalSeq"`
	EChunks  *int    `json:"eChunks"`
	VObjects *int    `json:"vObjects"`
}

func (v *verification) verifySessionEnd(seq uint64, raw []byte, listedChunks, listedVideos int) {
	v.ended = true
	subject := seqSubject(seq)
	var body sessionEndBody
	if err := json.Unmarshal(raw, &body); err != nil || body.FinalSeq == nil {
		v.report.tampered(subject, "session_end body has no finalSeq")
		return
	}
	if *body.FinalSeq != seq {
		v.report.tampered(subject, "session_end finalSeq %d is not its own seq", *body.FinalSeq)
	}
	if seq != v.lastSeq() {
		v.report.tampered(subject, "events recorded after session_end (last seq %d)", v.lastSeq())
	}
	v.compareEndCount(subject, "event chunks", body.EChunks, listedChunks)
	v.compareEndCount(subject, "video objects", body.VObjects, listedVideos)
}

// compareEndCount: fewer listed objects than session_end recorded is a Gap; more is impossible for a genuine bundle.
func (v *verification) compareEndCount(subject, what string, recorded *int, listed int) {
	switch {
	case recorded == nil || *recorded == listed:
	case listed < *recorded:
		v.report.incomplete(subject, "gap: session_end records %d %s, the bundle verifies %d", *recorded, what, listed)
	default:
		v.report.tampered(subject, "session_end records %d %s, the bundle lists %d", *recorded, what, listed)
	}
}

type videoEventBody struct {
	ObjectIndex *uint32 `json:"objectIndex"`
	Sha256      string  `json:"sha256"`
}

func videoEventType(kind contract.CheckpointKind) contract.EventType {
	if kind == contract.KindVideoInit {
		return contract.EventVInit
	}
	return contract.EventVSegment
}

func isVideoEvent(t contract.EventType) bool {
	return t == contract.EventVInit || t == contract.EventVSegment
}

// videoEvents parses every v_init/v_segment body once, keyed by seq.
func (v *verification) videoEvents() map[uint64]videoEventBody {
	bodies := map[uint64]videoEventBody{}
	for _, seq := range v.seqs {
		e := v.events[seq]
		if !isVideoEvent(e.envelope.Type) {
			continue
		}
		var body videoEventBody
		if err := json.Unmarshal(e.envelope.Body, &body); err != nil || body.ObjectIndex == nil {
			v.report.tampered(seqSubject(seq), "%s body has no objectIndex", e.envelope.Type)
			continue
		}
		bodies[seq] = body
	}
	return bodies
}

func (v *verification) verifyVideoBinding(videos []checkedObject) {
	bodies := v.videoEvents()
	present := map[uint32]bool{}
	for _, obj := range videos {
		present[obj.checkpoint.ObjectIndex] = true
		v.verifyVideoObjectBinding(obj.checkpoint, bodies)
	}
	v.reportMissingVideoObjects(bodies, present)
}

func (v *verification) verifyVideoObjectBinding(c *contract.Checkpoint, bodies map[uint64]videoEventBody) {
	subject := objectSubject(contract.SeriesV, c.ObjectIndex)
	if c.FirstSeq != c.LastSeq {
		v.report.tampered(subject, "video checkpoint covers seq %d..%d, expected one event", c.FirstSeq, c.LastSeq)
		return
	}
	e, ok := v.events[c.LastSeq]
	if !ok {
		v.unbound(subject, "its event seq %d is not in the bundle's event chunks", c.LastSeq)
		return
	}
	if e.envelope.Type != videoEventType(c.Kind) {
		v.report.tampered(subject, "seq %d is %s, expected %s", c.LastSeq, e.envelope.Type, videoEventType(c.Kind))
		return
	}
	body, ok := bodies[c.LastSeq]
	if !ok {
		return
	}
	if *body.ObjectIndex != c.ObjectIndex {
		v.report.tampered(subject, "seq %d names video object %d", c.LastSeq, *body.ObjectIndex)
	}
	if !strings.EqualFold(body.Sha256, hex.EncodeToString(c.PlaintextSHA256[:])) {
		v.report.tampered(subject, "seq %d records a different plaintext SHA-256", c.LastSeq)
	}
	if e.hash != c.ChainHead {
		v.report.tampered(subject, "chain head is not the hash of seq %d", c.LastSeq)
	}
}

func (v *verification) unbound(subject, format string, args ...any) {
	if v.ended && !v.chainGap {
		v.report.tampered(subject, "not bound to the chain: "+format, args...)
		return
	}
	v.report.incomplete(subject, "binding pending: "+format, args...)
}

// reportMissingVideoObjects reports video objects the chain records but the bundle lacks. Each is a Gap; up to the
// total count of V loss records it is attributed to the gateway-reported loss.
func (v *verification) reportMissingVideoObjects(bodies map[uint64]videoEventBody, present map[uint32]bool) {
	explained := v.videoLossCount
	for _, seq := range v.seqs {
		body, ok := bodies[seq]
		if !ok || present[*body.ObjectIndex] {
			continue
		}
		subject := objectSubject(contract.SeriesV, *body.ObjectIndex)
		if explained > 0 {
			explained--
			v.report.incomplete(subject, "recorded at seq %d but missing; covered by a gateway loss record", seq)
			continue
		}
		v.report.incomplete(subject, "gap: recorded at seq %d but missing from the bundle", seq)
	}
}
