package verifier

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/Infisical/infisical-merge/packages/pam/webapp/contract"
	"github.com/google/uuid"
)

const fingerprintPrefix = "SHA256:"

type chainEvent struct {
	envelope contract.Envelope
	hash     [32]byte
}

type checkedObject struct {
	entry      ObjectEntry
	checkpoint *contract.Checkpoint
	// plaintext is nil when the object could not be decrypted (no session key, or a failed check already reported).
	plaintext []byte
}

type verification struct {
	bundle       *Bundle
	report       *Report
	recordingPub ed25519.PublicKey
	sessionPub   ed25519.PublicKey
	keyCert      *contract.KeyCert
	events       map[uint64]chainEvent
	maxSeq       uint64
	ended        bool
	videoLoss    bool
	// eventsComplete is false when an event chunk could not be decrypted: end-record and binding conclusions would
	// then only repeat the failure already reported, so they are skipped.
	eventsComplete bool
}

// Verify checks the bundle against the customer-recorded recording key fingerprint and returns the verdict with
// every finding. It never trusts a key from the bundle that does not chain to that fingerprint.
func Verify(b *Bundle, trustedFingerprint string) *Report {
	v := &verification{
		bundle: b,
		report: &Report{
			Fingerprint: NormalizeFingerprint(trustedFingerprint),
			SessionID:   b.Replay.SessionID,
			ProjectID:   b.Replay.ProjectID,
		},
		events: map[uint64]chainEvent{},
	}
	if v.verifyKeys() {
		chunks := v.checkSeries(contract.SeriesE, b.Replay.Events.Chunks)
		videos := v.checkSeries(contract.SeriesV, b.Replay.Video.Objects)
		v.report.EventChunks, v.report.VideoObjects = len(chunks), len(videos)
		v.verifyChain(chunks)
		if v.eventsComplete {
			v.verifyLifecycle()
			v.verifyVideoBinding(videos)
		}
	}
	v.report.finalize()
	return v.report
}

func NormalizeFingerprint(fingerprint string) string {
	trimmed := strings.TrimSpace(fingerprint)
	if strings.HasPrefix(trimmed, fingerprintPrefix) {
		return trimmed
	}
	return fingerprintPrefix + trimmed
}

func (v *verification) verifyKeys() bool {
	replay := &v.bundle.Replay
	pub, err := base64.StdEncoding.DecodeString(replay.RecordingKey.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		v.report.tampered("keys", "recording public key is not 32 base64 bytes")
		return false
	}
	v.recordingPub = pub
	if got := contract.Fingerprint(pub); got != v.report.Fingerprint {
		v.report.tampered("keys", "recording key fingerprint %s does not match the trusted fingerprint", got)
		return false
	}
	sessionID, err := uuid.Parse(replay.SessionID)
	if err != nil {
		v.report.tampered("keys", "sessionId %q is not a UUID", replay.SessionID)
		return false
	}
	keyCert, err := verifyKeyCert(pub, replay.KeyCert, replay.KeyCertSig)
	if err != nil {
		v.report.tampered("keys", "session key certificate: %v", err)
		return false
	}
	if keyCert.SessionID != sessionID {
		v.report.tampered("keys", "session key certificate is for session %s", uuid.UUID(keyCert.SessionID))
		return false
	}
	v.keyCert = keyCert
	v.sessionPub = keyCert.SessionPublicKey[:]
	if v.bundle.SessionKey == nil {
		v.report.incomplete("keys", "no %s in the bundle: chain and plaintext digests not verified", SessionKeyFile)
	}
	return true
}

func verifyKeyCert(recordingPub ed25519.PublicKey, keyCertB64, sigB64 string) (*contract.KeyCert, error) {
	keyCert, err := base64.StdEncoding.DecodeString(keyCertB64)
	if err != nil {
		return nil, fmt.Errorf("keyCert is not base64: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("keyCertSig is not base64: %w", err)
	}
	return contract.VerifyKeyCert(recordingPub, keyCert, sig)
}

func (v *verification) checkSeries(series contract.Series, entries []ObjectEntry) []checkedObject {
	sorted := append([]ObjectEntry(nil), entries...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].ObjectIndex < sorted[j].ObjectIndex })
	var checked []checkedObject
	for i, entry := range sorted {
		if i > 0 && sorted[i-1].ObjectIndex == entry.ObjectIndex {
			v.report.tampered(objectSubject(series, entry.ObjectIndex), "listed twice")
			continue
		}
		if obj, ok := v.checkObject(series, entry); ok {
			checked = append(checked, obj)
		}
	}
	return checked
}

func objectSubject(series contract.Series, objectIndex uint32) string {
	return fmt.Sprintf("%s/%d", series.Letter(), objectIndex)
}

// checkObject verifies one checkpoint and its stored object. It returns false when the checkpoint itself cannot be
// trusted, so later stages never use its fields.
func (v *verification) checkObject(series contract.Series, entry ObjectEntry) (checkedObject, bool) {
	subject := objectSubject(series, entry.ObjectIndex)
	checkpoint, err := v.verifyCheckpointSignature(entry)
	if err != nil {
		v.report.tampered(subject, "checkpoint: %v", err)
		return checkedObject{}, false
	}
	if !v.checkCheckpointFields(subject, series, entry, checkpoint) {
		return checkedObject{}, false
	}
	obj := checkedObject{entry: entry, checkpoint: checkpoint}
	stored, err := v.bundle.storedObject(series, entry.ObjectIndex)
	if err != nil {
		v.report.tampered(subject, "stored object %s missing: %v", StoredObjectPath(series, entry.ObjectIndex), err)
		return obj, true
	}
	if !checkDigest(v.report, subject, "ciphertext", stored, checkpoint.CiphertextBytes, checkpoint.CiphertextSHA256) {
		return obj, true
	}
	obj.plaintext = v.decrypt(subject, series, entry.ObjectIndex, stored, checkpoint)
	return obj, true
}

func (v *verification) verifyCheckpointSignature(entry ObjectEntry) (*contract.Checkpoint, error) {
	raw, err := base64.StdEncoding.DecodeString(entry.Checkpoint)
	if err != nil {
		return nil, fmt.Errorf("not base64: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(entry.Signature)
	if err != nil {
		return nil, fmt.Errorf("signature not base64: %w", err)
	}
	return contract.VerifyCheckpoint(v.sessionPub, raw, sig)
}

func (v *verification) checkCheckpointFields(subject string, series contract.Series, entry ObjectEntry, c *contract.Checkpoint) bool {
	var problems []string
	if c.SessionID != v.keyCert.SessionID {
		problems = append(problems, "signed for another session")
	}
	if c.Series != series || c.ObjectIndex != entry.ObjectIndex {
		problems = append(problems, fmt.Sprintf("signed for %s, listed as %s", objectSubject(c.Series, c.ObjectIndex), subject))
	}
	if !kindMatches(series, entry.Kind, c.Kind) {
		problems = append(problems, fmt.Sprintf("kind %d does not match %q", c.Kind, entry.Kind))
	}
	if c.CreatedAtUnixMs < v.keyCert.NotBeforeUnixMs || c.CreatedAtUnixMs > v.keyCert.NotAfterUnixMs {
		problems = append(problems, "created outside the session key validity window")
	}
	if v.bundle.SessionKey != nil && c.KeyCommitment != contract.KeyCommitment(v.bundle.SessionKey) {
		problems = append(problems, "key commitment does not match the bundle session key")
	}
	for _, p := range problems {
		v.report.tampered(subject, "checkpoint %s", p)
	}
	return len(problems) == 0
}

func kindMatches(series contract.Series, listedKind string, signed contract.CheckpointKind) bool {
	if series == contract.SeriesE {
		return signed == contract.KindEvents
	}
	switch listedKind {
	case "init":
		return signed == contract.KindVideoInit
	case "media":
		return signed == contract.KindVideoMedia
	case "":
		return signed == contract.KindVideoInit || signed == contract.KindVideoMedia
	default:
		return false
	}
}

func checkDigest(r *Report, subject, what string, data []byte, wantLen uint64, wantSha [32]byte) bool {
	if uint64(len(data)) != wantLen {
		r.tampered(subject, "%s is %d bytes, checkpoint says %d", what, len(data), wantLen)
		return false
	}
	if sha256.Sum256(data) != wantSha {
		r.tampered(subject, "%s SHA-256 does not match the checkpoint", what)
		return false
	}
	return true
}

func (v *verification) decrypt(subject string, series contract.Series, objectIndex uint32, stored []byte, c *contract.Checkpoint) []byte {
	if v.bundle.SessionKey == nil {
		return nil
	}
	aad := contract.BuildAAD(v.bundle.Replay.ProjectID, v.bundle.Replay.SessionID, series, objectIndex)
	plaintext, err := contract.OpenObject(v.bundle.SessionKey, stored, aad)
	if err != nil {
		v.report.tampered(subject, "decryption failed: %v", err)
		return nil
	}
	if !checkDigest(v.report, subject, "plaintext", plaintext, c.PlaintextBytes, c.PlaintextSHA256) {
		return nil
	}
	return plaintext
}

func (v *verification) verifyChain(chunks []checkedObject) {
	if len(chunks) == 0 {
		v.report.incomplete("E", "no event chunks in the bundle")
		return
	}
	var prevHash [32]byte
	nextSeq := uint64(0)
	v.eventsComplete = true
	for i, chunk := range chunks {
		c := chunk.checkpoint
		subject := objectSubject(contract.SeriesE, c.ObjectIndex)
		if c.ObjectIndex != uint32(i) {
			v.report.tampered(subject, "event chunks %d..%d are missing", i, c.ObjectIndex-1)
		}
		if chunk.plaintext == nil {
			v.eventsComplete = false
			continue
		}
		envelopes, raws, err := contract.ParseEnvelopes(chunk.plaintext)
		if err != nil || len(envelopes) == 0 {
			v.report.tampered(subject, "event chunk does not parse: %v", err)
			v.eventsComplete = false
			continue
		}
		if c.FirstSeq != nextSeq {
			v.report.tampered(subject, "seq gap: expected first seq %d, checkpoint starts at %d", nextSeq, c.FirstSeq)
			prevHash = envelopes[0].PrevHash
		}
		v.verifyChunkChain(subject, chunk.plaintext, c, prevHash)
		v.collectEvents(envelopes, raws)
		prevHash, nextSeq = c.ChainHead, c.LastSeq+1
	}
}

func (v *verification) verifyChunkChain(subject string, plaintext []byte, c *contract.Checkpoint, prevHash [32]byte) {
	head, lastSeq, err := contract.VerifyChainSegment(plaintext, c.FirstSeq, prevHash)
	switch {
	case err != nil:
		v.report.tampered(subject, "hash chain: %v", err)
	case head != c.ChainHead:
		v.report.tampered(subject, "chain head does not match the checkpoint")
	case lastSeq != c.LastSeq:
		v.report.tampered(subject, "last seq %d, checkpoint says %d", lastSeq, c.LastSeq)
	}
}

func (v *verification) collectEvents(envelopes []contract.Envelope, raws [][]byte) {
	for i, e := range envelopes {
		v.events[e.Seq] = chainEvent{envelope: e, hash: contract.EventHash(raws[i])}
		if e.Seq > v.maxSeq {
			v.maxSeq = e.Seq
		}
	}
	v.report.Events = len(v.events)
}

func seqSubject(seq uint64) string { return fmt.Sprintf("seq %d", seq) }

func (v *verification) verifyLifecycle() {
	if len(v.events) == 0 {
		return
	}
	v.verifySessionOpen()
	for seq := uint64(0); seq <= v.maxSeq; seq++ {
		e, ok := v.events[seq]
		if !ok {
			continue
		}
		switch e.envelope.Type {
		case contract.EventLoss:
			v.reportLoss(seq, e.envelope.Body)
		case contract.EventContinuityUnknown:
			v.report.incomplete(seqSubject(seq), "gateway-reported continuity gap: %s", e.envelope.Body)
		case contract.EventSessionEnd:
			v.verifySessionEnd(seq, e.envelope.Body)
		}
	}
	if !v.ended {
		v.report.incomplete(seqSubject(v.maxSeq), "no session_end record after the last event")
	}
}

type sessionOpenBody struct {
	RecordingKey   RecordingKey `json:"recordingKey"`
	SessionKeyCert string       `json:"sessionKeyCert"`
}

func (v *verification) verifySessionOpen() {
	e, ok := v.events[0]
	if !ok || e.envelope.Type != contract.EventSessionOpen {
		v.report.tampered(seqSubject(0), "the chain does not start with session_open")
		return
	}
	var body sessionOpenBody
	if err := json.Unmarshal(e.envelope.Body, &body); err != nil {
		v.report.tampered(seqSubject(0), "session_open body: %v", err)
		return
	}
	// The chain is signed, so a field the gateway recorded must agree with the verified keys; absent fields are skipped.
	recorded := []struct{ name, got, want string }{
		{"recording public key", body.RecordingKey.PublicKey, base64.StdEncoding.EncodeToString(v.recordingPub)},
		{"recording key fingerprint", body.RecordingKey.Fingerprint, contract.Fingerprint(v.recordingPub)},
		{"recording key id", body.RecordingKey.KeyID, contract.KeyIDHex(v.recordingPub)},
		{"session key certificate", body.SessionKeyCert, v.bundle.Replay.KeyCert},
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
	if body.Stream == contract.SeriesV.Letter() {
		v.videoLoss = true
	}
	v.report.incomplete(seqSubject(seq), "gateway-reported loss on stream %s: %d lost (%s)", body.Stream, body.Count, body.Reason)
}

func (v *verification) verifySessionEnd(seq uint64, raw []byte) {
	v.ended = true
	var body struct {
		FinalSeq *uint64 `json:"finalSeq"`
	}
	if err := json.Unmarshal(raw, &body); err != nil || body.FinalSeq == nil {
		v.report.tampered(seqSubject(seq), "session_end body has no finalSeq")
		return
	}
	if *body.FinalSeq != seq {
		v.report.tampered(seqSubject(seq), "session_end finalSeq %d is not its own seq", *body.FinalSeq)
	}
	if seq != v.maxSeq {
		v.report.tampered(seqSubject(seq), "events recorded after session_end (last seq %d)", v.maxSeq)
	}
}

type videoEventBody struct {
	ObjectIndex *uint32 `json:"objectIndex"`
	Sha256      string  `json:"sha256"`
}

func (v *verification) verifyVideoBinding(videos []checkedObject) {
	present := map[uint32]bool{}
	for _, obj := range videos {
		present[obj.checkpoint.ObjectIndex] = true
		v.verifyVideoObjectBinding(obj.checkpoint)
	}
	v.verifyVideoEventsHaveObjects(present)
}

func (v *verification) verifyVideoObjectBinding(c *contract.Checkpoint) {
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
	var body videoEventBody
	if err := json.Unmarshal(e.envelope.Body, &body); err != nil || body.ObjectIndex == nil {
		v.report.tampered(subject, "seq %d body has no objectIndex", c.LastSeq)
		return
	}
	if *body.ObjectIndex != c.ObjectIndex {
		v.report.tampered(subject, "seq %d names video object %d", c.LastSeq, *body.ObjectIndex)
	}
	if !strings.EqualFold(body.Sha256, hex.EncodeToString(c.PlaintextSHA256[:])) {
		v.report.tampered(subject, "seq %d records a different plaintext SHA-256", c.LastSeq)
	}
	if !bytes.Equal(e.hash[:], c.ChainHead[:]) {
		v.report.tampered(subject, "chain head is not the hash of seq %d", c.LastSeq)
	}
}

func (v *verification) unbound(subject, format string, args ...any) {
	if v.ended {
		v.report.tampered(subject, "not bound to the chain: "+format, args...)
		return
	}
	v.report.incomplete(subject, "binding pending: "+format, args...)
}

func videoEventType(kind contract.CheckpointKind) contract.EventType {
	if kind == contract.KindVideoInit {
		return contract.EventVInit
	}
	return contract.EventVSegment
}

func (v *verification) verifyVideoEventsHaveObjects(present map[uint32]bool) {
	for seq := uint64(0); seq <= v.maxSeq; seq++ {
		e, ok := v.events[seq]
		if !ok || (e.envelope.Type != contract.EventVInit && e.envelope.Type != contract.EventVSegment) {
			continue
		}
		var body videoEventBody
		if err := json.Unmarshal(e.envelope.Body, &body); err != nil || body.ObjectIndex == nil {
			v.report.tampered(seqSubject(seq), "%s body has no objectIndex", e.envelope.Type)
			continue
		}
		if present[*body.ObjectIndex] {
			continue
		}
		subject := objectSubject(contract.SeriesV, *body.ObjectIndex)
		if v.videoLoss {
			v.report.incomplete(subject, "recorded at seq %d but missing; covered by a gateway loss record", seq)
		} else {
			v.report.tampered(subject, "recorded at seq %d but missing from the bundle", seq)
		}
	}
}
