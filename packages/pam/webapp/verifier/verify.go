package verifier

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/Infisical/infisical-merge/packages/pam/webapp/contract"
	"github.com/google/uuid"
)

const fingerprintPrefix = "SHA256:"

type checkedObject struct {
	checkpoint *contract.Checkpoint
	// plaintext is kept for event chunks only, and is nil when the chunk could not be decrypted.
	plaintext []byte
}

type verification struct {
	bundle         *Bundle
	report         *Report
	recordingPub   ed25519.PublicKey
	sessionPub     ed25519.PublicKey
	keyCert        *contract.KeyCert
	events         map[uint64]chainEvent
	seqs           []uint64
	eventsComplete bool
	chainGap       bool
	ended          bool
	videoLossCount int64
}

// Verify checks the bundle against the customer-recorded recording key fingerprint (CONTRACTS.md 6.11). It never
// trusts a key from the bundle that does not chain to that fingerprint.
func Verify(b *Bundle, trustedFingerprint string) *Report {
	v := &verification{
		bundle: b,
		report: &Report{
			Fingerprint: normalizeFingerprint(trustedFingerprint),
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
			v.verifyLifecycle(len(chunks), len(videos))
			v.verifyVideoBinding(videos)
		}
	}
	v.report.finalize()
	return v.report
}

func normalizeFingerprint(fingerprint string) string {
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
	v.checkAdvertisedKey()
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

// checkAdvertisedKey compares the fingerprint and key id that replay.json displays with the verified key, so a
// bundle cannot show a reader a different fingerprint than the one it was checked against.
func (v *verification) checkAdvertisedKey() {
	advertised := v.bundle.Replay.RecordingKey
	if advertised.Fingerprint != "" && advertised.Fingerprint != v.report.Fingerprint {
		v.report.tampered("keys", "replay.json advertises fingerprint %s", advertised.Fingerprint)
	}
	if advertised.KeyID != "" && advertised.KeyID != contract.KeyIDHex(v.recordingPub) {
		v.report.tampered("keys", "replay.json advertises key id %s", advertised.KeyID)
	}
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

// checkObject returns false when the checkpoint itself cannot be trusted, so later stages never use its fields.
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
	obj := checkedObject{checkpoint: checkpoint}
	stored, err := v.bundle.storedObject(series, entry.ObjectIndex, checkpoint.CiphertextBytes)
	if errors.Is(err, os.ErrNotExist) {
		v.report.incomplete(subject, "gap: stored object %s is not in the bundle", StoredObjectPath(series, entry.ObjectIndex))
		return obj, true
	}
	if err != nil {
		v.report.tampered(subject, "stored object: %v", err)
		return obj, true
	}
	if !checkDigest(v.report, subject, "ciphertext", stored, checkpoint.CiphertextBytes, checkpoint.CiphertextSHA256) {
		return obj, true
	}
	plaintext := v.decrypt(subject, series, entry.ObjectIndex, stored, checkpoint)
	if series == contract.SeriesE {
		obj.plaintext = plaintext
	}
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
	if listedKind == "" {
		return signed == contract.KindVideoInit || signed == contract.KindVideoMedia
	}
	return listedKind == videoKindName(signed)
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
