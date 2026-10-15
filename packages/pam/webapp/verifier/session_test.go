package verifier

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Infisical/infisical-merge/packages/pam/webapp/contract"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

const (
	testProjectID     = "6f1c2d3e-4a5b-4c6d-8e7f-90a1b2c3d4e5"
	testSessionID     = "8a0c6a4e-1f7b-4e0e-9a43-5d2a6f0b9c11"
	testNotBeforeMs   = int64(1760544000000)
	testNotAfterMs    = int64(1760551200000)
	testCreatedAtMs   = int64(1760544010000)
	testSessionKeyHex = "1111111111111111111111111111111111111111111111111111111111111111"
)

func testSeed(b byte) []byte { return bytes.Repeat([]byte{b}, ed25519.SeedSize) }

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// testSession produces a gateway-side recording with the contract package, the same way F2's gateway does.
type testSession struct {
	t            *testing.T
	recordingKey ed25519.PrivateKey
	sessionKey   ed25519.PrivateKey
	aesKey       []byte
	sessionID    uuid.UUID
	chain        *contract.Chain
	pending      [][]byte
	firstSeq     uint64
	replay       Replay
	stored       map[string][]byte
}

func newTestSession(t *testing.T) *testSession {
	aesKey, err := hex.DecodeString(testSessionKeyHex)
	require.NoError(t, err)
	s := &testSession{
		t:            t,
		recordingKey: ed25519.NewKeyFromSeed(testSeed(0x01)),
		sessionKey:   ed25519.NewKeyFromSeed(testSeed(0x02)),
		aesKey:       aesKey,
		sessionID:    uuid.MustParse(testSessionID),
		chain:        contract.NewChain(),
		stored:       map[string][]byte{},
	}
	s.replay.SessionID, s.replay.ProjectID = testSessionID, testProjectID
	s.replay.KeyCert, s.replay.KeyCertSig = s.signKeyCert(s.recordingKey)
	recordingPub := s.recordingKey.Public().(ed25519.PublicKey)
	s.replay.RecordingKey = RecordingKey{
		PublicKey:   b64(recordingPub),
		KeyID:       contract.KeyIDHex(recordingPub),
		Fingerprint: contract.Fingerprint(recordingPub),
	}
	return s
}

func (s *testSession) signKeyCert(issuer ed25519.PrivateKey) (string, string) {
	kc := &contract.KeyCert{
		SessionID:       s.sessionID,
		NotBeforeUnixMs: testNotBeforeMs,
		NotAfterUnixMs:  testNotAfterMs,
		IssuerKeyID:     contract.KeyID(issuer.Public().(ed25519.PublicKey)),
	}
	copy(kc.SessionPublicKey[:], s.sessionKey.Public().(ed25519.PublicKey))
	return b64(kc.Marshal()), b64(contract.SignKeyCert(issuer, kc))
}

func (s *testSession) fingerprint() string {
	return contract.Fingerprint(s.recordingKey.Public().(ed25519.PublicKey))
}

func (s *testSession) event(t contract.EventType, body any) (uint64, [32]byte) {
	raw, err := json.Marshal(body)
	require.NoError(s.t, err)
	seq := s.chain.NextSeq()
	_, envelope, hash := s.chain.Append(t, testCreatedAtMs, seq*1_000_000, raw)
	s.pending = append(s.pending, envelope)
	return seq, hash
}

func (s *testSession) open() {
	s.event(contract.EventSessionOpen, map[string]any{
		"sessionId": testSessionID, "projectId": testProjectID, "resourceType": "web-app",
		"recordingKey":   map[string]string{"publicKey": s.replay.RecordingKey.PublicKey, "fingerprint": s.fingerprint()},
		"sessionKeyCert": s.replay.KeyCert, "sessionKeyCertSig": s.replay.KeyCertSig,
	})
}

func (s *testSession) end() {
	seq := s.chain.NextSeq()
	s.event(contract.EventSessionEnd, map[string]any{"reason": "user_end", "finalSeq": seq})
}

func (s *testSession) seal(series contract.Series, kind contract.CheckpointKind, index uint32, plaintext []byte, first, last uint64, head [32]byte) ObjectEntry {
	aad := contract.BuildAAD(testProjectID, testSessionID, series, index)
	iv := bytes.Repeat([]byte{byte(0x20 + index)}, contract.IVSize)
	stored, err := contract.SealObject(s.aesKey, iv, plaintext, aad)
	require.NoError(s.t, err)
	c := &contract.Checkpoint{
		Series: series, Kind: kind, SessionID: s.sessionID, ObjectIndex: index, FirstSeq: first, LastSeq: last,
		ChainHead: head, PlaintextSHA256: sha256.Sum256(plaintext), CiphertextSHA256: sha256.Sum256(stored),
		PlaintextBytes: uint64(len(plaintext)), CiphertextBytes: uint64(len(stored)),
		KeyCommitment: contract.KeyCommitment(s.aesKey), MaskingPolicyVersion: 1,
		SignerKeyID: contract.KeyID(s.sessionKey.Public().(ed25519.PublicKey)), CreatedAtUnixMs: testCreatedAtMs,
	}
	s.stored[StoredObjectPath(series, index)] = stored
	return ObjectEntry{ObjectIndex: index, Checkpoint: b64(c.Marshal()), Signature: b64(contract.SignCheckpoint(s.sessionKey, c))}
}

func (s *testSession) sealChunk() {
	index := uint32(len(s.replay.Events.Chunks))
	last := s.chain.NextSeq() - 1
	entry := s.seal(contract.SeriesE, contract.KindEvents, index, bytes.Join(s.pending, nil), s.firstSeq, last, s.chain.Head())
	s.replay.Events.Chunks = append(s.replay.Events.Chunks, entry)
	s.pending, s.firstSeq = nil, last+1
}

func (s *testSession) video(kind contract.CheckpointKind, plaintext []byte) {
	index := uint32(len(s.replay.Video.Objects))
	sum := sha256.Sum256(plaintext)
	seq, hash := s.event(videoEventType(kind), map[string]any{"objectIndex": index, "sha256": hex.EncodeToString(sum[:]), "bytes": len(plaintext)})
	entry := s.seal(contract.SeriesV, kind, index, plaintext, seq, seq, hash)
	entry.Kind = videoKindName(kind)
	s.replay.Video.Objects = append(s.replay.Video.Objects, entry)
}

func (s *testSession) write() string {
	dir := s.t.TempDir()
	writeReplay(s.t, dir, s.replay)
	require.NoError(s.t, os.WriteFile(filepath.Join(dir, SessionKeyFile), []byte(b64(s.aesKey)+"\n"), 0o600))
	for rel, stored := range s.stored {
		path := filepath.Join(dir, rel)
		require.NoError(s.t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(s.t, os.WriteFile(path, stored, 0o644))
	}
	return dir
}

func writeReplay(t *testing.T, dir string, replay Replay) {
	raw, err := json.MarshalIndent(replay, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, ReplayFile), raw, 0o644))
}

type sessionOptions struct {
	withEnd    bool
	videoLoss  bool
	mediaCount int
}

func recordSession(t *testing.T, opts sessionOptions) *testSession {
	s := newTestSession(t)
	s.open()
	s.event(contract.EventL3Input, map[string]any{"events": []any{map[string]any{"t": "key", "code": "KeyA"}}})
	s.video(contract.KindVideoInit, []byte("ftyp-moov-init-segment"))
	s.sealChunk()
	for i := 0; i < opts.mediaCount; i++ {
		s.video(contract.KindVideoMedia, bytes.Repeat([]byte{byte('a' + i)}, 64))
	}
	if opts.videoLoss {
		s.event(contract.EventLoss, map[string]any{"stream": "V", "fromUs": 1, "toUs": 2, "count": 1, "reason": "recorder_overflow"})
	}
	s.event(contract.EventHeartbeat, map[string]any{"lastSeq": s.chain.NextSeq() - 1, "uptimeMs": 30000, "viewerConnected": true})
	if opts.withEnd {
		s.end()
	}
	s.sealChunk()
	return s
}

func verifyDir(t *testing.T, dir, fingerprint string) *Report {
	b, err := LoadBundle(dir)
	require.NoError(t, err)
	return Verify(b, fingerprint)
}

// fixtureDir holds a committed verified bundle for the webapp-verify CLI tests and demos. Its session-key.b64 is the
// deterministic test key 0x11 repeated, not a secret. Regenerate with:
// IWA_WRITE_BUNDLE=1 go test ./packages/pam/webapp/verifier/ -run TestFixtureBundle
const fixtureDir = "testdata/bundle-verified"

func TestFixtureBundle(t *testing.T) {
	s := recordSession(t, sessionOptions{withEnd: true, mediaCount: 2})
	if os.Getenv("IWA_WRITE_BUNDLE") != "" {
		require.NoError(t, os.RemoveAll(fixtureDir))
		require.NoError(t, os.CopyFS(fixtureDir, os.DirFS(s.write())))
	}
	report := verifyDir(t, fixtureDir, s.fingerprint())
	require.Equal(t, VerdictVerified, report.Verdict, "findings: %+v", report.Findings)
}
