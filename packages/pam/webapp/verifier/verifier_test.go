package verifier

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Infisical/infisical-merge/packages/pam/webapp/contract"
	"github.com/stretchr/testify/require"
)

// F0's shared vectors (CONTRACTS.md section 9) live with the contract package; the verifier must accept every one.
const vectorsDir = "../contract/testdata"

type keyVector struct {
	RecordingPublicKeyHex string `json:"recordingPublicKeyHex"`
	RecordingFingerprint  string `json:"recordingFingerprint"`
	KeyCertHex            string `json:"keyCertHex"`
	KeyCertSigHex         string `json:"keyCertSigHex"`
	SessionID             string `json:"sessionId"`
}

type checkpointVector struct {
	Name            string `json:"name"`
	Series          uint8  `json:"series"`
	Kind            uint8  `json:"kind"`
	ProjectID       string `json:"projectId"`
	ObjectIndex     uint32 `json:"objectIndex"`
	SessionKeyHex   string `json:"sessionKeyHex"`
	StoredObjectHex string `json:"storedObjectHex"`
	CheckpointHex   string `json:"checkpointHex"`
	SignatureHex    string `json:"signatureHex"`
}

func readVector(t *testing.T, name string, out any) {
	raw, err := os.ReadFile(filepath.Join(vectorsDir, name))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, out))
}

func hexB64(t *testing.T, h string) string {
	raw, err := hex.DecodeString(h)
	require.NoError(t, err)
	return b64(raw)
}

func writeHexFile(t *testing.T, path, h string) {
	raw, err := hex.DecodeString(h)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, raw, 0o644))
}

// vectorBundle assembles keys.json, chain.json and checkpoints.json into one evidence bundle: one E chunk (seq 0..3)
// and the V init it binds at seq 2.
func vectorBundle(t *testing.T) (string, keyVector) {
	var keys keyVector
	var checkpoints []checkpointVector
	readVector(t, "keys.json", &keys)
	readVector(t, "checkpoints.json", &checkpoints)
	require.NotEmpty(t, checkpoints)

	dir := t.TempDir()
	replay := Replay{SessionID: keys.SessionID, ProjectID: checkpoints[0].ProjectID}
	replay.RecordingKey.PublicKey = hexB64(t, keys.RecordingPublicKeyHex)
	replay.KeyCert, replay.KeyCertSig = hexB64(t, keys.KeyCertHex), hexB64(t, keys.KeyCertSigHex)
	for _, v := range checkpoints {
		series := contract.Series(v.Series)
		entry := ObjectEntry{ObjectIndex: v.ObjectIndex, Checkpoint: hexB64(t, v.CheckpointHex), Signature: hexB64(t, v.SignatureHex)}
		if series == contract.SeriesV {
			entry.Kind = map[uint8]string{1: "init", 2: "media"}[v.Kind]
			replay.Video.Objects = append(replay.Video.Objects, entry)
		} else {
			replay.Events.Chunks = append(replay.Events.Chunks, entry)
		}
		writeHexFile(t, filepath.Join(dir, StoredObjectPath(series, v.ObjectIndex)), v.StoredObjectHex)
	}
	writeReplay(t, dir, replay)
	require.NoError(t, os.WriteFile(filepath.Join(dir, SessionKeyFile), []byte(hexB64(t, checkpoints[0].SessionKeyHex)), 0o600))
	return dir, keys
}

func TestVectors(t *testing.T) {
	dir, keys := vectorBundle(t)
	pub, err := hex.DecodeString(keys.RecordingPublicKeyHex)
	require.NoError(t, err)
	require.Equal(t, keys.RecordingFingerprint, contract.Fingerprint(ed25519.PublicKey(pub)))

	report := verifyDir(t, dir, keys.RecordingFingerprint)

	require.Equal(t, 1, report.EventChunks)
	require.Equal(t, 1, report.VideoObjects)
	require.Equal(t, 4, report.Events)
	// The vector chain stops at a heartbeat: every cryptographic check passes and the only finding is the missing end.
	require.Equal(t, []Finding{{SeverityIncomplete, "seq 3", "no session_end record after the last event"}}, report.Findings)
	require.Equal(t, VerdictIncomplete, report.Verdict)
}

func TestVerifiedSession(t *testing.T) {
	s := recordSession(t, sessionOptions{withEnd: true, mediaCount: 2})
	report := verifyDir(t, s.write(), s.fingerprint())
	require.Empty(t, report.Findings)
	require.Equal(t, VerdictVerified, report.Verdict)
	require.Equal(t, ExitVerified, report.ExitCode())
	require.Equal(t, 2, report.EventChunks)
	require.Equal(t, 3, report.VideoObjects)
}

func TestFingerprintWithoutPrefix(t *testing.T) {
	s := recordSession(t, sessionOptions{withEnd: true})
	report := verifyDir(t, s.write(), s.fingerprint()[len(fingerprintPrefix):])
	require.Equal(t, VerdictVerified, report.Verdict)
}

func flipByte(t *testing.T, path string) {
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	raw[len(raw)/2] ^= 0x01
	require.NoError(t, os.WriteFile(path, raw, 0o644))
}

func swapFiles(t *testing.T, a, b string) {
	tmp := a + ".swap"
	require.NoError(t, os.Rename(a, tmp))
	require.NoError(t, os.Rename(b, a))
	require.NoError(t, os.Rename(tmp, b))
}

func editReplay(t *testing.T, dir string, edit func(*Replay)) {
	b, err := LoadBundle(dir)
	require.NoError(t, err)
	edit(&b.Replay)
	writeReplay(t, dir, b.Replay)
}

func TestMutations(t *testing.T) {
	otherKey := ed25519.NewKeyFromSeed(testSeed(0x03))
	cases := []struct {
		name    string
		opts    sessionOptions
		mutate  func(t *testing.T, s *testSession, dir string) string
		verdict Verdict
		exit    int
	}{
		{
			name: "flipped byte in an event chunk",
			mutate: func(t *testing.T, _ *testSession, dir string) string {
				flipByte(t, filepath.Join(dir, StoredObjectPath(contract.SeriesE, 1)))
				return ""
			},
			verdict: VerdictTampered, exit: ExitTampered,
		},
		{
			name: "flipped byte in a video segment",
			mutate: func(t *testing.T, _ *testSession, dir string) string {
				flipByte(t, filepath.Join(dir, StoredObjectPath(contract.SeriesV, 1)))
				return ""
			},
			verdict: VerdictTampered, exit: ExitTampered,
		},
		{
			name: "reordered event chunks",
			mutate: func(t *testing.T, _ *testSession, dir string) string {
				swapFiles(t, filepath.Join(dir, StoredObjectPath(contract.SeriesE, 0)), filepath.Join(dir, StoredObjectPath(contract.SeriesE, 1)))
				return ""
			},
			verdict: VerdictTampered, exit: ExitTampered,
		},
		{
			name: "reordered video segments",
			mutate: func(t *testing.T, _ *testSession, dir string) string {
				swapFiles(t, filepath.Join(dir, StoredObjectPath(contract.SeriesV, 1)), filepath.Join(dir, StoredObjectPath(contract.SeriesV, 2)))
				return ""
			},
			verdict: VerdictTampered, exit: ExitTampered,
		},
		{
			name: "removed checkpoint",
			mutate: func(t *testing.T, _ *testSession, dir string) string {
				editReplay(t, dir, func(r *Replay) { r.Events.Chunks = r.Events.Chunks[1:] })
				return ""
			},
			verdict: VerdictTampered, exit: ExitTampered,
		},
		{
			name: "removed video object without a loss record",
			mutate: func(t *testing.T, _ *testSession, dir string) string {
				editReplay(t, dir, func(r *Replay) { r.Video.Objects = r.Video.Objects[:1] })
				return ""
			},
			verdict: VerdictTampered, exit: ExitTampered,
		},
		{
			name: "wrong fingerprint",
			mutate: func(_ *testing.T, _ *testSession, _ string) string {
				return contract.Fingerprint(otherKey.Public().(ed25519.PublicKey))
			},
			verdict: VerdictTampered, exit: ExitTampered,
		},
		{
			// CONTRACTS.md has no rotation record yet; the chain of trust is fingerprint -> recording key -> KeyCert.
			name: "session key certificate signed by an untrusted key",
			mutate: func(t *testing.T, s *testSession, dir string) string {
				editReplay(t, dir, func(r *Replay) { r.KeyCert, r.KeyCertSig = s.signKeyCert(otherKey) })
				return ""
			},
			verdict: VerdictTampered, exit: ExitTampered,
		},
		{
			name: "recording key swapped for one matching an attacker fingerprint",
			mutate: func(t *testing.T, _ *testSession, dir string) string {
				editReplay(t, dir, func(r *Replay) { r.RecordingKey.PublicKey = b64(otherKey.Public().(ed25519.PublicKey)) })
				return contract.Fingerprint(otherKey.Public().(ed25519.PublicKey))
			},
			verdict: VerdictTampered, exit: ExitTampered,
		},
		{
			name: "gap covered by a signed loss record",
			opts: sessionOptions{withEnd: true, mediaCount: 2, videoLoss: true},
			mutate: func(t *testing.T, _ *testSession, dir string) string {
				editReplay(t, dir, func(r *Replay) { r.Video.Objects = r.Video.Objects[:2] })
				require.NoError(t, os.Remove(filepath.Join(dir, StoredObjectPath(contract.SeriesV, 2))))
				return ""
			},
			verdict: VerdictIncomplete, exit: ExitIncomplete,
		},
		{
			name:    "missing end record",
			opts:    sessionOptions{mediaCount: 2},
			mutate:  func(*testing.T, *testSession, string) string { return "" },
			verdict: VerdictIncomplete, exit: ExitIncomplete,
		},
		{
			name: "missing session key",
			mutate: func(t *testing.T, _ *testSession, dir string) string {
				require.NoError(t, os.Remove(filepath.Join(dir, SessionKeyFile)))
				return ""
			},
			verdict: VerdictIncomplete, exit: ExitIncomplete,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := tc.opts
			if opts == (sessionOptions{}) {
				opts = sessionOptions{withEnd: true, mediaCount: 2}
			}
			s := recordSession(t, opts)
			dir := s.write()
			fingerprint := s.fingerprint()
			if override := tc.mutate(t, s, dir); override != "" {
				fingerprint = override
			}
			report := verifyDir(t, dir, fingerprint)
			require.Equal(t, tc.verdict, report.Verdict, "findings: %+v", report.Findings)
			require.Equal(t, tc.exit, report.ExitCode())
			require.NotEmpty(t, report.Findings)
		})
	}
}
