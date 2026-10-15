package contract

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// Shared test vectors (CONTRACTS.md section 9). Go generates them from fixed inputs; TypeScript and the offline verifier
// must reproduce every hex value. Regenerate with: IWA_WRITE_VECTORS=<dir> go test ./packages/pam/webapp/contract/

const (
	vecProjectID = "6f1c2d3e-4a5b-4c6d-8e7f-90a1b2c3d4e5"
	vecSessionID = "8a0c6a4e-1f7b-4e0e-9a43-5d2a6f0b9c11"
)

func hx(b []byte) string { return hex.EncodeToString(b) }

func seed(b byte) []byte { return bytes.Repeat([]byte{b}, ed25519.SeedSize) }

type frameVector struct {
	Name        string `json:"name"`
	Type        uint8  `json:"type"`
	Flags       uint16 `json:"flags"`
	Seq         uint32 `json:"seq"`
	TimestampUs uint64 `json:"timestampUs"`
	PayloadHex  string `json:"payloadHex"`
	FrameHex    string `json:"frameHex"`
}

type eventVector struct {
	Type           uint16 `json:"type"`
	TypeName       string `json:"typeName"`
	Seq            uint64 `json:"seq"`
	WallTimeUnixMs int64  `json:"wallTimeUnixMs"`
	MonoElapsedUs  uint64 `json:"monoElapsedUs"`
	Body           string `json:"body"`
	PrevHashHex    string `json:"prevHashHex"`
	EnvelopeHex    string `json:"envelopeHex"`
	EventHashHex   string `json:"eventHashHex"`
}

type chainVector struct {
	Events            []eventVector `json:"events"`
	ChunkPlaintextHex string        `json:"chunkPlaintextHex"`
	ChainHeadHex      string        `json:"chainHeadHex"`
	FirstSeq          uint64        `json:"firstSeq"`
	LastSeq           uint64        `json:"lastSeq"`
}

type keyVector struct {
	RecordingSeedHex      string `json:"recordingSeedHex"`
	RecordingPublicKeyHex string `json:"recordingPublicKeyHex"`
	RecordingKeyID        string `json:"recordingKeyId"`
	RecordingFingerprint  string `json:"recordingFingerprint"`
	SessionSeedHex        string `json:"sessionSeedHex"`
	SessionPublicKeyHex   string `json:"sessionPublicKeyHex"`
	SessionKeyID          string `json:"sessionKeyId"`
	SessionID             string `json:"sessionId"`
	NotBeforeUnixMs       int64  `json:"notBeforeUnixMs"`
	NotAfterUnixMs        int64  `json:"notAfterUnixMs"`
	KeyCertHex            string `json:"keyCertHex"`
	KeyCertSigHex         string `json:"keyCertSigHex"`
}

type checkpointVector struct {
	Name                 string `json:"name"`
	Series               uint8  `json:"series"`
	Kind                 uint8  `json:"kind"`
	SessionID            string `json:"sessionId"`
	ProjectID            string `json:"projectId"`
	ObjectIndex          uint32 `json:"objectIndex"`
	FirstSeq             uint64 `json:"firstSeq"`
	LastSeq              uint64 `json:"lastSeq"`
	ChainHeadHex         string `json:"chainHeadHex"`
	SessionKeyHex        string `json:"sessionKeyHex"`
	IVHex                string `json:"ivHex"`
	AADHex               string `json:"aadHex"`
	PlaintextHex         string `json:"plaintextHex"`
	StoredObjectHex      string `json:"storedObjectHex"`
	PlaintextSHA256Hex   string `json:"plaintextSha256Hex"`
	CiphertextSHA256Hex  string `json:"ciphertextSha256Hex"`
	KeyCommitmentHex     string `json:"keyCommitmentHex"`
	MaskingPolicyVersion uint32 `json:"maskingPolicyVersion"`
	CreatedAtUnixMs      int64  `json:"createdAtUnixMs"`
	CheckpointHex        string `json:"checkpointHex"`
	SignatureHex         string `json:"signatureHex"`
	ObjectKey            string `json:"objectKey"`
	KeyPrefix            string `json:"keyPrefix"`
}

type shortcutCase struct {
	Name    string       `json:"name"`
	Events  []InputEvent `json:"events"`
	Kept    []InputEvent `json:"kept"`
	Dropped []string     `json:"droppedRules"`
}

type vectors struct {
	Frames      []frameVector      `json:"frames"`
	Chain       chainVector        `json:"chain"`
	Keys        keyVector          `json:"keys"`
	Checkpoints []checkpointVector `json:"checkpoints"`
	Shortcuts   []shortcutCase     `json:"shortcuts"`
}

func buildVectors(t *testing.T) vectors {
	var v vectors

	// Frames
	ack := Ack{AckSeq: 41, DecodeQueue: 2}.Marshal()
	meta, err := MarshalMetaPrefixed(RecSegmentMeta{SegmentIndex: 1, EndPtsUs: 10000000, FrameCount: 300, FramesCaptured: 300,
		SHA256: hx(sha256.New().Sum(nil))}, []byte("moof+mdat"))
	require.NoError(t, err)
	frames := []struct {
		name string
		f    Frame
	}{
		{"hello", Frame{Type: FrameHello, Payload: []byte(`{"protocol":1,"client":"infisical-web/1.0","decoders":{"vp9":true,"h264":true},"viewport":{"width":1280,"height":720,"devicePixelRatio":2}}`)}},
		{"video_config", Frame{Type: FrameVideoConfig, Seq: 0, TimestampUs: 0, Payload: []byte(`{"codec":"avc1.42E01F","format":"annexb","width":1280,"height":720,"framerate":30,"epoch":1}`)}},
		{"video_chunk_keyframe", Frame{Type: FrameVideoChunk, Flags: FlagKeyframe, Seq: 1, TimestampUs: 33333, Payload: []byte{0, 0, 0, 1, 0x67, 0x42, 0xe0, 0x1f}}},
		{"control_backend_error", Frame{Type: FrameControl, Flags: FlagOriginBackend, Seq: 7, TimestampUs: 1500000, Payload: []byte(`{"kind":"error","code":"tunnel_failed","message":"gateway unreachable","fatal":true}`)}},
		{"input_key", Frame{Type: FrameInput, Seq: 3, TimestampUs: 2000000, Payload: []byte(`{"events":[{"t":"key","action":"down","code":"KeyA","key":"a","mods":0,"repeat":false,"ts":1234.5}]}`)}},
		{"ack", Frame{Type: FrameAck, Seq: 4, TimestampUs: 2100000, Payload: ack}},
		{"keyframe_request", Frame{Type: FrameKeyframeRequest, Seq: 5, TimestampUs: 2200000, Payload: []byte{}}},
		{"rec_segment", Frame{Type: FrameRecSegment, Seq: 9, TimestampUs: 10000000, Payload: meta}},
	}
	for _, fr := range frames {
		f := fr.f
		v.Frames = append(v.Frames, frameVector{Name: fr.name, Type: uint8(f.Type), Flags: f.Flags, Seq: f.Seq,
			TimestampUs: f.TimestampUs, PayloadHex: hx(f.Payload), FrameHex: hx(f.Marshal())})
	}

	// Keys
	recPriv := ed25519.NewKeyFromSeed(seed(0x01))
	recPub := recPriv.Public().(ed25519.PublicKey)
	sesPriv := ed25519.NewKeyFromSeed(seed(0x02))
	sesPub := sesPriv.Public().(ed25519.PublicKey)
	sid := uuid.MustParse(vecSessionID)
	kc := KeyCert{SessionID: sid, NotBeforeUnixMs: 1760544000000, NotAfterUnixMs: 1760551200000, IssuerKeyID: KeyID(recPub)}
	copy(kc.SessionPublicKey[:], sesPub)
	kcSig := SignKeyCert(recPriv, &kc)
	sesKeyID := KeyID(sesPub)
	v.Keys = keyVector{
		RecordingSeedHex: hx(seed(0x01)), RecordingPublicKeyHex: hx(recPub), RecordingKeyID: KeyIDHex(recPub),
		RecordingFingerprint: Fingerprint(recPub), SessionSeedHex: hx(seed(0x02)), SessionPublicKeyHex: hx(sesPub),
		SessionKeyID: hx(sesKeyID[:]), SessionID: vecSessionID, NotBeforeUnixMs: kc.NotBeforeUnixMs,
		NotAfterUnixMs: kc.NotAfterUnixMs, KeyCertHex: hx(kc.Marshal()), KeyCertSigHex: hx(kcSig),
	}

	// Chain: session_open, l3_input, v_init, heartbeat
	initPlain := []byte("ftyp....moov....")
	initSum := sha256.Sum256(initPlain)
	bodies := []struct {
		t    EventType
		body string
	}{
		{EventSessionOpen, `{"sessionId":"` + vecSessionID + `","projectId":"` + vecProjectID + `","resourceType":"web-app","recordingKey":{"keyId":"` + KeyIDHex(recPub) + `","fingerprint":"` + Fingerprint(recPub) + `"}}`},
		{EventL3Input, `{"events":[{"t":"key","action":"down","code":"KeyA","key":"a","mods":0,"repeat":false,"ts":1234.5}],"dropped":[],"masked":false,"frameSeq":3}`},
		{EventVInit, `{"objectIndex":0,"sha256":"` + hx(initSum[:]) + `","bytes":16,"codec":"avc1.64001f","width":1280,"height":720,"timescale":90000}`},
		{EventHeartbeat, `{"lastSeq":2,"uptimeMs":30000,"viewerConnected":true}`},
	}
	chain := NewChain()
	var plain []byte
	var vInitSeq uint64
	var vInitHash [32]byte
	for i, b := range bodies {
		prev := chain.Head()
		e, raw, h := chain.Append(b.t, 1760544000000+int64(i)*1000, uint64(i)*1000000, []byte(b.body))
		if b.t == EventVInit {
			vInitSeq, vInitHash = e.Seq, h
		}
		plain = append(plain, raw...)
		v.Chain.Events = append(v.Chain.Events, eventVector{Type: uint16(e.Type), TypeName: e.Type.String(), Seq: e.Seq,
			WallTimeUnixMs: e.WallTimeUnixMs, MonoElapsedUs: e.MonoElapsedUs, Body: b.body, PrevHashHex: hx(prev[:]),
			EnvelopeHex: hx(raw), EventHashHex: hx(h[:])})
	}
	head := chain.Head()
	v.Chain.ChunkPlaintextHex = hx(plain)
	v.Chain.ChainHeadHex = hx(head[:])
	v.Chain.FirstSeq, v.Chain.LastSeq = 0, chain.NextSeq()-1

	// Checkpoints: E chunk 0 and V init 0
	sessionKey := bytes.Repeat([]byte{0x11}, 32)
	commit := KeyCommitment(sessionKey)
	mk := func(name string, series Series, kind CheckpointKind, idx uint32, first, last uint64, chainHead [32]byte, pt []byte, iv byte) checkpointVector {
		aad := BuildAAD(vecProjectID, vecSessionID, series, idx)
		ivb := bytes.Repeat([]byte{iv}, IVSize)
		stored, err := SealObject(sessionKey, ivb, pt, aad)
		require.NoError(t, err)
		ps, cs := sha256.Sum256(pt), sha256.Sum256(stored)
		cp := Checkpoint{Series: series, Kind: kind, SessionID: sid, ObjectIndex: idx, FirstSeq: first, LastSeq: last,
			ChainHead: chainHead, PlaintextSHA256: ps, CiphertextSHA256: cs, PlaintextBytes: uint64(len(pt)),
			CiphertextBytes: uint64(len(stored)), KeyCommitment: commit, MaskingPolicyVersion: 1, SignerKeyID: sesKeyID,
			CreatedAtUnixMs: 1760544010000}
		sig := SignCheckpoint(sesPriv, &cp)
		return checkpointVector{Name: name, Series: uint8(series), Kind: uint8(kind), SessionID: vecSessionID,
			ProjectID: vecProjectID, ObjectIndex: idx, FirstSeq: first, LastSeq: last, ChainHeadHex: hx(chainHead[:]),
			SessionKeyHex: hx(sessionKey), IVHex: hx(ivb), AADHex: hx(aad), PlaintextHex: hx(pt), StoredObjectHex: hx(stored),
			PlaintextSHA256Hex: hx(ps[:]), CiphertextSHA256Hex: hx(cs[:]), KeyCommitmentHex: hx(commit[:]),
			MaskingPolicyVersion: 1, CreatedAtUnixMs: cp.CreatedAtUnixMs, CheckpointHex: hx(cp.Marshal()),
			SignatureHex: hx(sig), KeyPrefix: "recordings",
			ObjectKey: ObjectKey("recordings", vecProjectID, vecSessionID, series, kind, idx)}
	}
	v.Checkpoints = append(v.Checkpoints,
		mk("e_chunk_0", SeriesE, KindEvents, 0, 0, chain.NextSeq()-1, head, plain, 0x21),
		mk("v_init_0", SeriesV, KindVideoInit, 0, vInitSeq, vInitSeq, vInitHash, initPlain, 0x22),
	)

	// Shortcuts
	cases := []shortcutCase{
		{Name: "ctrl_n_down_up_dropped", Events: []InputEvent{{T: "key", Action: "down", Code: "KeyN", Key: "n", Mods: ModCtrl}, {T: "key", Action: "up", Code: "KeyN", Key: "n", Mods: 0}}},
		{Name: "ctrl_shift_n_incognito_dropped", Events: []InputEvent{{T: "key", Action: "down", Code: "KeyN", Key: "N", Mods: ModCtrl | ModShift}}},
		{Name: "ctrl_c_kept", Events: []InputEvent{{T: "key", Action: "down", Code: "KeyC", Key: "c", Mods: ModCtrl}, {T: "key", Action: "up", Code: "KeyC", Key: "c", Mods: ModCtrl}}},
		{Name: "ctrl_shift_c_inspect_dropped", Events: []InputEvent{{T: "key", Action: "down", Code: "KeyC", Key: "C", Mods: ModCtrl | ModShift}}},
		{Name: "plain_typing_kept", Events: []InputEvent{{T: "key", Action: "down", Code: "KeyH", Key: "h"}, {T: "key", Action: "up", Code: "KeyH", Key: "h"}}},
		{Name: "f12_dropped", Events: []InputEvent{{T: "key", Action: "down", Code: "F12", Key: "F12"}}},
		{Name: "f5_kept", Events: []InputEvent{{T: "key", Action: "down", Code: "F5", Key: "F5"}}},
		{Name: "shift_escape_dropped", Events: []InputEvent{{T: "key", Action: "down", Code: "Escape", Key: "Escape", Mods: ModShift}}},
		{Name: "meta_any_dropped", Events: []InputEvent{{T: "key", Action: "down", Code: "KeyL", Key: "l", Mods: ModMeta}}},
		{Name: "ctrl_alt_f2_dropped", Events: []InputEvent{{T: "key", Action: "down", Code: "F2", Key: "F2", Mods: ModCtrl | ModAlt}}},
		{Name: "mouse_back_button_dropped", Events: []InputEvent{{T: "button", Action: "down", Button: 3, X: 10, Y: 10}, {T: "button", Action: "down", Button: 0, X: 10, Y: 10}}},
	}
	for _, c := range cases {
		kept, dropped := NewInputFilter().Filter(c.Events)
		c.Kept = kept
		if c.Kept == nil {
			c.Kept = []InputEvent{}
		}
		c.Dropped = []string{}
		for _, d := range dropped {
			c.Dropped = append(c.Dropped, d.Rule)
		}
		v.Shortcuts = append(v.Shortcuts, c)
	}
	return v
}

func vectorFiles(v vectors) map[string]any {
	return map[string]any{
		"frames.json":      v.Frames,
		"chain.json":       v.Chain,
		"keys.json":        v.Keys,
		"checkpoints.json": v.Checkpoints,
		"shortcuts.json":   v.Shortcuts,
	}
}

func TestVectorsMatchTestdata(t *testing.T) {
	v := buildVectors(t)
	if dir := os.Getenv("IWA_WRITE_VECTORS"); dir != "" {
		for _, d := range []string{dir, "testdata"} {
			require.NoError(t, os.MkdirAll(d, 0o755))
			for name, content := range vectorFiles(v) {
				b, err := json.MarshalIndent(content, "", "  ")
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(filepath.Join(d, name), append(b, '\n'), 0o644))
			}
		}
	}
	for name, content := range vectorFiles(v) {
		want, err := os.ReadFile(filepath.Join("testdata", name))
		require.NoError(t, err, "missing testdata; regenerate with IWA_WRITE_VECTORS")
		got, err := json.MarshalIndent(content, "", "  ")
		require.NoError(t, err)
		require.JSONEq(t, string(want), string(got), name)
	}
}

func TestVectorsVerify(t *testing.T) {
	v := buildVectors(t)

	for _, fv := range v.Frames {
		raw, _ := hex.DecodeString(fv.FrameHex)
		f, err := UnmarshalFrame(raw, MaxAgentPayload)
		require.NoError(t, err, fv.Name)
		require.Equal(t, fv.PayloadHex, hx(f.Payload))
		f2, err := ReadFrame(bytes.NewReader(raw), MaxAgentPayload)
		require.NoError(t, err)
		require.Equal(t, f.Seq, f2.Seq)
	}

	recPub, _ := hex.DecodeString(v.Keys.RecordingPublicKeyHex)
	kcBytes, _ := hex.DecodeString(v.Keys.KeyCertHex)
	kcSig, _ := hex.DecodeString(v.Keys.KeyCertSigHex)
	kc, err := VerifyKeyCert(recPub, kcBytes, kcSig)
	require.NoError(t, err)
	sesPub := ed25519.PublicKey(kc.SessionPublicKey[:])

	plain, _ := hex.DecodeString(v.Chain.ChunkPlaintextHex)
	head, last, err := VerifyChainSegment(plain, 0, [32]byte{})
	require.NoError(t, err)
	require.Equal(t, v.Chain.ChainHeadHex, hx(head[:]))
	require.Equal(t, v.Chain.LastSeq, last)

	for _, cv := range v.Checkpoints {
		cb, _ := hex.DecodeString(cv.CheckpointHex)
		sig, _ := hex.DecodeString(cv.SignatureHex)
		cp, err := VerifyCheckpoint(sesPub, cb, sig)
		require.NoError(t, err, cv.Name)
		key, _ := hex.DecodeString(cv.SessionKeyHex)
		stored, _ := hex.DecodeString(cv.StoredObjectHex)
		require.Equal(t, cp.CiphertextSHA256, sha256.Sum256(stored))
		pt, err := OpenObject(key, stored, BuildAAD(cv.ProjectID, cv.SessionID, cp.Series, cp.ObjectIndex))
		require.NoError(t, err)
		require.Equal(t, cp.PlaintextSHA256, sha256.Sum256(pt))
		require.Equal(t, cp.KeyCommitment, KeyCommitment(key))
	}
}

func TestTamperDetection(t *testing.T) {
	v := buildVectors(t)
	plain, _ := hex.DecodeString(v.Chain.ChunkPlaintextHex)
	tampered := append([]byte(nil), plain...)
	tampered[len(tampered)-3] ^= 0x01 // last body byte of the last event
	head, _, err := VerifyChainSegment(tampered, 0, [32]byte{})
	require.NoError(t, err)
	require.NotEqual(t, v.Chain.ChainHeadHex, hx(head[:]))

	// dropping an event in the middle breaks prevHash
	envs, raws, err := ParseEnvelopes(plain)
	require.NoError(t, err)
	require.Len(t, envs, 4)
	gap := append(append([]byte{}, raws[0]...), raws[2]...)
	_, _, err = VerifyChainSegment(gap, 0, [32]byte{})
	require.Error(t, err)

	cv := v.Checkpoints[0]
	cb, _ := hex.DecodeString(cv.CheckpointHex)
	sig, _ := hex.DecodeString(cv.SignatureHex)
	sesPub, _ := hex.DecodeString(v.Keys.SessionPublicKeyHex)
	cb[30] ^= 0x01
	_, err = VerifyCheckpoint(sesPub, cb, sig)
	require.Error(t, err)

	key, _ := hex.DecodeString(cv.SessionKeyHex)
	stored, _ := hex.DecodeString(cv.StoredObjectHex)
	_, err = OpenObject(key, stored, BuildAAD(cv.ProjectID, cv.SessionID, SeriesE, 1)) // wrong object index
	require.Error(t, err)
}

func TestFrameLimits(t *testing.T) {
	big := Frame{Type: FrameInput, Payload: make([]byte, MaxUpstreamPayload+1)}
	_, err := UnmarshalFrame(big.Marshal(), MaxUpstreamPayload)
	require.ErrorIs(t, err, ErrFrameTooLarge)
	bad := (&Frame{Type: FrameAck, Payload: Ack{}.Marshal()}).Marshal()
	bad[0] = 2
	_, err = UnmarshalFrame(bad, MaxUpstreamPayload)
	require.ErrorIs(t, err, ErrBadVersion)
	require.True(t, FrameHello.IsUpstream())
	require.True(t, FrameVideoChunk.IsDownstream())
	require.True(t, FrameRecSegment.IsAgentOnly())

	var meta RecSegmentMeta
	payload, err := MarshalMetaPrefixed(RecSegmentMeta{SegmentIndex: 3}, []byte("body"))
	require.NoError(t, err)
	body, err := UnmarshalMetaPrefixed(payload, &meta)
	require.NoError(t, err)
	require.Equal(t, 3, meta.SegmentIndex)
	require.Equal(t, "body", string(body))
}

func TestMonoFromPts(t *testing.T) {
	require.Equal(t, int64(61250000), MonoFromPts(1760545801250, 1760545800000, 60000000))
}

func TestChooseLiveCodec(t *testing.T) {
	var h ViewerHello
	h.Decoders.VP9, h.Decoders.H264 = true, true
	c, ok := ChooseLiveCodec(h, []string{"vp9", "h264"})
	require.True(t, ok)
	require.Equal(t, "vp9", c)
	c, ok = ChooseLiveCodec(h, []string{"h264"}) // shared encoder mode
	require.True(t, ok)
	require.Equal(t, "h264", c)
	h.Decoders.VP9, h.Decoders.H264 = false, false
	_, ok = ChooseLiveCodec(h, []string{"vp9", "h264"})
	require.False(t, ok)
}
