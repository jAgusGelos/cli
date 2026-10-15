package recorder

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/webapp/contract"
	"github.com/Infisical/infisical-merge/packages/pam/webapp/recorder/recordertest"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

const (
	testProject = "6f1c2d3e-4a5b-4c6d-8e7f-90a1b2c3d4e5"
	testSession = "8a0c6a4e-1f7b-4e0e-9a43-5d2a6f0b9c11"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newTestRecorder(t *testing.T, srv *recordertest.Server, clock *fakeClock) (*Recorder, []byte, ed25519.PrivateKey) {
	t.Helper()
	_, recKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	r, err := New(Options{
		SessionID: testSession, ProjectID: testProject, SessionKey: key, RecordingKey: recKey,
		ExpiresAt: clock.Now().Add(time.Hour), Backend: NewHTTPBackend(srv.URL, testSession, "tok", resty.New()),
		Now: clock.Now, Log: zerolog.Nop(), Retry: time.Millisecond,
	})
	require.NoError(t, err)
	return r, key, recKey
}

func TestRecordingKeyLoadOrCreate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	k1, err := LoadOrCreateRecordingKey(dir)
	require.NoError(t, err)
	st, err := os.Stat(filepath.Join(dir, RecordingKeyFile))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), st.Mode().Perm())
	k2, err := LoadOrCreateRecordingKey(dir)
	require.NoError(t, err)
	require.True(t, k1.Equal(k2))
	require.Regexp(t, `^SHA256:[A-Za-z0-9+/]{43}$`, contract.Fingerprint(k1.Public().(ed25519.PublicKey)))
}

func TestRecorderSignedSession(t *testing.T) {
	srv := recordertest.NewServer(testProject, "tok")
	defer srv.Close()
	clock := &fakeClock{t: time.UnixMilli(1760545800000)}
	r, key, recKey := newTestRecorder(t, srv, clock)

	require.NoError(t, r.Open(SessionOpen{GatewayID: "gw", StartURL: "https://app.corp.internal/", AllowedHosts: []string{"app.corp.internal"}}))
	_, err := r.Append(contract.EventLiveCodec, map[string]any{"codec": "h264"})
	require.NoError(t, err)

	initBody := []byte("ftyp-moov")
	require.NoError(t, r.RecInit(contract.RecInitMeta{Codec: contract.CodecStringH264Rec, Width: 1280, Height: 720, Timescale: 90000, PtsZeroUnixMs: 1760545800500}, initBody))
	seg := []byte("moof-mdat-1")
	sum := sha256.Sum256(seg)
	require.Error(t, r.RecSegment(contract.RecSegmentMeta{SegmentIndex: 1, SHA256: "00"}, seg), "sha256 mismatch must be refused")
	require.NoError(t, r.RecSegment(contract.RecSegmentMeta{SegmentIndex: 1, StartPtsUs: 0, EndPtsUs: 10_000_000, FrameCount: 300, SHA256: hex.EncodeToString(sum[:])}, seg))

	clock.Add(11 * time.Second)
	_, err = r.AppendAt(contract.EventL3Input, map[string]any{"events": []any{}}, clock.Now())
	require.NoError(t, err) // crosses the 10 s window: first E chunk sealed
	clock.Add(time.Second)
	_, err = r.Append(contract.EventL3Input, map[string]any{"events": []any{}})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, r.Close(ctx, "user_end"))
	require.NoError(t, r.Close(ctx, "error"), "close is idempotent")

	res, err := srv.Verify(key, testSession, recKey.Public().(ed25519.PublicKey))
	require.NoError(t, err)
	require.Equal(t, 2, res.EChunks)
	require.Len(t, res.VInits, 1)
	require.Equal(t, initBody, res.VInits[0])
	require.Len(t, res.VMedia, 1)
	require.Equal(t, seg, res.VMedia[0])

	last := res.Events[len(res.Events)-1]
	require.Equal(t, contract.EventSessionEnd, last.Type)
	var end sessionEndBody
	require.NoError(t, json.Unmarshal(last.Body, &end))
	require.Equal(t, last.Seq, end.FinalSeq)
	require.Equal(t, "user_end", end.Reason)
	require.Equal(t, uint32(2), end.VObjects)
	require.Equal(t, uint32(2), end.EChunks)

	segEv := res.ByType(contract.EventVSegment)
	require.Len(t, segEv, 1)
	var vs vSegmentBody
	require.NoError(t, json.Unmarshal(segEv[0].Body, &vs))
	require.Equal(t, int64(500_000), vs.MonoStartUs)
	require.Equal(t, int64(10_500_000), vs.MonoEndUs)

	// Upload order: open first, each object presign -> put -> checkpoint, end last; E checkpoints in index order.
	require.Equal(t, "open", srv.Order[0])
	require.Equal(t, "end", srv.Order[len(srv.Order)-1])
	require.Len(t, srv.Opens, 1)
	for _, p := range srv.Puts {
		require.Empty(t, p.Headers.Get("Authorization"))
		require.Equal(t, "*", p.Headers.Get("If-None-Match"))
	}
	for _, c := range srv.Checkpoints {
		require.NotEmpty(t, c.VersionID)
	}
	// Keys are erased after close.
	require.Equal(t, make([]byte, 32), r.sessionKey)
}

func TestRecorderTolerates404And412(t *testing.T) {
	srv := recordertest.NewServer(testProject, "tok")
	defer srv.Close()
	srv.FailOpen404 = true
	srv.Fail412["web-app/"+testProject+"/"+testSession+"/E/00000000.evt"] = true
	clock := &fakeClock{t: time.Now()}
	r, _, _ := newTestRecorder(t, srv, clock)
	require.NoError(t, r.Open(SessionOpen{}))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, r.Close(ctx, "user_end"))
	require.Contains(t, srv.Order, "put:E0")
	require.Contains(t, srv.Order, "end")
	require.Empty(t, srv.Checkpoints, "404 checkpoints are tolerated, not retried forever")
}

func TestRecorderHeartbeatAndOrderedCheckpointRetry(t *testing.T) {
	srv := recordertest.NewServer(testProject, "tok")
	defer srv.Close()
	srv.FailCheckpoint["E0"] = []int{500}
	srv.FailCheckpoint["E1"] = []int{422}
	clock := &fakeClock{t: time.UnixMilli(1760545800000)}
	r, key, recKey := newTestRecorder(t, srv, clock)
	r.o.ViewerConnected = func() bool { return false }
	r.o.StatePath = filepath.Join(t.TempDir(), "state.json")
	require.NoError(t, r.Open(SessionOpen{}))
	for i := 0; i < 7; i++ { // 70 s: two heartbeats, several E chunks
		clock.Add(10 * time.Second)
		require.NoError(t, r.Tick())
	}
	_, err := os.Stat(r.o.StatePath)
	require.NoError(t, err, "chain state persisted after a seal")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, r.Close(ctx, "user_end"))
	_, err = os.Stat(r.o.StatePath)
	require.True(t, os.IsNotExist(err), "state removed after a clean close")

	res, err := srv.Verify(key, testSession, recKey.Public().(ed25519.PublicKey))
	require.NoError(t, err, "all checkpoints accepted in order: %v", srv.Order)
	require.Contains(t, srv.Order, "refused:E0")
	require.Contains(t, srv.Order, "refused:E1")
	beats := res.ByType(contract.EventHeartbeat)
	require.Len(t, beats, 2)
	var hb heartbeatBody
	require.NoError(t, json.Unmarshal(beats[0].Body, &hb))
	require.False(t, hb.ViewerConnected)
	require.Equal(t, int64(30000), hb.UptimeMs)
	require.Equal(t, beats[0].Seq-1, hb.LastSeq)
	require.Equal(t, "end", srv.Order[len(srv.Order)-1])
}

func TestRecorderUploadBacklogLoss(t *testing.T) {
	srv := recordertest.NewServer(testProject, "tok")
	defer srv.Close()
	clock := &fakeClock{t: time.Now()}
	r, key, recKey := newTestRecorder(t, srv, clock)
	overflow := make(chan struct{}, 2)
	r.o.MaxBacklog = 10 // any V object overflows
	r.o.OnOverflow = func() { overflow <- struct{}{} }
	require.NoError(t, r.Open(SessionOpen{}))
	require.NoError(t, r.RecInit(contract.RecInitMeta{Codec: contract.CodecStringH264Rec}, []byte("an init segment bigger than ten bytes")))
	require.NoError(t, r.RecInit(contract.RecInitMeta{Codec: contract.CodecStringH264Rec}, []byte("another init segment over the limit")))
	select {
	case <-overflow:
	case <-time.After(5 * time.Second):
		t.Fatal("OnOverflow not called")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, r.Close(ctx, "recording_failed"))
	require.Len(t, overflow, 0, "OnOverflow is called once")
	res, err := srv.Verify(key, testSession, recKey.Public().(ed25519.PublicKey))
	require.NoError(t, err)
	require.Empty(t, res.VInits, "over-backlog V objects are not uploaded")
	losses := res.ByType(contract.EventLoss)
	require.Len(t, losses, 2)
	var l LossBody
	require.NoError(t, json.Unmarshal(losses[0].Body, &l))
	require.Equal(t, "V", l.Stream)
	require.Equal(t, "upload_backlog", l.Reason)
}
