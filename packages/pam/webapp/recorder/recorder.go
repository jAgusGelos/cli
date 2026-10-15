// Package recorder turns a Web App session into signed evidence (INF-WEBAPP CONTRACTS.md sections 5 and 6): every fact
// is a chained envelope, envelopes are sealed into E chunks, recording segments become V objects, and every object is
// encrypted with the session key, checkpointed with the per-session signer and uploaded through the backend.
package recorder

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/Infisical/infisical-merge/packages/pam/webapp/contract"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// EChunkInterval is how often pending events are sealed into an E chunk (CONTRACTS.md 6.5).
const EChunkInterval = 10 * time.Second

// HeartbeatInterval is the lifecycle heartbeat period (CONTRACTS.md 5.6).
const HeartbeatInterval = 30 * time.Second

// DefaultMaxBacklog is the per-session upload queue limit before V objects count as loss (CONTRACTS.md 4.3).
const DefaultMaxBacklog = 256 * 1024 * 1024

const (
	sessionKeyBytes       = 32
	queueCapacity         = 4096
	uploadAttempts        = 3
	endCheckpointAttempts = 5
	defaultRetryDelay     = time.Second
	defaultMaskingPolicy  = 1
	signerValidityExtra   = time.Hour

	lossReasonUploadBacklog = "upload_backlog"
)

// Upload operations, as logged and as named in withRetry's 404 tolerance.
const (
	opOpen       = "open"
	opPresign    = "presign"
	opPut        = "put"
	opCheckpoint = "checkpoint"
	opEnd        = "end"
)

// objectKindNames are the presign kinds per checkpoint kind (CONTRACTS.md 6.8).
var objectKindNames = map[contract.CheckpointKind]string{
	contract.KindEvents:     "events",
	contract.KindVideoInit:  "init",
	contract.KindVideoMedia: "media",
}

var ErrClosed = errors.New("recorder: closed")

type Options struct {
	SessionID            string
	ProjectID            string
	SessionKey           []byte // 32-byte AES-256 recording key of the session (copied, zeroed at Close)
	RecordingKey         ed25519.PrivateKey
	ExpiresAt            time.Time
	Backend              Backend
	MaskingPolicyVersion uint32
	// Scrub replaces vaulted secrets in an event body before it is chained (CONTRACTS.md 5.3b). Nil: no secrets.
	Scrub func([]byte) []byte
	Now   func() time.Time
	Log   zerolog.Logger
	// Retry is the delay between upload attempts (default 1 s).
	Retry time.Duration
	// ViewerConnected feeds heartbeat.viewerConnected. Nil: true.
	ViewerConnected func() bool
	// OnOverflow is called (once, on its own goroutine) when the upload backlog forced a V loss record; the session
	// applies the template overflow policy.
	OnOverflow func()
	// MaxBacklog bounds the queued upload bytes (default 256 MiB).
	MaxBacklog int64
	// StatePath, when set, receives the chain state (next seq, head, object counters) after every seal, so a restart
	// can tell where the chain stopped (CONTRACTS.md 6.2).
	StatePath string
}

// SessionOpen is the session_open body (CONTRACTS.md 5.6). The recorder fills the key fields.
type SessionOpen struct {
	SessionID            string        `json:"sessionId"`
	ProjectID            string        `json:"projectId"`
	AccountID            string        `json:"accountId"`
	UserID               string        `json:"userId"`
	GatewayID            string        `json:"gatewayId"`
	ResourceType         string        `json:"resourceType"`
	StartURL             string        `json:"startUrl"`
	AllowedHosts         []string      `json:"allowedHosts"`
	Runner               RunnerInfo    `json:"runner"`
	RecordingKey         RecordingInfo `json:"recordingKey"`
	SessionKeyCert       string        `json:"sessionKeyCert"`
	SessionKeyCertSig    string        `json:"sessionKeyCertSig"`
	MaskingPolicyVersion uint32        `json:"maskingPolicyVersion"`
	LiveCodec            *string       `json:"liveCodec"`
	StartedAt            string        `json:"startedAt"`
}

type RunnerInfo struct {
	Image string `json:"image"`
	IP    string `json:"ip"`
}

type RecordingInfo struct {
	KeyID       string `json:"keyId"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"publicKey"`
}

type vInitBody struct {
	ObjectIndex uint32 `json:"objectIndex"`
	SHA256      string `json:"sha256"`
	Bytes       int    `json:"bytes"`
	Codec       string `json:"codec"`
	Width       int    `json:"width"`
	Height      int    `json:"height"`
	Timescale   int    `json:"timescale"`
}

type vSegmentBody struct {
	ObjectIndex   uint32 `json:"objectIndex"`
	InitIndex     uint32 `json:"initIndex"`
	SegmentIndex  int    `json:"segmentIndex"`
	SHA256        string `json:"sha256"`
	Bytes         int    `json:"bytes"`
	StartPtsUs    int64  `json:"startPtsUs"`
	EndPtsUs      int64  `json:"endPtsUs"`
	MonoStartUs   int64  `json:"monoStartUs"`
	MonoEndUs     int64  `json:"monoEndUs"`
	FirstFrame    int64  `json:"firstFrame"`
	FrameCount    int    `json:"frameCount"`
	FramesDropped int    `json:"framesDropped"`
}

type heartbeatBody struct {
	LastSeq         uint64 `json:"lastSeq"`
	UptimeMs        int64  `json:"uptimeMs"`
	ViewerConnected bool   `json:"viewerConnected"`
}

// LossBody is the lifecycle loss event (CONTRACTS.md 5.6); times on the session monotonic clock.
type LossBody struct {
	Stream string `json:"stream"`
	FromUs int64  `json:"fromUs"`
	ToUs   int64  `json:"toUs"`
	Count  int    `json:"count"`
	Reason string `json:"reason"`
}

type sessionEndBody struct {
	Reason   string `json:"reason"`
	FinalSeq uint64 `json:"finalSeq"`
	VObjects uint32 `json:"vObjects"`
	EChunks  uint32 `json:"eChunks"`
}

// job is one upload unit; jobs run strictly in queue order.
type job struct {
	open       *OpenRequest
	end        *EndRequest
	series     contract.Series
	kind       contract.CheckpointKind
	index      uint32
	stored     []byte
	checkpoint []byte
	signature  []byte
}

type Recorder struct {
	o           Options
	sessionUUID [16]byte
	sessionKey  []byte
	commitment  [32]byte
	signer      *SessionSigner
	log         zerolog.Logger

	mu          sync.Mutex
	chain       *contract.Chain
	opened      bool
	closed      bool
	openWall    time.Time
	pending     []byte
	pendingFrom uint64
	eNext       uint32
	vNext       uint32
	initIndex   int64 // -1 until the first REC_INIT
	ptsZeroMs   int64
	lastSeal    time.Time
	lastBeat    time.Time
	overflowed  bool

	queued    atomic.Int64
	cpBacklog []CheckpointRequest // refused checkpoints, uploader goroutine only
	queue     chan job
	done      chan struct{}
	warned    map[string]bool
	warnedMu  sync.Mutex
}

func New(o Options) (*Recorder, error) {
	if len(o.SessionKey) != sessionKeyBytes {
		return nil, fmt.Errorf("recorder: session key must be 32 bytes, got %d", len(o.SessionKey))
	}
	if o.Backend == nil || o.RecordingKey == nil {
		return nil, errors.New("recorder: backend and recording key are required")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Retry == 0 {
		o.Retry = defaultRetryDelay
	}
	if o.MaxBacklog == 0 {
		o.MaxBacklog = DefaultMaxBacklog
	}
	if o.MaskingPolicyVersion == 0 {
		o.MaskingPolicyVersion = defaultMaskingPolicy
	}
	id, err := uuid.Parse(o.SessionID)
	if err != nil {
		return nil, fmt.Errorf("recorder: session id: %w", err)
	}
	now := o.Now()
	signer, err := NewSessionSigner(o.RecordingKey, o.SessionID, now, o.ExpiresAt.Add(signerValidityExtra))
	if err != nil {
		return nil, err
	}
	key := append([]byte(nil), o.SessionKey...)
	return &Recorder{
		o:           o,
		sessionUUID: id,
		sessionKey:  key,
		commitment:  contract.KeyCommitment(key),
		signer:      signer,
		log:         o.Log,
		chain:       contract.NewChain(),
		initIndex:   -1,
		queue:       make(chan job, queueCapacity),
		done:        make(chan struct{}),
		warned:      map[string]bool{},
	}, nil
}

// Open records session_open (seq 0) and starts the uploader. The first upload job registers the keys with the backend.
func (r *Recorder) Open(info SessionOpen) error {
	recPub := r.o.RecordingKey.Public().(ed25519.PublicKey)
	r.mu.Lock()
	if r.opened {
		r.mu.Unlock()
		return errors.New("recorder: already open")
	}
	r.opened = true
	r.openWall = r.o.Now()
	r.lastSeal = r.openWall
	r.lastBeat = r.openWall
	info.SessionID = r.o.SessionID
	info.ProjectID = r.o.ProjectID
	info.ResourceType = session.ResourceTypeWebApp
	info.RecordingKey = RecordingInfo{
		KeyID:       contract.KeyIDHex(recPub),
		Fingerprint: contract.Fingerprint(recPub),
		PublicKey:   base64.StdEncoding.EncodeToString(recPub),
	}
	info.SessionKeyCert = base64.StdEncoding.EncodeToString(r.signer.Cert)
	info.SessionKeyCertSig = base64.StdEncoding.EncodeToString(r.signer.CertSig)
	info.MaskingPolicyVersion = r.o.MaskingPolicyVersion
	info.StartedAt = r.openWall.UTC().Format(time.RFC3339Nano)
	if info.AllowedHosts == nil {
		info.AllowedHosts = []string{}
	}
	_, err := r.appendLocked(contract.EventSessionOpen, info, r.openWall)
	r.mu.Unlock()
	if err != nil {
		return err
	}
	go r.uploader()
	r.queue <- job{open: &OpenRequest{
		RecordingPublicKey: base64.StdEncoding.EncodeToString(recPub),
		Fingerprint:        contract.Fingerprint(recPub),
		KeyCert:            base64.StdEncoding.EncodeToString(r.signer.Cert),
		KeyCertSig:         base64.StdEncoding.EncodeToString(r.signer.CertSig),
	}}
	return nil
}

// Append records an event stamped now.
func (r *Recorder) Append(t contract.EventType, body any) (uint64, error) {
	return r.AppendAt(t, body, r.o.Now())
}

// AppendAt records an event stamped with the given arrival time (L3 stamps, CONTRACTS.md 5.4).
func (r *Recorder) AppendAt(t contract.EventType, body any, at time.Time) (uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.opened {
		return 0, errors.New("recorder: not open")
	}
	seq, err := r.appendLocked(t, body, at)
	if err != nil {
		return 0, err
	}
	return seq, r.sealIfDueLocked()
}

func (r *Recorder) appendLocked(t contract.EventType, body any, at time.Time) (uint64, error) {
	if r.closed {
		return 0, ErrClosed
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	if r.o.Scrub != nil {
		raw = r.o.Scrub(raw)
	}
	if len(raw) > contract.MaxEnvelopeBody {
		return 0, fmt.Errorf("recorder: %s body of %d bytes exceeds the envelope limit", t, len(raw))
	}
	mono := at.Sub(r.openWall)
	if mono < 0 {
		mono = 0
	}
	if len(r.pending) == 0 {
		r.pendingFrom = r.chain.NextSeq()
	}
	env, envBytes, _ := r.chain.Append(t, at.UnixMilli(), uint64(mono.Microseconds()), raw)
	r.pending = append(r.pending, envBytes...)
	return env.Seq, nil
}

func (r *Recorder) sealIfDueLocked() error {
	if r.o.Now().Sub(r.lastSeal) < EChunkInterval {
		return nil
	}
	return r.sealEventsLocked()
}

// Tick records the 30 s heartbeat when due and seals an E chunk when the 10 s window elapsed.
func (r *Recorder) Tick() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || !r.opened {
		return nil
	}
	now := r.o.Now()
	if now.Sub(r.lastBeat) >= HeartbeatInterval {
		r.lastBeat = now
		connected := true
		if r.o.ViewerConnected != nil {
			connected = r.o.ViewerConnected()
		}
		body := heartbeatBody{LastSeq: r.chain.NextSeq() - 1, UptimeMs: now.Sub(r.openWall).Milliseconds(), ViewerConnected: connected}
		if _, err := r.appendLocked(contract.EventHeartbeat, body, now); err != nil {
			return err
		}
	}
	return r.sealIfDueLocked()
}

// MonoUs returns t on the session monotonic clock (microseconds since session_open).
func (r *Recorder) MonoUs(t time.Time) int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return t.Sub(r.openWall).Microseconds()
}

// PtsMonoUs maps a recording PTS of the current init onto the session monotonic clock (CONTRACTS.md 5.2).
func (r *Recorder) PtsMonoUs(ptsUs int64) int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return contract.MonoFromPts(r.ptsZeroMs, r.openWall.UnixMilli(), ptsUs)
}

// Loss records a lifecycle loss event.
func (r *Recorder) Loss(l LossBody) error {
	_, err := r.Append(contract.EventLoss, l)
	return err
}

// backlogFullLocked records a V loss when the upload queue is over its limit, and reports whether the object must be
// dropped. The first overflow calls OnOverflow.
func (r *Recorder) backlogFullLocked(size int, fromUs, toUs int64) (bool, error) {
	if r.queued.Load()+int64(size) <= r.o.MaxBacklog {
		return false, nil
	}
	if _, err := r.appendLocked(contract.EventLoss, LossBody{Stream: contract.SeriesV.Letter(), FromUs: fromUs, ToUs: toUs, Count: 1, Reason: lossReasonUploadBacklog}, r.o.Now()); err != nil {
		return true, err
	}
	if !r.overflowed {
		r.overflowed = true
		if r.o.OnOverflow != nil {
			go r.o.OnOverflow()
		}
	}
	return true, nil
}

func (r *Recorder) sealEventsLocked() error {
	r.lastSeal = r.o.Now()
	if len(r.pending) == 0 {
		return nil
	}
	plaintext := r.pending
	r.pending = nil
	idx := r.eNext
	r.eNext++
	return r.sealObjectLocked(contract.SeriesE, contract.KindEvents, idx, plaintext, r.pendingFrom, r.chain.NextSeq()-1, r.chain.Head())
}

func (r *Recorder) sealObjectLocked(series contract.Series, kind contract.CheckpointKind, idx uint32, plaintext []byte, firstSeq, lastSeq uint64, head [32]byte) error {
	aad := contract.BuildAAD(r.o.ProjectID, r.o.SessionID, series, idx)
	stored, err := contract.SealObject(r.sessionKey, nil, plaintext, aad)
	if err != nil {
		return err
	}
	cp := &contract.Checkpoint{
		Series:               series,
		Kind:                 kind,
		SessionID:            r.sessionUUID,
		ObjectIndex:          idx,
		FirstSeq:             firstSeq,
		LastSeq:              lastSeq,
		ChainHead:            head,
		PlaintextSHA256:      sha256.Sum256(plaintext),
		CiphertextSHA256:     sha256.Sum256(stored),
		PlaintextBytes:       uint64(len(plaintext)),
		CiphertextBytes:      uint64(len(stored)),
		KeyCommitment:        r.commitment,
		MaskingPolicyVersion: r.o.MaskingPolicyVersion,
		SignerKeyID:          r.signer.KeyID,
		CreatedAtUnixMs:      r.o.Now().UnixMilli(),
	}
	r.queued.Add(int64(len(stored)))
	r.queue <- job{series: series, kind: kind, index: idx, stored: stored, checkpoint: cp.Marshal(), signature: r.signer.sign(cp)}
	r.persistLocked()
	return nil
}

type chainState struct {
	NextSeq uint64 `json:"nextSeq"`
	Head    string `json:"head"`
	ENext   uint32 `json:"eNext"`
	VNext   uint32 `json:"vNext"`
}

func (r *Recorder) persistLocked() {
	if r.o.StatePath == "" {
		return
	}
	if err := r.writeStateLocked(); err != nil {
		r.log.Warn().Err(err).Str("path", r.o.StatePath).Msg("Web App recorder chain state not persisted")
	}
}

func (r *Recorder) writeStateLocked() error {
	head := r.chain.Head()
	b, err := json.Marshal(chainState{NextSeq: r.chain.NextSeq(), Head: hex.EncodeToString(head[:]), ENext: r.eNext, VNext: r.vNext})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(r.o.StatePath), 0o700); err != nil {
		return err
	}
	tmp := r.o.StatePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.o.StatePath)
}

// RecInit turns a REC_INIT into a V init object and its v_init event (CONTRACTS.md 6.6).
func (r *Recorder) RecInit(meta contract.RecInitMeta, body []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.opened || r.closed {
		return ErrClosed
	}
	nowUs := r.o.Now().Sub(r.openWall).Microseconds()
	if full, err := r.backlogFullLocked(len(body), nowUs, nowUs); full || err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	idx := r.vNext
	r.vNext++
	seq, err := r.appendLocked(contract.EventVInit, vInitBody{
		ObjectIndex: idx, SHA256: hex.EncodeToString(sum[:]), Bytes: len(body),
		Codec: meta.Codec, Width: meta.Width, Height: meta.Height, Timescale: meta.Timescale,
	}, r.o.Now())
	if err != nil {
		return err
	}
	r.initIndex = int64(idx)
	r.ptsZeroMs = meta.PtsZeroUnixMs
	if err := r.sealObjectLocked(contract.SeriesV, contract.KindVideoInit, idx, body, seq, seq, r.chain.Head()); err != nil {
		return err
	}
	return r.sealIfDueLocked()
}

// RecSegment turns a REC_SEGMENT into a V media object and its v_segment event. The meta sha256 must match the body.
func (r *Recorder) RecSegment(meta contract.RecSegmentMeta, body []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.opened || r.closed {
		return ErrClosed
	}
	if r.initIndex < 0 {
		return errors.New("recorder: REC_SEGMENT before REC_INIT")
	}
	sum := sha256.Sum256(body)
	sumHex := hex.EncodeToString(sum[:])
	if meta.SHA256 != sumHex {
		return fmt.Errorf("recorder: segment %d sha256 mismatch", meta.SegmentIndex)
	}
	openMs := r.openWall.UnixMilli()
	if full, err := r.backlogFullLocked(len(body), contract.MonoFromPts(r.ptsZeroMs, openMs, meta.StartPtsUs), contract.MonoFromPts(r.ptsZeroMs, openMs, meta.EndPtsUs)); full || err != nil {
		return err
	}
	idx := r.vNext
	r.vNext++
	seq, err := r.appendLocked(contract.EventVSegment, vSegmentBody{
		ObjectIndex: idx, InitIndex: uint32(r.initIndex), SegmentIndex: meta.SegmentIndex, SHA256: sumHex, Bytes: len(body),
		StartPtsUs: meta.StartPtsUs, EndPtsUs: meta.EndPtsUs,
		MonoStartUs: contract.MonoFromPts(r.ptsZeroMs, openMs, meta.StartPtsUs),
		MonoEndUs:   contract.MonoFromPts(r.ptsZeroMs, openMs, meta.EndPtsUs),
		FirstFrame:  meta.FirstFrame, FrameCount: meta.FrameCount, FramesDropped: meta.FramesDropped,
	}, r.o.Now())
	if err != nil {
		return err
	}
	if err := r.sealObjectLocked(contract.SeriesV, contract.KindVideoMedia, idx, body, seq, seq, r.chain.Head()); err != nil {
		return err
	}
	return r.sealIfDueLocked()
}

// Close records session_end as the last event, seals the last E chunk, waits for the uploads (bounded by ctx), calls
// the backend end route and erases the session keys. It is idempotent; only the first reason is recorded.
func (r *Recorder) Close(ctx context.Context, reason string) error {
	r.mu.Lock()
	if r.closed || !r.opened {
		r.mu.Unlock()
		return nil
	}
	finalSeq := r.chain.NextSeq()
	eChunks := r.eNext + 1
	_, err := r.appendLocked(contract.EventSessionEnd, sessionEndBody{Reason: reason, FinalSeq: finalSeq, VObjects: r.vNext, EChunks: eChunks}, r.o.Now())
	if err == nil {
		err = r.sealEventsLocked()
	}
	r.closed = true
	r.queue <- job{end: &EndRequest{FinalSeq: finalSeq, Reason: reason}}
	close(r.queue)
	r.mu.Unlock()

	select {
	case <-r.done:
	case <-ctx.Done():
		r.log.Error().Msg("Web App recorder: uploads still pending at close deadline")
	}
	r.erase()
	if r.o.StatePath != "" {
		_ = os.Remove(r.o.StatePath)
	}
	return err
}

func (r *Recorder) erase() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.sessionKey {
		r.sessionKey[i] = 0
	}
	r.signer.Erase()
}

// uploader drains the queue in order: open, then objects (presign, PUT, checkpoint), then end.
func (r *Recorder) uploader() {
	defer close(r.done)
	ctx := context.Background()
	for j := range r.queue {
		switch {
		case j.open != nil:
			r.withRetry(opOpen, func() error { return r.o.Backend.Open(ctx, *j.open) })
		case j.end != nil:
			// The end call follows the last checkpoint: resubmit what the backend refused first.
			for attempt := 0; attempt < endCheckpointAttempts && len(r.cpBacklog) > 0; attempt++ {
				if attempt > 0 {
					time.Sleep(r.o.Retry)
				}
				r.flushCheckpoints(ctx)
			}
			if len(r.cpBacklog) > 0 {
				r.log.Error().Int("checkpoints", len(r.cpBacklog)).Msg("Web App checkpoints still refused at session end")
			}
			r.withRetry(opEnd, func() error { return r.o.Backend.End(ctx, *j.end) })
		default:
			r.uploadObject(ctx, j)
			r.queued.Add(-int64(len(j.stored)))
		}
	}
}

// flushCheckpoints resubmits refused checkpoints in order and stops at the first one still refused (E checkpoints
// must reach the backend in objectIndex order, CONTRACTS.md 6.9).
func (r *Recorder) flushCheckpoints(ctx context.Context) {
	for len(r.cpBacklog) > 0 {
		if err := r.o.Backend.SubmitCheckpoint(ctx, r.cpBacklog[0]); err != nil && statusOf(err) != http.StatusNotFound {
			r.log.Warn().Err(err).Msg("Web App checkpoint resubmission refused")
			return
		}
		r.cpBacklog = r.cpBacklog[1:]
	}
}

func (r *Recorder) uploadObject(ctx context.Context, j job) {
	kind := objectKindNames[j.kind]
	ctSum := sha256.Sum256(j.stored)
	var presigned *PresignResponse
	if !r.withRetry(opPresign, func() error {
		p, err := r.o.Backend.Presign(ctx, PresignRequest{
			Series: j.series.Letter(), ObjectIndex: j.index, Kind: kind,
			CiphertextBytes: len(j.stored), CiphertextSha256: base64.StdEncoding.EncodeToString(ctSum[:]),
		})
		presigned = p
		return err
	}) {
		return
	}
	var versionID string
	if !r.withRetry(opPut, func() error {
		v, err := r.o.Backend.Put(ctx, presigned, j.stored)
		if errors.Is(err, ErrPreconditionFailed) {
			r.log.Warn().Str("series", j.series.Letter()).Uint32("objectIndex", j.index).Msg("Web App object already exists, submitting checkpoint anyway")
			return nil
		}
		versionID = v
		return err
	}) {
		return
	}
	r.log.Info().Str("series", j.series.Letter()).Uint32("objectIndex", j.index).Int("bytes", len(j.stored)).Msg("Web App object uploaded")
	req := CheckpointRequest{
		Checkpoint: base64.StdEncoding.EncodeToString(j.checkpoint),
		Signature:  base64.StdEncoding.EncodeToString(j.signature),
		ObjectKey:  presigned.ObjectKey,
		VersionID:  versionID,
	}
	r.flushCheckpoints(ctx)
	if len(r.cpBacklog) > 0 {
		r.cpBacklog = append(r.cpBacklog, req)
		return
	}
	if !r.withRetry(opCheckpoint, func() error { return r.o.Backend.SubmitCheckpoint(ctx, req) }) {
		r.cpBacklog = append(r.cpBacklog, req)
	}
}

// withRetry runs fn up to uploadAttempts times on network errors and 5xx. A 404 on open, checkpoint or end is tolerated with one
// warning per operation (the backend may land its routes in stages); other 4xx are logged as errors.
func (r *Recorder) withRetry(op string, fn func() error) bool {
	var err error
	for attempt := 0; attempt < uploadAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(r.o.Retry)
		}
		err = fn()
		if err == nil {
			return true
		}
		status := statusOf(err)
		if status == http.StatusNotFound && op != opPresign && op != opPut {
			r.warnOnce(op, err)
			return true
		}
		if status >= http.StatusBadRequest && status < http.StatusInternalServerError {
			break
		}
	}
	r.log.Error().Err(err).Str("op", op).Msg("Web App recording upload failed")
	return false
}

func (r *Recorder) warnOnce(op string, err error) {
	r.warnedMu.Lock()
	defer r.warnedMu.Unlock()
	if r.warned[op] {
		return
	}
	r.warned[op] = true
	r.log.Warn().Err(err).Str("op", op).Msg("Web App backend route not available yet, continuing")
}
