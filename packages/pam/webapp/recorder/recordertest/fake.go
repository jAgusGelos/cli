// Package recordertest provides a fake Infisical backend plus a fake S3 for Web App recorder tests, and a verifier that
// checks stored objects the way a replay client would (CONTRACTS.md 6.7).
package recordertest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"

	"github.com/Infisical/infisical-merge/packages/pam/webapp/contract"
)

type Checkpoint struct {
	Raw       []byte
	Signature []byte
	ObjectKey string
	VersionID string
	Parsed    *contract.Checkpoint
}

type Put struct {
	Key     string
	Headers http.Header
	Body    []byte
}

// Server is a fake backend (CONTRACTS.md 6.9) and S3 (6.8) on one httptest server.
type Server struct {
	*httptest.Server
	ProjectID   string
	UploadToken string

	mu          sync.Mutex
	Opens       []map[string]string
	Objects     map[string][]byte
	Puts        []Put
	Checkpoints []Checkpoint
	Ends        []map[string]any
	Order       []string // "open", "presign:E0", "put:E0", "checkpoint:E0", "end"
	versions    int
	// FailOpen404 makes /open and /checkpoints answer 404 (backend not merged yet).
	FailOpen404 bool
	// Fail412 makes the next PUT of this key answer 412.
	Fail412 map[string]bool
	// FailCheckpoint answers the next checkpoints of "E1", "V0", ... with these statuses (422 carries seq_gap).
	FailCheckpoint map[string][]int
}

func NewServer(projectID, uploadToken string) *Server {
	s := &Server{ProjectID: projectID, UploadToken: uploadToken, Objects: map[string][]byte{}, Fail412: map[string]bool{}, FailCheckpoint: map[string][]int{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/pam/sessions/{id}/web-app/open", s.auth(s.open))
	mux.HandleFunc("POST /v1/pam/sessions/{id}/web-app/objects/presign", s.auth(s.presign))
	mux.HandleFunc("POST /v1/pam/sessions/{id}/web-app/checkpoints", s.auth(s.checkpoint))
	mux.HandleFunc("POST /v1/pam/sessions/{id}/web-app/end", s.auth(s.end))
	mux.HandleFunc("PUT /s3/{key...}", s.put)
	s.Server = httptest.NewServer(mux)
	return s
}

func (s *Server) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Gateway-Upload-Token") != s.UploadToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

func (s *Server) record(op string) {
	s.Order = append(s.Order, op)
}

func (s *Server) open(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.FailOpen404 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	var body map[string]string
	_ = json.NewDecoder(r.Body).Decode(&body)
	s.Opens = append(s.Opens, body)
	s.record("open")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func ext(kind string) string {
	switch kind {
	case "init":
		return "init.mp4"
	case "media":
		return "m4s"
	}
	return "evt"
}

func (s *Server) presign(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Series           string `json:"series"`
		ObjectIndex      uint32 `json:"objectIndex"`
		Kind             string `json:"kind"`
		CiphertextBytes  int    `json:"ciphertextBytes"`
		CiphertextSha256 string `json:"ciphertextSha256"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	key := fmt.Sprintf("web-app/%s/%s/%s/%08d.%s", s.ProjectID, r.PathValue("id"), req.Series, req.ObjectIndex, ext(req.Kind))
	s.mu.Lock()
	s.record(fmt.Sprintf("presign:%s%d", req.Series, req.ObjectIndex))
	s.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]any{
		"url": s.URL + "/s3/" + key, "objectKey": key, "method": "PUT", "expiresInSeconds": 300,
		"headers": map[string]string{"x-amz-checksum-sha256": req.CiphertextSha256, "If-None-Match": "*"},
	})
}

func (s *Server) put(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	body, _ := io.ReadAll(r.Body)
	sum := sha256.Sum256(body)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Puts = append(s.Puts, Put{Key: key, Headers: r.Header.Clone(), Body: body})
	s.record("put:" + seriesIndex(key))
	if r.Header.Get("x-amz-checksum-sha256") != base64.StdEncoding.EncodeToString(sum[:]) ||
		r.Header.Get("If-None-Match") != "*" || r.ContentLength != int64(len(body)) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if r.Header.Get("Authorization") != "" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if _, exists := s.Objects[key]; exists || s.Fail412[key] {
		delete(s.Fail412, key)
		w.WriteHeader(http.StatusPreconditionFailed)
		return
	}
	s.Objects[key] = body
	s.versions++
	w.Header().Set("x-amz-version-id", fmt.Sprintf("v%d", s.versions))
	w.WriteHeader(http.StatusOK)
}

func seriesIndex(key string) string {
	parts := strings.Split(key, "/")
	if len(parts) < 2 {
		return key
	}
	file := parts[len(parts)-1]
	n := strings.TrimLeft(strings.SplitN(file, ".", 2)[0], "0")
	if n == "" {
		n = "0"
	}
	return parts[len(parts)-2] + n
}

func (s *Server) checkpoint(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Checkpoint string `json:"checkpoint"`
		Signature  string `json:"signature"`
		ObjectKey  string `json:"objectKey"`
		VersionID  string `json:"versionId"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.FailOpen404 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	raw, _ := base64.StdEncoding.DecodeString(req.Checkpoint)
	sig, _ := base64.StdEncoding.DecodeString(req.Signature)
	cp, err := contract.UnmarshalCheckpoint(raw)
	if err != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}
	id := cp.Series.Letter() + fmt.Sprint(cp.ObjectIndex)
	if fails := s.FailCheckpoint[id]; len(fails) > 0 {
		s.FailCheckpoint[id] = fails[1:]
		s.record("refused:" + id)
		w.WriteHeader(fails[0])
		_ = json.NewEncoder(w).Encode(map[string]string{"code": "seq_gap"})
		return
	}
	// E checkpoints must arrive in objectIndex order.
	if cp.Series == contract.SeriesE {
		want := uint32(0)
		for _, c := range s.Checkpoints {
			if c.Parsed.Series == contract.SeriesE {
				want++
			}
		}
		if cp.ObjectIndex != want {
			s.record("seq_gap:" + id)
			w.WriteHeader(http.StatusUnprocessableEntity)
			_ = json.NewEncoder(w).Encode(map[string]string{"code": "seq_gap"})
			return
		}
	}
	s.Checkpoints = append(s.Checkpoints, Checkpoint{Raw: raw, Signature: sig, ObjectKey: req.ObjectKey, VersionID: req.VersionID, Parsed: cp})
	s.record(fmt.Sprintf("checkpoint:%s%d", cp.Series.Letter(), cp.ObjectIndex))
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]bool{"accepted": true})
}

func (s *Server) end(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Ends = append(s.Ends, body)
	s.record("end")
	w.WriteHeader(http.StatusOK)
}

// Snapshot returns copies of the recorded checkpoints and objects.
func (s *Server) Snapshot() ([]Checkpoint, map[string][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	objs := make(map[string][]byte, len(s.Objects))
	for k, v := range s.Objects {
		objs[k] = v
	}
	return append([]Checkpoint(nil), s.Checkpoints...), objs
}

// Event is one verified envelope.
type Event struct {
	contract.Envelope
	Hash [32]byte
}

// Result is what a verified session contains.
type Result struct {
	Events  []Event
	VInits  [][]byte
	VMedia  [][]byte
	EChunks int
}

func (r *Result) ByType(t contract.EventType) []Event {
	var out []Event
	for _, e := range r.Events {
		if e.Type == t {
			out = append(out, e)
		}
	}
	return out
}

// Verify checks every checkpoint and stored object as a replay client would: KeyCert from session_open under the
// recording key, checkpoint signatures, ciphertext and plaintext digests, key commitment, chain continuity across E
// chunks, and every V object bound to its v_init/v_segment event.
func (s *Server) Verify(sessionKey []byte, sessionID string, recordingPub ed25519.PublicKey) (*Result, error) {
	cps, objs := s.Snapshot()
	var es, vs []Checkpoint
	for _, c := range cps {
		if c.Parsed.Series == contract.SeriesE {
			es = append(es, c)
		} else {
			vs = append(vs, c)
		}
	}
	sort.Slice(es, func(i, j int) bool { return es[i].Parsed.ObjectIndex < es[j].Parsed.ObjectIndex })
	sort.Slice(vs, func(i, j int) bool { return vs[i].Parsed.ObjectIndex < vs[j].Parsed.ObjectIndex })
	if len(es) == 0 {
		return nil, fmt.Errorf("no E checkpoints")
	}
	res := &Result{EChunks: len(es)}
	plain := func(c Checkpoint) ([]byte, error) {
		stored, ok := objs[c.ObjectKey]
		if !ok {
			return nil, fmt.Errorf("object %s missing", c.ObjectKey)
		}
		if sha256.Sum256(stored) != c.Parsed.CiphertextSHA256 || uint64(len(stored)) != c.Parsed.CiphertextBytes {
			return nil, fmt.Errorf("ciphertext digest mismatch for %s", c.ObjectKey)
		}
		if contract.KeyCommitment(sessionKey) != c.Parsed.KeyCommitment {
			return nil, fmt.Errorf("key commitment mismatch for %s", c.ObjectKey)
		}
		p, err := contract.OpenObject(sessionKey, stored, contract.BuildAAD(s.ProjectID, sessionID, c.Parsed.Series, c.Parsed.ObjectIndex))
		if err != nil {
			return nil, fmt.Errorf("decrypt %s: %w", c.ObjectKey, err)
		}
		if sha256.Sum256(p) != c.Parsed.PlaintextSHA256 {
			return nil, fmt.Errorf("plaintext digest mismatch for %s", c.ObjectKey)
		}
		return p, nil
	}
	var prev [32]byte
	next := uint64(0)
	for i, c := range es {
		if c.Parsed.ObjectIndex != uint32(i) {
			return nil, fmt.Errorf("E index gap at %d", i)
		}
		p, err := plain(c)
		if err != nil {
			return nil, err
		}
		head, last, err := contract.VerifyChainSegment(p, next, prev)
		if err != nil {
			return nil, fmt.Errorf("E%d chain: %w", i, err)
		}
		if head != c.Parsed.ChainHead || c.Parsed.FirstSeq != next || c.Parsed.LastSeq != last {
			return nil, fmt.Errorf("E%d checkpoint does not match its chain", i)
		}
		envs, raws, _ := contract.ParseEnvelopes(p)
		for k, e := range envs {
			res.Events = append(res.Events, Event{Envelope: e, Hash: contract.EventHash(raws[k])})
		}
		prev, next = head, last+1
	}
	if res.Events[0].Type != contract.EventSessionOpen {
		return nil, fmt.Errorf("first event is %s", res.Events[0].Type)
	}
	var open struct {
		SessionKeyCert    string `json:"sessionKeyCert"`
		SessionKeyCertSig string `json:"sessionKeyCertSig"`
	}
	if err := json.Unmarshal(res.Events[0].Body, &open); err != nil {
		return nil, err
	}
	kcRaw, _ := base64.StdEncoding.DecodeString(open.SessionKeyCert)
	kcSig, _ := base64.StdEncoding.DecodeString(open.SessionKeyCertSig)
	kc, err := contract.VerifyKeyCert(recordingPub, kcRaw, kcSig)
	if err != nil {
		return nil, err
	}
	sessionPub := ed25519.PublicKey(kc.SessionPublicKey[:])
	for _, c := range append(append([]Checkpoint(nil), es...), vs...) {
		if _, err := contract.VerifyCheckpoint(sessionPub, c.Raw, c.Signature); err != nil {
			return nil, fmt.Errorf("%s: %w", c.ObjectKey, err)
		}
		if c.Parsed.SessionID != kc.SessionID {
			return nil, fmt.Errorf("%s: session id mismatch", c.ObjectKey)
		}
	}
	for _, c := range vs {
		p, err := plain(c)
		if err != nil {
			return nil, err
		}
		if c.Parsed.FirstSeq != c.Parsed.LastSeq || c.Parsed.LastSeq >= uint64(len(res.Events)) {
			return nil, fmt.Errorf("V%d seq range invalid", c.Parsed.ObjectIndex)
		}
		ev := res.Events[c.Parsed.LastSeq]
		if ev.Hash != c.Parsed.ChainHead {
			return nil, fmt.Errorf("V%d chain head does not match its event", c.Parsed.ObjectIndex)
		}
		var vb struct {
			ObjectIndex uint32 `json:"objectIndex"`
			SHA256      string `json:"sha256"`
		}
		if err := json.Unmarshal(ev.Body, &vb); err != nil {
			return nil, err
		}
		sum := sha256.Sum256(p)
		if vb.SHA256 != hex.EncodeToString(sum[:]) || vb.ObjectIndex != c.Parsed.ObjectIndex {
			return nil, fmt.Errorf("V%d does not match its %s event", c.Parsed.ObjectIndex, ev.Type)
		}
		if c.Parsed.Kind == contract.KindVideoInit {
			res.VInits = append(res.VInits, p)
		} else {
			res.VMedia = append(res.VMedia, p)
		}
	}
	return res, nil
}
