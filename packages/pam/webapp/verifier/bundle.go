// Package verifier checks a Web App session evidence bundle offline (D-06 item 10). The only trust input is the
// recording key fingerprint the customer recorded out of band; every other key must chain to it.
package verifier

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Infisical/infisical-merge/packages/pam/webapp/contract"
)

// Bundle layout (CONTRACTS.md 6.11).
const (
	ReplayFile     = "replay.json"
	SessionKeyFile = "session-key.b64"
	ObjectsDir     = "objects"
)

const (
	ObjectKindInit  = "init"
	ObjectKindMedia = "media"
)

const (
	sessionKeySize = 32
	// Upper bounds checked before reading, so a hostile bundle cannot exhaust memory.
	maxReplayBytes     = 16 << 20
	maxSessionKeyBytes = 1 << 10
	// The presign route refuses objects over 64 MiB (CONTRACTS.md 6.9); IV and tag add 28 bytes.
	maxStoredObjectBytes = 64<<20 + contract.IVSize + contract.TagSize
)

// ErrMalformedBundle marks bundle content that exists but cannot be parsed (as opposed to an unreadable path).
var ErrMalformedBundle = errors.New("malformed bundle")

type ObjectEntry struct {
	ObjectIndex uint32 `json:"objectIndex"`
	Kind        string `json:"kind,omitempty"`
	Checkpoint  string `json:"checkpoint"`
	Signature   string `json:"signature"`
	ObjectKey   string `json:"objectKey,omitempty"`
	VersionID   string `json:"versionId,omitempty"`
}

type RecordingKey struct {
	PublicKey   string `json:"publicKey"`
	KeyID       string `json:"keyId"`
	Fingerprint string `json:"fingerprint"`
}

type Replay struct {
	SessionID    string       `json:"sessionId"`
	ProjectID    string       `json:"projectId"`
	RecordingKey RecordingKey `json:"recordingKey"`
	KeyCert      string       `json:"keyCert"`
	KeyCertSig   string       `json:"keyCertSig"`
	Video        struct {
		Objects []ObjectEntry `json:"objects"`
	} `json:"video"`
	Events struct {
		Chunks []ObjectEntry `json:"chunks"`
	} `json:"events"`
}

type Bundle struct {
	Dir    string
	Replay Replay
	// SessionKey is nil when the bundle carries no session key; plaintext checks are then impossible.
	SessionKey []byte
}

func videoKindName(kind contract.CheckpointKind) string {
	switch kind {
	case contract.KindVideoInit:
		return ObjectKindInit
	case contract.KindVideoMedia:
		return ObjectKindMedia
	default:
		return ""
	}
}

func LoadBundle(dir string) (*Bundle, error) {
	raw, err := readRegularFile(filepath.Join(dir, ReplayFile), maxReplayBytes)
	if err != nil {
		return nil, err
	}
	b := &Bundle{Dir: dir}
	if err := json.Unmarshal(raw, &b.Replay); err != nil {
		return nil, fmt.Errorf("%w: parse %s: %v", ErrMalformedBundle, ReplayFile, err)
	}
	key, err := readSessionKey(filepath.Join(dir, SessionKeyFile))
	if err != nil {
		return nil, err
	}
	b.SessionKey = key
	return b, nil
}

func readSessionKey(path string) ([]byte, error) {
	raw, err := readRegularFile(path, maxSessionKeyBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("%w: decode %s: %v", ErrMalformedBundle, SessionKeyFile, err)
	}
	if len(key) != sessionKeySize {
		return nil, fmt.Errorf("%w: %s holds %d bytes, want %d", ErrMalformedBundle, SessionKeyFile, len(key), sessionKeySize)
	}
	return key, nil
}

// readRegularFile refuses symlinks, devices and files larger than limit before reading them.
func readRegularFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrMalformedBundle, path)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%w: %s is %d bytes, limit %d", ErrMalformedBundle, path, info.Size(), limit)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit+1))
}

func StoredObjectPath(series contract.Series, objectIndex uint32) string {
	return filepath.Join(ObjectsDir, series.Letter(), fmt.Sprintf("%08d.stored", objectIndex))
}

func (b *Bundle) storedObject(series contract.Series, objectIndex uint32, signedBytes uint64) ([]byte, error) {
	return readRegularFile(filepath.Join(b.Dir, StoredObjectPath(series, objectIndex)), int64(min(signedBytes, maxStoredObjectBytes)))
}
