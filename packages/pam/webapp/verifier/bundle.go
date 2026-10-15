// Package verifier checks a Web App session evidence bundle offline (D-06 item 10). The only trust input is the
// recording key fingerprint the customer recorded out of band; every other key must chain to it.
package verifier

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Infisical/infisical-merge/packages/pam/webapp/contract"
)

// Bundle layout: the replay document (CONTRACTS.md 6.10) verbatim, the session AES key, and every stored object
// (IV || ciphertext || tag) exactly as the `?form=stored` route returns it.
const (
	ReplayFile     = "replay.json"
	SessionKeyFile = "session-key.b64"
	ObjectsDir     = "objects"
)

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

func LoadBundle(dir string) (*Bundle, error) {
	raw, err := os.ReadFile(filepath.Join(dir, ReplayFile))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", ReplayFile, err)
	}
	b := &Bundle{Dir: dir}
	if err := json.Unmarshal(raw, &b.Replay); err != nil {
		return nil, fmt.Errorf("parse %s: %w", ReplayFile, err)
	}
	key, err := readSessionKey(filepath.Join(dir, SessionKeyFile))
	if err != nil {
		return nil, err
	}
	b.SessionKey = key
	return b, nil
}

func readSessionKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", SessionKeyFile, err)
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", SessionKeyFile, err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("%s: session key must be 32 bytes, got %d", SessionKeyFile, len(key))
	}
	return key, nil
}

// StoredObjectPath is the bundle-relative path of a stored object.
func StoredObjectPath(series contract.Series, objectIndex uint32) string {
	return filepath.Join(ObjectsDir, series.Letter(), fmt.Sprintf("%08d.stored", objectIndex))
}

func (b *Bundle) storedObject(series contract.Series, objectIndex uint32) ([]byte, error) {
	return os.ReadFile(filepath.Join(b.Dir, StoredObjectPath(series, objectIndex)))
}
