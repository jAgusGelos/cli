package recorder

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/webapp/contract"
	"github.com/google/uuid"
)

// RecordingKeyFile is the file name of the gateway recording key inside the gateway state dir (CONTRACTS.md 6.3).
const RecordingKeyFile = "webapp-recording-key.pem"

// LoadOrCreateRecordingKey reads the Ed25519 recording key (PKCS#8 PEM) from dir, generating it with mode 0600 on
// first start.
func LoadOrCreateRecordingKey(dir string) (ed25519.PrivateKey, error) {
	path := filepath.Join(dir, RecordingKeyFile)
	raw, err := os.ReadFile(path)
	if err == nil {
		return parseRecordingKey(raw)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read recording key: %w", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create recording key dir: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	tmp, err := os.CreateTemp(dir, RecordingKeyFile+".tmp-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return nil, err
	}
	if _, err := tmp.Write(pemBytes); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	// Link instead of rename so a concurrent first start never overwrites a key another process already wrote.
	if err := os.Link(tmp.Name(), path); err != nil {
		if errors.Is(err, os.ErrExist) {
			raw, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil, rerr
			}
			return parseRecordingKey(raw)
		}
		return nil, fmt.Errorf("store recording key: %w", err)
	}
	return priv, nil
}

func parseRecordingKey(raw []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("recording key: not a PKCS#8 PEM private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("recording key: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("recording key: not an Ed25519 key")
	}
	return priv, nil
}

// SessionSigner is the per-session ephemeral Ed25519 key and its KeyCert signed by the recording key.
type SessionSigner struct {
	priv    ed25519.PrivateKey
	Pub     ed25519.PublicKey
	KeyID   [8]byte
	Cert    []byte
	CertSig []byte
}

// NewSessionSigner generates a session key certified until notAfter (session expiry + 1 h).
func NewSessionSigner(recordingKey ed25519.PrivateKey, sessionID string, notBefore, notAfter time.Time) (*SessionSigner, error) {
	id, err := uuid.Parse(sessionID)
	if err != nil {
		return nil, fmt.Errorf("session id is not a UUID: %w", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	recPub := recordingKey.Public().(ed25519.PublicKey)
	kc := &contract.KeyCert{
		SessionID:       id,
		NotBeforeUnixMs: notBefore.UnixMilli(),
		NotAfterUnixMs:  notAfter.UnixMilli(),
		IssuerKeyID:     contract.KeyID(recPub),
	}
	copy(kc.SessionPublicKey[:], pub)
	return &SessionSigner{
		priv:    priv,
		Pub:     pub,
		KeyID:   contract.KeyID(pub),
		Cert:    kc.Marshal(),
		CertSig: contract.SignKeyCert(recordingKey, kc),
	}, nil
}

func (s *SessionSigner) sign(c *contract.Checkpoint) []byte {
	return contract.SignCheckpoint(s.priv, c)
}

// Erase zeroes the private key; the signer cannot sign afterwards.
func (s *SessionSigner) Erase() {
	for i := range s.priv {
		s.priv[i] = 0
	}
}
