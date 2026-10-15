package contract

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Chunk encryption, key commitment and S3 object keys (CONTRACTS.md 6.4, 6.8).

const (
	IVSize  = 12
	TagSize = 16
)

// BuildAAD returns SHA-256(domain || 0 || projectId || 0 || sessionId || 0 || series || 0 || decimal(objectIndex)).
func BuildAAD(projectID, sessionID string, series Series, objectIndex uint32) []byte {
	h := sha256.New()
	for _, part := range []string{domainAAD, projectID, sessionID, series.Letter()} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	h.Write([]byte(strconv.FormatUint(uint64(objectIndex), 10)))
	return h.Sum(nil)
}

// KeyCommitment returns SHA-256(domain || 0 || sessionKey).
func KeyCommitment(sessionKey []byte) [32]byte {
	return sha256.Sum256(domainMessage(domainKeyCommit, sessionKey))
}

// SealObject encrypts plaintext into a stored object: IV || ciphertext || tag. A nil iv draws a random one.
func SealObject(sessionKey, iv, plaintext, aad []byte) ([]byte, error) {
	if len(sessionKey) != 32 {
		return nil, fmt.Errorf("contract: session key must be 32 bytes, got %d", len(sessionKey))
	}
	if iv == nil {
		iv = make([]byte, IVSize)
		if _, err := rand.Read(iv); err != nil {
			return nil, err
		}
	}
	if len(iv) != IVSize {
		return nil, errors.New("contract: iv must be 12 bytes")
	}
	gcm, err := newGCM(sessionKey)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, IVSize+len(plaintext)+TagSize)
	out = append(out, iv...)
	return gcm.Seal(out, iv, plaintext, aad), nil
}

// OpenObject decrypts a stored object (IV || ciphertext || tag).
func OpenObject(sessionKey, stored, aad []byte) ([]byte, error) {
	if len(stored) < IVSize+TagSize {
		return nil, errors.New("contract: stored object too short")
	}
	gcm, err := newGCM(sessionKey)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, stored[:IVSize], stored[IVSize:], aad)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// ObjectKey returns {keyPrefix}/web-app/{projectId}/{sessionId}/{series}/{objectIndex:08d}.{ext}.
func ObjectKey(keyPrefix, projectID, sessionID string, series Series, kind CheckpointKind, objectIndex uint32) string {
	ext := "evt"
	switch kind {
	case KindVideoInit:
		ext = "init.mp4"
	case KindVideoMedia:
		ext = "m4s"
	}
	key := fmt.Sprintf("web-app/%s/%s/%s/%08d.%s", projectID, sessionID, series.Letter(), objectIndex, ext)
	prefix := strings.Trim(keyPrefix, "/")
	if prefix == "" {
		return key
	}
	return prefix + "/" + key
}
