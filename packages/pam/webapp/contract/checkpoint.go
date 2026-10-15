package contract

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// Keys, KeyCert and Checkpoint (CONTRACTS.md 6.3, 6.4, 6.7).

const (
	KeyCertSize    = 80
	CheckpointSize = 208
)

var (
	keyCertMagic    = [4]byte{'I', 'W', 'K', '1'}
	checkpointMagic = [4]byte{'I', 'W', 'C', '1'}
)

// KeyID returns the first 8 bytes of SHA-256(raw public key).
func KeyID(pub ed25519.PublicKey) [8]byte {
	sum := sha256.Sum256(pub)
	var id [8]byte
	copy(id[:], sum[:8])
	return id
}

// KeyIDHex is the 16-char lowercase hex form of KeyID.
func KeyIDHex(pub ed25519.PublicKey) string {
	id := KeyID(pub)
	return hex.EncodeToString(id[:])
}

// Fingerprint returns "SHA256:" + unpadded standard base64 of SHA-256(raw public key).
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func domainSign(priv ed25519.PrivateKey, domain string, msg []byte) []byte {
	return ed25519.Sign(priv, domainMessage(domain, msg))
}

func domainVerify(pub ed25519.PublicKey, domain string, msg, sig []byte) bool {
	return len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, domainMessage(domain, msg), sig)
}

func domainMessage(domain string, msg []byte) []byte {
	out := make([]byte, 0, len(domain)+1+len(msg))
	out = append(out, domain...)
	out = append(out, 0)
	return append(out, msg...)
}

type KeyCert struct {
	SessionID        [16]byte
	SessionPublicKey [32]byte
	NotBeforeUnixMs  int64
	NotAfterUnixMs   int64
	IssuerKeyID      [8]byte
}

func (k *KeyCert) Marshal() []byte {
	out := make([]byte, KeyCertSize)
	copy(out[0:4], keyCertMagic[:])
	out[4] = 1
	out[5] = AlgV1
	copy(out[8:24], k.SessionID[:])
	copy(out[24:56], k.SessionPublicKey[:])
	binary.BigEndian.PutUint64(out[56:64], uint64(k.NotBeforeUnixMs))
	binary.BigEndian.PutUint64(out[64:72], uint64(k.NotAfterUnixMs))
	copy(out[72:80], k.IssuerKeyID[:])
	return out
}

func UnmarshalKeyCert(b []byte) (*KeyCert, error) {
	if len(b) != KeyCertSize || !bytes.Equal(b[0:4], keyCertMagic[:]) || b[4] != 1 || b[5] != AlgV1 {
		return nil, errors.New("contract: bad key cert encoding")
	}
	k := &KeyCert{
		NotBeforeUnixMs: int64(binary.BigEndian.Uint64(b[56:64])),
		NotAfterUnixMs:  int64(binary.BigEndian.Uint64(b[64:72])),
	}
	copy(k.SessionID[:], b[8:24])
	copy(k.SessionPublicKey[:], b[24:56])
	copy(k.IssuerKeyID[:], b[72:80])
	return k, nil
}

// SignKeyCert signs a KeyCert with the gateway recording key.
func SignKeyCert(recordingKey ed25519.PrivateKey, k *KeyCert) []byte {
	return domainSign(recordingKey, domainKeyCert, k.Marshal())
}

// VerifyKeyCert checks the KeyCert signature against a trusted recording public key and the issuer key id.
func VerifyKeyCert(recordingPub ed25519.PublicKey, keyCertBytes, sig []byte) (*KeyCert, error) {
	k, err := UnmarshalKeyCert(keyCertBytes)
	if err != nil {
		return nil, err
	}
	if k.IssuerKeyID != KeyID(recordingPub) {
		return nil, errors.New("contract: key cert issuer does not match recording key")
	}
	if !domainVerify(recordingPub, domainKeyCert, keyCertBytes, sig) {
		return nil, errors.New("contract: bad key cert signature")
	}
	return k, nil
}

type Series uint8

const (
	SeriesE Series = 1
	SeriesV Series = 2
)

func (s Series) Letter() string {
	if s == SeriesV {
		return "V"
	}
	return "E"
}

type CheckpointKind uint8

const (
	KindEvents     CheckpointKind = 0
	KindVideoInit  CheckpointKind = 1
	KindVideoMedia CheckpointKind = 2
)

type Checkpoint struct {
	Series               Series
	Kind                 CheckpointKind
	SessionID            [16]byte
	ObjectIndex          uint32
	FirstSeq             uint64
	LastSeq              uint64
	ChainHead            [32]byte
	PlaintextSHA256      [32]byte
	CiphertextSHA256     [32]byte
	PlaintextBytes       uint64
	CiphertextBytes      uint64
	KeyCommitment        [32]byte
	MaskingPolicyVersion uint32
	SignerKeyID          [8]byte
	CreatedAtUnixMs      int64
}

func (c *Checkpoint) Marshal() []byte {
	out := make([]byte, CheckpointSize)
	copy(out[0:4], checkpointMagic[:])
	out[4] = 1
	out[5] = AlgV1
	out[6] = byte(c.Series)
	out[7] = byte(c.Kind)
	copy(out[8:24], c.SessionID[:])
	binary.BigEndian.PutUint32(out[24:28], c.ObjectIndex)
	binary.BigEndian.PutUint64(out[28:36], c.FirstSeq)
	binary.BigEndian.PutUint64(out[36:44], c.LastSeq)
	copy(out[44:76], c.ChainHead[:])
	copy(out[76:108], c.PlaintextSHA256[:])
	copy(out[108:140], c.CiphertextSHA256[:])
	binary.BigEndian.PutUint64(out[140:148], c.PlaintextBytes)
	binary.BigEndian.PutUint64(out[148:156], c.CiphertextBytes)
	copy(out[156:188], c.KeyCommitment[:])
	binary.BigEndian.PutUint32(out[188:192], c.MaskingPolicyVersion)
	copy(out[192:200], c.SignerKeyID[:])
	binary.BigEndian.PutUint64(out[200:208], uint64(c.CreatedAtUnixMs))
	return out
}

func UnmarshalCheckpoint(b []byte) (*Checkpoint, error) {
	if len(b) != CheckpointSize || !bytes.Equal(b[0:4], checkpointMagic[:]) || b[4] != 1 || b[5] != AlgV1 {
		return nil, errors.New("contract: bad checkpoint encoding")
	}
	c := &Checkpoint{
		Series:               Series(b[6]),
		Kind:                 CheckpointKind(b[7]),
		ObjectIndex:          binary.BigEndian.Uint32(b[24:28]),
		FirstSeq:             binary.BigEndian.Uint64(b[28:36]),
		LastSeq:              binary.BigEndian.Uint64(b[36:44]),
		PlaintextBytes:       binary.BigEndian.Uint64(b[140:148]),
		CiphertextBytes:      binary.BigEndian.Uint64(b[148:156]),
		MaskingPolicyVersion: binary.BigEndian.Uint32(b[188:192]),
		CreatedAtUnixMs:      int64(binary.BigEndian.Uint64(b[200:208])),
	}
	if c.Series != SeriesE && c.Series != SeriesV {
		return nil, fmt.Errorf("contract: unknown series %d", c.Series)
	}
	validKind := c.Kind == KindEvents
	if c.Series == SeriesV {
		validKind = c.Kind == KindVideoInit || c.Kind == KindVideoMedia
	}
	if !validKind {
		return nil, fmt.Errorf("contract: checkpoint kind %d is invalid for series %d", c.Kind, c.Series)
	}
	copy(c.SessionID[:], b[8:24])
	copy(c.ChainHead[:], b[44:76])
	copy(c.PlaintextSHA256[:], b[76:108])
	copy(c.CiphertextSHA256[:], b[108:140])
	copy(c.KeyCommitment[:], b[156:188])
	copy(c.SignerKeyID[:], b[192:200])
	return c, nil
}

// SignCheckpoint signs with the per-session key.
func SignCheckpoint(sessionKey ed25519.PrivateKey, c *Checkpoint) []byte {
	return domainSign(sessionKey, domainCheckpoint, c.Marshal())
}

// VerifyCheckpoint checks the signature and the signer key id against the session public key from a verified KeyCert.
func VerifyCheckpoint(sessionPub ed25519.PublicKey, checkpointBytes, sig []byte) (*Checkpoint, error) {
	c, err := UnmarshalCheckpoint(checkpointBytes)
	if err != nil {
		return nil, err
	}
	if c.SignerKeyID != KeyID(sessionPub) {
		return nil, errors.New("contract: checkpoint signer does not match session key")
	}
	if !domainVerify(sessionPub, domainCheckpoint, checkpointBytes, sig) {
		return nil, errors.New("contract: bad checkpoint signature")
	}
	return c, nil
}
