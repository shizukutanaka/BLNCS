package multiformats

import (
	"crypto/ed25519"
	"errors"
)

// Multicodec prefix for Ed25519 public keys (ed25519-pub = 0xed), varint-encoded
// as the two bytes 0xed 0x01.
var ed25519PubPrefix = []byte{0xed, 0x01}

// ErrBadMultikey is returned when a Multikey string is malformed or not Ed25519.
var ErrBadMultikey = errors.New("multiformats: malformed or non-Ed25519 multikey")

// EncodeEd25519Multikey encodes an Ed25519 public key as a W3C Multikey:
//
//	"z" + base58btc(0xed 0x01 || pubkey)
//
// This is the verification-method key form used by did:key and did:webvh
// (e.g. "z6Mk…").
func EncodeEd25519Multikey(pub ed25519.PublicKey) string {
	buf := make([]byte, 0, len(ed25519PubPrefix)+len(pub))
	buf = append(buf, ed25519PubPrefix...)
	buf = append(buf, pub...)
	return "z" + Base58Encode(buf)
}

// DecodeEd25519Multikey decodes a "z6Mk…" Multikey back to an Ed25519 public key.
func DecodeEd25519Multikey(mk string) (ed25519.PublicKey, error) {
	if len(mk) < 1 || mk[0] != 'z' {
		return nil, ErrBadMultikey
	}
	raw, err := Base58Decode(mk[1:])
	if err != nil {
		return nil, err
	}
	if len(raw) != len(ed25519PubPrefix)+ed25519.PublicKeySize {
		return nil, ErrBadMultikey
	}
	if raw[0] != ed25519PubPrefix[0] || raw[1] != ed25519PubPrefix[1] {
		return nil, ErrBadMultikey
	}
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(pub, raw[2:])
	return pub, nil
}

// EncodeMultibaseBase58 encodes raw bytes as multibase base58btc ("z" prefix),
// the form used for Data Integrity proofValue.
func EncodeMultibaseBase58(data []byte) string {
	return "z" + Base58Encode(data)
}

// DecodeMultibaseBase58 decodes a multibase base58btc ("z"-prefixed) string.
func DecodeMultibaseBase58(s string) ([]byte, error) {
	if len(s) < 1 || s[0] != 'z' {
		return nil, errors.New("multiformats: not multibase base58btc (missing 'z')")
	}
	return Base58Decode(s[1:])
}
