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

// ============================================================================
// P-256 (secp256r1) Multikey — Axis 136
// ============================================================================

// Multicodec prefix for P-256 public keys (p256-pub = 0x1200), varint-encoded
// as the two bytes 0x80 0x24.
//
// The varint (LEB128) derivation: 0x1200 = 4608; the low 7 bits are 0 with the
// continuation bit set (0x80), and 4608>>7 = 36 = 0x24. Multikey then carries
// the COMPRESSED 33-byte point, giving 35 bytes before base58btc — which is why
// P-256 did:key identifiers begin "zDn".
var p256PubPrefix = []byte{0x80, 0x24}

// P256CompressedSize is the SEC1 compressed point length carried by a Multikey.
const P256CompressedSize = 33

// ErrBadP256Multikey is returned when a Multikey is malformed or not P-256.
var ErrBadP256Multikey = errors.New("multiformats: malformed or non-P-256 multikey")

// EncodeP256Multikey encodes a COMPRESSED P-256 point (33 bytes, 0x02/0x03-led)
// as a W3C Multikey: "z" + base58btc(0x80 0x24 || compressed).
func EncodeP256Multikey(compressed []byte) (string, error) {
	if len(compressed) != P256CompressedSize || (compressed[0] != 0x02 && compressed[0] != 0x03) {
		return "", ErrBadP256Multikey
	}
	buf := make([]byte, 0, len(p256PubPrefix)+len(compressed))
	buf = append(buf, p256PubPrefix...)
	buf = append(buf, compressed...)
	return "z" + Base58Encode(buf), nil
}

// DecodeP256Multikey decodes a "zDn…" Multikey to the compressed P-256 point.
// It deliberately does NOT accept an Ed25519 multikey: the two prefixes are
// distinct, and silently coercing between curves would be a key-confusion bug.
func DecodeP256Multikey(mk string) ([]byte, error) {
	if len(mk) < 1 || mk[0] != 'z' {
		return nil, ErrBadP256Multikey
	}
	raw, err := Base58Decode(mk[1:])
	if err != nil {
		return nil, err
	}
	if len(raw) != len(p256PubPrefix)+P256CompressedSize {
		return nil, ErrBadP256Multikey
	}
	if raw[0] != p256PubPrefix[0] || raw[1] != p256PubPrefix[1] {
		return nil, ErrBadP256Multikey
	}
	if raw[2] != 0x02 && raw[2] != 0x03 {
		return nil, ErrBadP256Multikey
	}
	out := make([]byte, P256CompressedSize)
	copy(out, raw[2:])
	return out, nil
}
