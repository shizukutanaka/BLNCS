// Package jwe implements the subset of JSON Web Encryption (RFC 7516) that the
// EUDI / HAIP OpenID4VP response-encryption profile requires: ECDH-ES direct
// key agreement over P-256 (RFC 7518 §4.6) with A128GCM content encryption
// (RFC 7518 §5.3), in the compact serialization (RFC 7516 §7.1).
//
// Scope is deliberately narrow. HAIP (OpenID4VC High Assurance Interoperability
// Profile) and OpenID4VP §8.3 require verifiers to accept an encrypted
// Authorization Response, and the profile pins ECDH-ES + A128GCM on P-256 —
// exactly what browsers (Chrome/Safari Digital Credentials API) emit. Only that
// one algorithm pair is implemented; every other `alg`/`enc` is rejected rather
// than silently accepted, and the code is stdlib-only (crypto/ecdh, crypto/aes,
// crypto/cipher, crypto/sha256) to keep the zero-dependency guarantee.
//
// The key-agreement math is verified against the fully-worked example in RFC
// 7518 Appendix C (see jwe_test.go), so the Concat KDF construction is known to
// be byte-for-byte interoperable.
package jwe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// Algorithm identifiers this package implements. Anything else is refused.
const (
	AlgECDHES  = "ECDH-ES" // RFC 7518 §4.6 direct key agreement
	EncA128GCM = "A128GCM" // RFC 7518 §5.3 (128-bit AES-GCM)

	cekBytes = 16 // A128GCM content-encryption key size
	gcmIVLen = 12 // 96-bit IV, the only length RFC 7518 §5.3 permits
)

var (
	// ErrUnsupportedAlg is returned when the JWE header names an alg/enc pair
	// other than the single ECDH-ES / A128GCM combination implemented here.
	ErrUnsupportedAlg = errors.New("jwe: unsupported alg/enc (only ECDH-ES + A128GCM)")
	// ErrMalformed is returned for a structurally invalid compact JWE.
	ErrMalformed = errors.New("jwe: malformed compact serialization")
	// ErrBadKey is returned when a supplied or embedded key is not P-256.
	ErrBadKey = errors.New("jwe: key is not a valid P-256 key")
	// ErrDecrypt is returned when authenticated decryption fails (wrong key,
	// tampering, or a truncated ciphertext/tag). It intentionally does not
	// distinguish these cases, to avoid a padding/validation oracle.
	ErrDecrypt = errors.New("jwe: decryption failed")
)

// protectedHeader is the JWE Protected Header for ECDH-ES direct agreement.
// With direct agreement the JWE Encrypted Key is empty, so no `encrypted_key`
// field appears; the CEK is the agreed key itself (RFC 7518 §4.6.1).
type protectedHeader struct {
	Alg string       `json:"alg"`
	Enc string       `json:"enc"`
	EPK *ecPublicJWK `json:"epk"`           // ephemeral originator public key
	APU string       `json:"apu,omitempty"` // PartyUInfo (base64url)
	APV string       `json:"apv,omitempty"` // PartyVInfo (base64url)
	Kid string       `json:"kid,omitempty"`
}

// ecPublicJWK is a P-256 public key in JWK form (RFC 7518 §6.2.1).
type ecPublicJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// Encrypt produces a compact JWE for the P-256 recipient using ECDH-ES direct
// key agreement and A128GCM. apu/apv are the optional PartyUInfo/PartyVInfo
// agreement parameters (pass nil to omit); OpenID4VP does not require them but
// they are bound into the derived key and echoed in the header when present.
//
// A fresh ephemeral key pair is generated per call (RFC 7518 §4.6.1 requires the
// ephemeral key be used once), so encrypting the same plaintext twice yields
// distinct ciphertexts.
func Encrypt(recipient *ecdsa.PublicKey, plaintext, apu, apv []byte) (string, error) {
	if recipient == nil || recipient.Curve != elliptic.P256() {
		return "", ErrBadKey
	}
	recipientECDH, err := recipient.ECDH()
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrBadKey, err)
	}

	// Ephemeral originator key (single-use).
	ephPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("jwe: ephemeral keygen: %w", err)
	}
	z, err := ephPriv.ECDH(recipientECDH)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrBadKey, err)
	}

	epk, err := ecdhToJWK(ephPriv.PublicKey())
	if err != nil {
		return "", err
	}
	hdr := protectedHeader{Alg: AlgECDHES, Enc: EncA128GCM, EPK: epk}
	if len(apu) > 0 {
		hdr.APU = b64(apu)
	}
	if len(apv) > 0 {
		hdr.APV = b64(apv)
	}
	hdrJSON, err := json.Marshal(hdr)
	if err != nil {
		return "", fmt.Errorf("jwe: header marshal: %w", err)
	}
	encodedHeader := b64(hdrJSON)

	// ECDH-ES direct: the derived key IS the CEK. AlgorithmID in the KDF is the
	// `enc` value, keydatalen is the content-encryption key length (RFC 7518
	// §5.8.1.1 / the direct-agreement rule in §4.6.2).
	cek := concatKDF(z, []byte(EncA128GCM), apu, apv, cekBytes*8)

	block, err := aes.NewCipher(cek)
	if err != nil {
		return "", fmt.Errorf("jwe: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("jwe: gcm: %w", err)
	}
	iv := make([]byte, gcmIVLen)
	if _, err := rand.Read(iv); err != nil {
		return "", fmt.Errorf("jwe: iv: %w", err)
	}
	// AAD for the AEAD is ASCII(BASE64URL(protected header)) (RFC 7516 §5.1).
	sealed := gcm.Seal(nil, iv, plaintext, []byte(encodedHeader))
	// Go appends the 16-byte tag to the ciphertext; JWE serializes them apart.
	ct, tag := sealed[:len(sealed)-gcm.Overhead()], sealed[len(sealed)-gcm.Overhead():]

	// Compact: header . encrypted_key . iv . ciphertext . tag. encrypted_key is
	// empty for direct agreement.
	return encodedHeader + "." + "" + "." + b64(iv) + "." + b64(ct) + "." + b64(tag), nil
}

// Decrypt reverses Encrypt for the P-256 recipient. It enforces the pinned
// alg/enc pair and rejects any other before doing key agreement.
func Decrypt(compact string, recipient *ecdsa.PrivateKey) ([]byte, error) {
	if recipient == nil || recipient.Curve != elliptic.P256() {
		return nil, ErrBadKey
	}
	recipientECDH, err := recipient.ECDH()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadKey, err)
	}

	parts, err := splitCompact(compact)
	if err != nil {
		return nil, err
	}
	hdrJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrMalformed
	}
	var hdr protectedHeader
	if err := json.Unmarshal(hdrJSON, &hdr); err != nil {
		return nil, ErrMalformed
	}
	// Pin the algorithm pair BEFORE any crypto. Direct agreement means the JWE
	// Encrypted Key MUST be empty (RFC 7518 §4.6.1); a non-empty one signals a
	// different (unimplemented) key-management mode, so reject it.
	if hdr.Alg != AlgECDHES || hdr.Enc != EncA128GCM {
		return nil, ErrUnsupportedAlg
	}
	if parts[1] != "" {
		return nil, ErrUnsupportedAlg
	}
	if hdr.EPK == nil {
		return nil, ErrMalformed
	}
	ephPub, err := jwkToECDH(hdr.EPK)
	if err != nil {
		return nil, err
	}
	z, err := recipientECDH.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadKey, err)
	}

	apu, err := decodeAgreementParam(hdr.APU)
	if err != nil {
		return nil, ErrMalformed
	}
	apv, err := decodeAgreementParam(hdr.APV)
	if err != nil {
		return nil, ErrMalformed
	}
	cek := concatKDF(z, []byte(EncA128GCM), apu, apv, cekBytes*8)

	iv, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(iv) != gcmIVLen {
		return nil, ErrMalformed
	}
	ct, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, ErrMalformed
	}
	tag, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, ErrMalformed
	}

	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, fmt.Errorf("jwe: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("jwe: gcm: %w", err)
	}
	if len(tag) != gcm.Overhead() {
		return nil, ErrMalformed
	}
	pt, err := gcm.Open(nil, iv, append(append([]byte{}, ct...), tag...), []byte(parts[0]))
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// concatKDF is the NIST SP 800-56A Concatenation KDF (single-step, SHA-256) as
// profiled by RFC 7518 §4.6.2. It derives keyLenBits bits from the shared
// secret z, binding the algorithm ID and the party info into OtherInfo. For the
// key sizes used here (≤ 256 bits) exactly one hash iteration is needed, but the
// full counter loop is implemented for correctness.
func concatKDF(z, algID, partyU, partyV []byte, keyLenBits int) []byte {
	// OtherInfo = AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo, each of
	// the first three length-prefixed with a 32-bit big-endian octet count
	// (RFC 7518 §4.6.2). SuppPubInfo is the key length in bits as a 32-bit
	// big-endian integer; SuppPrivInfo is empty.
	var otherInfo []byte
	otherInfo = append(otherInfo, lengthPrefixed(algID)...)
	otherInfo = append(otherInfo, lengthPrefixed(partyU)...)
	otherInfo = append(otherInfo, lengthPrefixed(partyV)...)
	otherInfo = append(otherInfo, uint32be(uint32(keyLenBits))...)

	keyLen := keyLenBits / 8
	out := make([]byte, 0, keyLen)
	for counter := uint32(1); len(out) < keyLen; counter++ {
		h := sha256.New()
		h.Write(uint32be(counter))
		h.Write(z)
		h.Write(otherInfo)
		out = h.Sum(out)
	}
	return out[:keyLen]
}

func lengthPrefixed(b []byte) []byte { return append(uint32be(uint32(len(b))), b...) }

func uint32be(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}

// ecdhToJWK renders a P-256 ecdh public key as a JWK with fixed-width, zero-
// padded coordinates (RFC 7518 §6.2.1.2 mandates the full field length).
func ecdhToJWK(pub *ecdh.PublicKey) (*ecPublicJWK, error) {
	raw := pub.Bytes() // 0x04 || X || Y (SEC1 uncompressed)
	if len(raw) != 65 || raw[0] != 0x04 {
		return nil, ErrBadKey
	}
	return &ecPublicJWK{
		Kty: "EC", Crv: "P-256",
		X: b64(raw[1:33]),
		Y: b64(raw[33:]),
	}, nil
}

// jwkToECDH parses a P-256 JWK into an ecdh public key, validating the point is
// on the curve (crypto/ecdh rejects off-curve points).
func jwkToECDH(jwk *ecPublicJWK) (*ecdh.PublicKey, error) {
	if jwk.Kty != "EC" || jwk.Crv != "P-256" {
		return nil, ErrBadKey
	}
	x, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil || len(x) != 32 {
		return nil, ErrBadKey
	}
	y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil || len(y) != 32 {
		return nil, ErrBadKey
	}
	raw := make([]byte, 0, 65)
	raw = append(raw, 0x04)
	raw = append(raw, x...)
	raw = append(raw, y...)
	pub, err := ecdh.P256().NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadKey, err)
	}
	return pub, nil
}

// PublicKeyJWK renders a P-256 public key as the JWK a verifier advertises in
// its client_metadata `jwks` so a wallet can encrypt to it. use is set to "enc".
func PublicKeyJWK(pub *ecdsa.PublicKey) (map[string]any, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return nil, ErrBadKey
	}
	return map[string]any{
		"kty": "EC", "crv": "P-256", "use": "enc", "alg": AlgECDHES,
		"x": b64(bigTo32(pub.X)),
		"y": b64(bigTo32(pub.Y)),
	}, nil
}

func bigTo32(v *big.Int) []byte {
	var b [32]byte
	v.FillBytes(b[:])
	return b[:]
}

func decodeAgreementParam(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

func splitCompact(s string) ([5]string, error) {
	var out [5]string
	n, start := 0, 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			if n >= 4 {
				return out, ErrMalformed
			}
			out[n] = s[start:i]
			n++
			start = i + 1
		}
	}
	if n != 4 {
		return out, ErrMalformed
	}
	out[4] = s[start:]
	// header, iv, ciphertext, tag are all mandatory and non-empty; encrypted_key
	// (index 1) is legitimately empty for direct key agreement.
	if out[0] == "" || out[2] == "" || out[3] == "" || out[4] == "" {
		return out, ErrMalformed
	}
	return out, nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
