// Package ecdsakey — NIST P-256 (ES256) public-key parsing and signature
// verification, shared by the JOSE (SD-JWT) and COSE (mdoc/SCITT) paths.
//
// # Why this exists
//
// BLRCS is Ed25519 end-to-end, but the EUDI ARF and the OpenID4VC High
// Assurance Interoperability Profile mandate NIST P-256 / ES256. Until a
// verifier can check an ES256 signature, no real EUDI wallet can interoperate
// with this stack regardless of how conformant the protocol layer is. This
// package supplies the verify half; it plugs into the algorithm registries that
// already exist (compliance.RegisterJWSVerifier, cbor.RegisterVerifier) so no
// core code changes and the zero-dependency invariant holds (stdlib only).
//
// # The encoding that everyone gets wrong
//
// JOSE and COSE both encode an ECDSA signature as the RAW FIXED-WIDTH
// concatenation R‖S — NOT the ASN.1 DER structure that most crypto libraries
// (and Go's ecdsa.SignASN1/VerifyASN1) produce by default:
//
//   - RFC 7518 §3.4 (JWA): R and S are "octet sequences in big-endian order",
//     each "32 octets long" for ES256, and "MUST NOT be shortened to omit any
//     leading zero octets"; the two are concatenated R then S, giving a
//     64-octet JWS Signature.
//   - RFC 9053 §2.1 (COSE): Signature = I2OSP(R, n) | I2OSP(S, n) where
//     n = ceiling(key_length / 8) — i.e. the same fixed-width concatenation,
//     32+32 for P-256.
//
// Because both specs agree, one decoder serves both call sites. Accepting DER
// here as well would be an encoding-confusion hazard (two distinct byte strings
// verifying as the same signature), so a signature that is not exactly 64 bytes
// is rejected outright.
//
// # Signature malleability (deliberate non-enforcement)
//
// ECDSA signatures are inherently malleable: for a valid (R, S), the pair
// (R, n-S) verifies equally. Neither RFC 7518 nor RFC 9053 requires the "low-S"
// canonical form, so rejecting high-S here would reject signatures from
// spec-conforming issuers. Callers MUST NOT therefore treat a signature as a
// unique identifier for the signed object; use the payload digest instead.
package ecdsakey

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

const (
	// P256CoordSize is the octet length of one P-256 coordinate (and of R and S).
	P256CoordSize = 32
	// P256UncompressedSize is the SEC1 uncompressed point length: 0x04 || X || Y.
	P256UncompressedSize = 1 + 2*P256CoordSize // 65
	// P256CompressedSize is the SEC1 compressed point length: 0x02|0x03 || X.
	P256CompressedSize = 1 + P256CoordSize // 33
	// ES256SignatureSize is the fixed JOSE/COSE signature length: R‖S.
	ES256SignatureSize = 2 * P256CoordSize // 64
)

var (
	// ErrBadKey is returned when the bytes are not a valid P-256 point.
	ErrBadKey = errors.New("ecdsakey: invalid P-256 public key")
	// ErrBadSignatureLength is returned when a signature is not exactly the
	// fixed 64-octet R‖S form both JOSE and COSE mandate (e.g. ASN.1 DER).
	ErrBadSignatureLength = errors.New("ecdsakey: signature must be 64 bytes (raw R||S), not DER")
)

// ParseP256PublicKey decodes a SEC1 point — uncompressed (65 bytes, 0x04-led)
// or compressed (33 bytes, 0x02/0x03-led) — into an ECDSA public key, checking
// that the point actually lies on P-256.
//
// The on-curve check is not optional: verifying against an off-curve or
// small-order "key" is the classic invalid-curve attack, and a raw byte slice
// carries no guarantee on its own.
func ParseP256PublicKey(b []byte) (*ecdsa.PublicKey, error) {
	switch len(b) {
	case P256UncompressedSize:
		if b[0] != 0x04 {
			return nil, fmt.Errorf("%w: uncompressed point must start with 0x04, got 0x%02x", ErrBadKey, b[0])
		}
		// crypto/ecdh validates the point is on the curve and is not the
		// identity; it is the vetted stdlib path for untrusted point bytes.
		if _, err := ecdh.P256().NewPublicKey(b); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBadKey, err)
		}
		return &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(b[1 : 1+P256CoordSize]),
			Y:     new(big.Int).SetBytes(b[1+P256CoordSize:]),
		}, nil

	case P256CompressedSize:
		if b[0] != 0x02 && b[0] != 0x03 {
			return nil, fmt.Errorf("%w: compressed point must start with 0x02 or 0x03, got 0x%02x", ErrBadKey, b[0])
		}
		//nolint:staticcheck // UnmarshalCompressed has no crypto/ecdh equivalent
		// and performs the on-curve check itself, returning nil X on failure.
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), b)
		if x == nil {
			return nil, fmt.Errorf("%w: point is not on P-256", ErrBadKey)
		}
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil

	default:
		return nil, fmt.Errorf("%w: length %d is neither %d (uncompressed) nor %d (compressed)",
			ErrBadKey, len(b), P256UncompressedSize, P256CompressedSize)
	}
}

// MarshalP256PublicKey encodes a P-256 public key as an uncompressed SEC1 point
// (0x04 || X || Y), the form ParseP256PublicKey and the registry verifiers take.
func MarshalP256PublicKey(pub *ecdsa.PublicKey) ([]byte, error) {
	if pub == nil || pub.Curve != elliptic.P256() || pub.X == nil || pub.Y == nil {
		return nil, ErrBadKey
	}
	out := make([]byte, P256UncompressedSize)
	out[0] = 0x04
	pub.X.FillBytes(out[1 : 1+P256CoordSize])
	pub.Y.FillBytes(out[1+P256CoordSize:])
	return out, nil
}

// SplitES256Signature parses the fixed-width R‖S form into (R, S). It rejects
// any length other than 64 — notably ASN.1 DER, which most libraries emit by
// default and which neither RFC 7518 nor RFC 9053 permits here.
func SplitES256Signature(sig []byte) (r, s *big.Int, err error) {
	if len(sig) != ES256SignatureSize {
		return nil, nil, fmt.Errorf("%w: got %d bytes", ErrBadSignatureLength, len(sig))
	}
	return new(big.Int).SetBytes(sig[:P256CoordSize]),
		new(big.Int).SetBytes(sig[P256CoordSize:]), nil
}

// VerifyES256 checks a raw R‖S ECDSA/P-256/SHA-256 signature over msg.
//
// pub is a SEC1 point (uncompressed or compressed); msg is the unhashed signing
// input — the JWS signing input for JOSE, or the Sig_structure for COSE — which
// this function hashes with SHA-256 as ES256 requires. It returns a bool (not an
// error) to match the JWSVerifier / COSEVerifier registry signatures.
//
// ecdsa.Verify itself rejects r or s outside [1, n-1], so together with the
// on-curve check in ParseP256PublicKey and the strict length check in
// SplitES256Signature, every structural precondition is enforced before any
// curve arithmetic on attacker-supplied values.
func VerifyES256(pub, msg, sig []byte) bool {
	key, err := ParseP256PublicKey(pub)
	if err != nil {
		return false
	}
	r, s, err := SplitES256Signature(sig)
	if err != nil {
		return false
	}
	digest := sha256.Sum256(msg)
	return ecdsa.Verify(key, digest[:], r, s)
}
