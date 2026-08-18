package conformance

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"

	"blrcs/ecdsakey"
	"blrcs/jwe"
	"blrcs/openid4vci"
)

// ============================================================================
// Axis 152: P-256 / EUDI conformance vectors
//
// The reference suite covered GTIN, DID, SD-JWT, Merkle, GS1, VC, DCQL and
// tiers — everything the project could do before Axis 135. The whole P-256 arc
// (Axes 135-148: ES256 issuance and verification, KB-JWT holder binding, JWE
// response encryption, PKCE, the mdoc PKI) shipped with no vectors at all, so a
// third party could claim "BLRCS-compatible" while sharing none of the
// cryptography a real EUDI deployment actually exercises.
//
// Every vector here is DETERMINISTIC, which constrains what can be tested.
// ECDSA signing and JWE encryption are randomised by design — hedged nonces and
// single-use ephemeral keys — so "sign this and compare bytes" is not a legal
// vector for either. What IS deterministic, and is what an implementer actually
// needs to get right, is the verification and derivation direction:
//
//	pkce_s256    — RFC 7636 §4.2 code_challenge derivation
//	es256_verify — RFC 7518 §3.4 raw R‖S signature verification
//	jwe_decrypt  — RFC 7518 §4.6 ECDH-ES + Concat KDF + A128GCM, end to end
//	p256_point   — SEC1 uncompressed point <-> JWK coordinate encoding
//
// Two vectors are lifted from the RFCs themselves rather than generated here,
// so passing them proves agreement with the specification and not merely with
// this implementation:
//
//	pkce/rfc7636-appendix-b — the published verifier/challenge pair
//	(the RFC 7518 Appendix C Concat KDF vector is asserted in jwe's own tests;
//	 jwe_decrypt covers the same construction end to end for other languages)
//
// The jwe_decrypt vector deliberately publishes a private key. Conformance
// vectors are public by construction, the key exists only to make the vector
// checkable, and it must never be used for anything else.
// ============================================================================

type p256In struct {
	Op string `json:"op"`
	// pkce_s256
	Verifier string `json:"verifier,omitempty"`
	// es256_verify
	SEC1 string `json:"sec1,omitempty"` // hex, uncompressed 0x04||X||Y
	Msg  string `json:"msg,omitempty"`  // hex
	Sig  string `json:"sig,omitempty"`  // hex, raw R||S (64 octets)
	// jwe_decrypt
	PrivD   string `json:"privD,omitempty"` // hex P-256 scalar
	Compact string `json:"compact,omitempty"`
	// p256_point
	Point string `json:"point,omitempty"` // hex SEC1
}

type p256Out struct {
	Challenge string `json:"challenge,omitempty"`
	Valid     *bool  `json:"valid,omitempty"`
	Plaintext string `json:"plaintext,omitempty"`
	X         string `json:"x,omitempty"` // base64url, fixed 32 octets
	Y         string `json:"y,omitempty"`
}

func runP256(v TestVector) Result {
	r := Result{VectorID: v.ID}
	var in p256In
	if err := json.Unmarshal(v.Input, &in); err != nil {
		r.Reason = "bad input: " + err.Error()
		return r
	}
	var want p256Out
	if err := json.Unmarshal(v.Expected, &want); err != nil {
		r.Reason = "bad expected: " + err.Error()
		return r
	}

	switch in.Op {
	case "pkce_s256":
		got := openid4vci.S256Challenge(in.Verifier)
		if got != want.Challenge {
			r.Reason = "challenge " + got + " != " + want.Challenge
			return r
		}

	case "es256_verify":
		pub, err := hex.DecodeString(in.SEC1)
		if err != nil {
			r.Reason = "bad sec1 hex"
			return r
		}
		msg, err := hex.DecodeString(in.Msg)
		if err != nil {
			r.Reason = "bad msg hex"
			return r
		}
		sig, err := hex.DecodeString(in.Sig)
		if err != nil {
			r.Reason = "bad sig hex"
			return r
		}
		got := ecdsakey.VerifyES256(pub, msg, sig)
		if want.Valid == nil || got != *want.Valid {
			r.Reason = "verify result mismatch"
			return r
		}

	case "jwe_decrypt":
		priv, err := p256PrivFromScalar(in.PrivD)
		if err != nil {
			r.Reason = err.Error()
			return r
		}
		pt, err := jwe.Decrypt(in.Compact, priv)
		if err != nil {
			// A vector may legitimately expect failure (tampered ciphertext).
			if want.Valid != nil && !*want.Valid {
				break
			}
			r.Reason = "decrypt: " + err.Error()
			return r
		}
		if want.Valid != nil && !*want.Valid {
			r.Reason = "decrypt should have failed but succeeded"
			return r
		}
		if string(pt) != want.Plaintext {
			r.Reason = "plaintext mismatch"
			return r
		}

	case "p256_point":
		raw, err := hex.DecodeString(in.Point)
		if err != nil {
			r.Reason = "bad point hex"
			return r
		}
		pub, err := ecdsakey.ParseP256PublicKey(raw)
		if err != nil {
			if want.Valid != nil && !*want.Valid {
				break
			}
			r.Reason = "parse: " + err.Error()
			return r
		}
		if want.Valid != nil && !*want.Valid {
			r.Reason = "off-curve point should have been rejected"
			return r
		}
		x, y := b64Coord(pub.X), b64Coord(pub.Y)
		if x != want.X || y != want.Y {
			r.Reason = "JWK coordinates mismatch: x=" + x + " y=" + y
			return r
		}

	default:
		r.Reason = "unknown p256 op: " + in.Op
		return r
	}

	r.Passed = true
	return r
}

// p256PrivFromScalar rebuilds a P-256 private key from its hex scalar, so a
// vector can publish a key compactly and a third-party implementation can
// reconstruct the same one.
func p256PrivFromScalar(hexD string) (*ecdsa.PrivateKey, error) {
	b, err := hex.DecodeString(hexD)
	if err != nil {
		return nil, errBadScalar
	}
	d := new(big.Int).SetBytes(b)
	n := elliptic.P256().Params().N
	if d.Sign() <= 0 || d.Cmp(n) >= 0 {
		return nil, errBadScalar
	}
	priv := new(ecdsa.PrivateKey)
	priv.Curve = elliptic.P256()
	priv.D = d
	priv.X, priv.Y = elliptic.P256().ScalarBaseMult(d.Bytes())
	return priv, nil
}

// b64Coord renders a coordinate as fixed-width base64url, which RFC 7518
// §6.2.1.2 requires — a coordinate must be padded to the full field length, not
// emitted as a minimal big-endian integer.
func b64Coord(v *big.Int) string {
	var b [32]byte
	v.FillBytes(b[:])
	return b64url(b[:])
}

// errBadScalar is returned for a vector whose private scalar is not a valid
// P-256 secret (zero, or >= the group order).
var errBadScalar = errors.New("conformance: invalid P-256 private scalar")

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
