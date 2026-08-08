package compliance

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"blrcs/ecdsakey"
)

// ============================================================================
// Axis 137: ES256 (P-256) SD-JWT ISSUANCE
//
// Axes 135/136 completed the verify side: ES256 signatures check out and P-256
// keys resolve from DIDs. This closes the remaining half of the EUDI-interop
// weakness — BLRCS can now ISSUE credentials a P-256-only ecosystem accepts.
//
// # Why a distinct type rather than a mode on Issuer
//
// Issuer.PrivateKey() hands an ed25519.PrivateKey to SCITT statements,
// did:webvh log entries, status-list signing and witness proofs — all of which
// are Ed25519-only. If ES256 were a flag on Issuer, every one of those call
// sites would silently receive a nil (or wrongly-typed) key at runtime. Making
// it a separate type means the compiler rejects that misuse: an ES256Issuer
// simply cannot be passed where an Ed25519 Issuer is required. The SD-JWT
// construction itself is shared, not duplicated — both types feed the same
// core builder through the jwsSigner seam.
//
// # Nonce generation
//
// ECDSA fails catastrophically on nonce reuse or bias: two signatures sharing k
// leak the private key outright. Go's crypto/ecdsa does NOT take a raw nonce
// from the RNG. It produces "hedged" signatures, drawing k from an AES-CTR
// CSPRNG keyed by SHA2-512(priv.D || entropy || hash)[:32], so the private key
// and the message digest both feed the nonce. That resists RNG failure (a
// broken entropy source still yields distinct k per distinct message) while
// keeping the fault-injection tolerance that pure RFC 6979 determinism gives
// up. Go can produce strict RFC 6979 signatures by passing a nil reader, but we
// deliberately pass rand.Reader: hedged is the stronger choice, and byte-stable
// signatures buy us nothing here (SD-JWT salts are random anyway, so a reissued
// credential never reproduces bit-for-bit regardless).
// ============================================================================

// ErrNotP256 is returned when a supplied ECDSA key is not on P-256.
var ErrNotP256 = errors.New("compliance: issuer key must be on P-256 for ES256")

// jwsSigner is the seam that lets one SD-JWT builder serve both algorithms. It
// is unexported: callers pick an issuer type, not a signer.
type jwsSigner interface {
	// jwsAlg is the JOSE `alg` header value.
	jwsAlg() string
	// signJWS signs the JWS signing input, returning the signature in the exact
	// wire form the alg mandates.
	signJWS(signingInput []byte) ([]byte, error)
	// sdjwtTyp is the JWS `typ` header value to stamp.
	sdjwtTyp() string
	// decoyCount is how many decoy digests to mix into `_sd`.
	decoyCount() int
}

// --- Ed25519 issuer implements the seam (behaviour unchanged) ---------------

func (i *Issuer) jwsAlg() string   { return "EdDSA" }
func (i *Issuer) sdjwtTyp() string { return i.sdjwtVCType() }
func (i *Issuer) decoyCount() int  { return i.DecoyDigests }
func (i *Issuer) signJWS(in []byte) ([]byte, error) {
	return ed25519.Sign(i.privateKey, in), nil
}

// --- ES256 issuer ----------------------------------------------------------

// ES256Issuer issues SD-JWT VCs signed with ECDSA on P-256 (JOSE alg "ES256"),
// the algorithm the EUDI ARF and OpenID4VC HAIP mandate.
//
// It deliberately exposes no PrivateKey() accessor: the Ed25519-only
// subsystems (SCITT, did:webvh, status lists) must not be reachable with a
// P-256 key. Use a regular Issuer for those.
type ES256Issuer struct {
	ID         string
	privateKey *ecdsa.PrivateKey

	// DecoyDigests mirrors Issuer.DecoyDigests — the number of dummy `_sd`
	// digests to add, hiding the true count of selectively-disclosable claims.
	DecoyDigests int
	// SDJWTVCType overrides the JWS `typ`; empty uses the current `dc+sd-jwt`.
	SDJWTVCType string
}

// NewES256Issuer generates a fresh P-256 key pair and returns an ES256 issuer.
func NewES256Issuer(id string) (*ES256Issuer, error) {
	if id == "" {
		return nil, errors.New("issuer ID required")
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keygen: %w", err)
	}
	return &ES256Issuer{ID: id, privateKey: priv}, nil
}

// NewES256IssuerFromKey adopts an existing P-256 private key — the path an
// operator uses when the key lives in an HSM-backed or pre-provisioned form.
func NewES256IssuerFromKey(id string, priv *ecdsa.PrivateKey) (*ES256Issuer, error) {
	if id == "" {
		return nil, errors.New("issuer ID required")
	}
	if priv == nil || priv.Curve != elliptic.P256() {
		return nil, ErrNotP256
	}
	return &ES256Issuer{ID: id, privateKey: priv}, nil
}

// PublicKey returns the issuer's public key as an uncompressed SEC1 point
// (0x04 || X || Y) — the form compliance.VerifySDJWTWithBinding and
// didresolver.PublicKey.Bytes both use, so it can be passed straight to
// verification with no conversion.
func (i *ES256Issuer) PublicKey() []byte {
	b, err := ecdsakey.MarshalP256PublicKey(&i.privateKey.PublicKey)
	if err != nil {
		return nil
	}
	return b
}

// PublicKeyECDSA returns the raw public key, for callers that need to publish a
// JWK or a Multikey.
func (i *ES256Issuer) PublicKeyECDSA() *ecdsa.PublicKey { return &i.privateKey.PublicKey }

// Alg reports the JOSE algorithm this issuer signs with.
func (i *ES256Issuer) Alg() string { return "ES256" }

func (i *ES256Issuer) jwsAlg() string  { return "ES256" }
func (i *ES256Issuer) decoyCount() int { return i.DecoyDigests }
func (i *ES256Issuer) sdjwtTyp() string {
	if i.SDJWTVCType != "" {
		return i.SDJWTVCType
	}
	return "dc+sd-jwt"
}

// signJWS produces the fixed-width R‖S signature form that RFC 7518 §3.4
// mandates for ES256 — 32 octets each, big-endian, leading zeros preserved.
// FillBytes does the zero-padding; using r.Bytes() would emit a short encoding
// whenever r or s happens to have a leading zero byte (roughly 1 signature in
// 256), producing signatures that conforming verifiers reject.
func (i *ES256Issuer) signJWS(signingInput []byte) ([]byte, error) {
	digest := sha256.Sum256(signingInput)
	r, s, err := ecdsa.Sign(rand.Reader, i.privateKey, digest[:])
	if err != nil {
		return nil, fmt.Errorf("compliance: ES256 sign: %w", err)
	}
	out := make([]byte, ecdsakey.ES256SignatureSize)
	r.FillBytes(out[:ecdsakey.P256CoordSize])
	s.FillBytes(out[ecdsakey.P256CoordSize:])
	return out, nil
}

// --- Issuance API (mirrors the Ed25519 Issuer's shape) ---------------------

// IssueSDJWTVC issues an ES256-signed SD-JWT VC with the given type.
func (i *ES256Issuer) IssueSDJWTVC(vct, subject string, sdClaims, clearClaims map[string]any, validFor time.Duration) (string, []Disclosure, error) {
	return buildSDJWT(i, i.ID, vct, subject, sdClaims, clearClaims, nil, nil, validFor)
}

// IssueSDJWT issues an ES256-signed SD-JWT VC with the default DPP type.
func (i *ES256Issuer) IssueSDJWT(subject string, sdClaims, clearClaims map[string]any, validFor time.Duration) (string, []Disclosure, error) {
	return i.IssueSDJWTVC(VCTDigitalProductPassport, subject, sdClaims, clearClaims, validFor)
}

// IssueSDJWTVCStatus issues an ES256-signed SD-JWT VC carrying a revocation
// reference.
func (i *ES256Issuer) IssueSDJWTVCStatus(vct, subject string, sdClaims, clearClaims map[string]any, status *StatusRef, validFor time.Duration) (string, []Disclosure, error) {
	return buildSDJWT(i, i.ID, vct, subject, sdClaims, clearClaims, nil, status, validFor)
}

// IssueSDJWTVCBound issues an ES256-signed SD-JWT VC bound to a holder key
// (cnf), so the holder can later produce a KB-JWT.
//
// holderPub is an Ed25519 key: holder binding and issuer signing are
// independent choices, and the KB-JWT path remains Ed25519 in this build.
func (i *ES256Issuer) IssueSDJWTVCBound(vct, subject string, sdClaims, clearClaims map[string]any, holderPub []byte, validFor time.Duration) (string, []Disclosure, error) {
	return buildSDJWT(i, i.ID, vct, subject, sdClaims, clearClaims, holderPub, nil, validFor)
}
