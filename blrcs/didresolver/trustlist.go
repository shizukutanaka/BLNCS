package didresolver

// Trust List — a signed, versioned allow-list of authorized credential issuers.
//
// A valid issuer signature proves *who* signed a credential, never that the
// signer is an *authorized* DPP/Battery-Passport issuer: a counterfeiter can mint
// a perfectly-valid SD-JWT under their own DID. The missing link is an authority
// (an EU DPP registry / competent authority) publishing "these DIDs are
// authorized issuers" in a form verifiers can consume without hard-coding keys.
//
// TrustList is that artifact (conceptually an ETSI TS 119 612 Trusted List, kept
// minimal and zero-dependency). It is Ed25519-signed by the authority, carries an
// expiry and a monotonic version, and marks each issuer active/suspended/revoked.
// A verifier turns the active entries into a *TrustAnchor*. Defenses:
//
//   - forged list      → Ed25519 signature over the canonical payload,
//   - stale list       → `exp` expiry (with clock-skew leeway),
//   - revoked issuer   → only `active` entries become trusted (fail-closed),
//   - rollback attack  → monotonic `version`; TrustListVerifier rejects an older
//     version than the highest already accepted (replaying an old list that still
//     trusts a since-revoked issuer is refused).

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Trust-list errors.
var (
	ErrTrustListMalformed = errors.New("didresolver: trust list malformed")
	ErrTrustListSig       = errors.New("didresolver: trust list signature invalid")
	ErrTrustListExpired   = errors.New("didresolver: trust list expired")
	// ErrTrustListRollback is returned by TrustListVerifier when a presented list
	// has a version less than the highest already accepted — a downgrade/rollback
	// attempt to re-trust a since-revoked issuer.
	ErrTrustListRollback = errors.New("didresolver: trust list version older than current (rollback)")
)

// trustListLeeway bounds acceptable clock skew on the expiry check.
const trustListLeeway = 60 * time.Second

// IssuerStatus is the authorization state of a listed issuer.
type IssuerStatus string

const (
	IssuerActive    IssuerStatus = "active"
	IssuerSuspended IssuerStatus = "suspended"
	IssuerRevoked   IssuerStatus = "revoked"
)

// TrustListEntry authorizes a single issuer.
type TrustListEntry struct {
	DID string `json:"did"`
	// KeyHash optionally pins the issuer's Ed25519 public key as a lowercase
	// SHA-256 hex digest. When set it is registered alongside the DID, so a
	// verifier can trust the exact key even across DID-document changes.
	KeyHash string       `json:"keyHash,omitempty"`
	Status  IssuerStatus `json:"status"`
	// Scope optionally narrows the authorization (e.g. "battery", "textile").
	Scope string `json:"scope,omitempty"`
}

// TrustList is the authority-signed payload.
type TrustList struct {
	Authority string           `json:"authority"` // DID of the issuing authority
	Version   uint64           `json:"version"`   // monotonic; higher supersedes lower
	IssuedAt  int64            `json:"iat"`       // unix seconds
	Expires   int64            `json:"exp,omitempty"`
	Entries   []TrustListEntry `json:"entries"`
}

// SignTrustList serializes tl and signs it with the authority key, returning the
// compact form "<base64url(payload)>.<base64url(signature)>". The signature
// covers the exact transmitted payload bytes (like JWS), so verification needs no
// canonicalization step.
func SignTrustList(tl *TrustList, priv ed25519.PrivateKey) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("%w: bad private key", ErrTrustListMalformed)
	}
	if err := validateTrustList(tl); err != nil {
		return "", err
	}
	payload, err := json.Marshal(tl)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrTrustListMalformed, err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	sig := ed25519.Sign(priv, []byte(payloadB64))
	return payloadB64 + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyTrustList verifies the signature and expiry against the current time.
func VerifyTrustList(signed string, authorityPub ed25519.PublicKey) (*TrustList, error) {
	return VerifyTrustListAt(signed, authorityPub, time.Now())
}

// VerifyTrustListAt verifies the signature against authorityPub and the expiry at
// `now` (with leeway), returning the parsed list. It does NOT enforce version
// rollback — use TrustListVerifier for that.
func VerifyTrustListAt(signed string, authorityPub ed25519.PublicKey, now time.Time) (*TrustList, error) {
	if len(authorityPub) != ed25519.PublicKeySize {
		return nil, ErrTrustListSig
	}
	payloadB64, sigB64, ok := strings.Cut(signed, ".")
	if !ok || payloadB64 == "" || sigB64 == "" {
		return nil, ErrTrustListMalformed
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, ErrTrustListMalformed
	}
	// Verify over the received payload bytes (no re-serialization).
	if !ed25519.Verify(authorityPub, []byte(payloadB64), sig) {
		return nil, ErrTrustListSig
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, ErrTrustListMalformed
	}
	var tl TrustList
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&tl); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTrustListMalformed, err)
	}
	if err := validateTrustList(&tl); err != nil {
		return nil, err
	}
	if tl.Expires != 0 && now.After(time.Unix(tl.Expires, 0).Add(trustListLeeway)) {
		return nil, ErrTrustListExpired
	}
	return &tl, nil
}

// validateTrustList checks structural well-formedness independent of signature.
func validateTrustList(tl *TrustList) error {
	if tl == nil || tl.Authority == "" {
		return fmt.Errorf("%w: missing authority", ErrTrustListMalformed)
	}
	seen := make(map[string]struct{}, len(tl.Entries))
	for i := range tl.Entries {
		e := &tl.Entries[i]
		if e.DID == "" {
			return fmt.Errorf("%w: entry %d missing did", ErrTrustListMalformed, i)
		}
		if _, dup := seen[e.DID]; dup {
			return fmt.Errorf("%w: duplicate entry for %s", ErrTrustListMalformed, e.DID)
		}
		seen[e.DID] = struct{}{}
		switch e.Status {
		case IssuerActive, IssuerSuspended, IssuerRevoked:
		default:
			return fmt.Errorf("%w: entry %s has invalid status %q", ErrTrustListMalformed, e.DID, e.Status)
		}
		if e.KeyHash != "" && !isSHA256Hex(e.KeyHash) {
			return fmt.Errorf("%w: entry %s has invalid keyHash", ErrTrustListMalformed, e.DID)
		}
	}
	return nil
}

// isSHA256Hex reports whether s is a 64-character lowercase hex string.
func isSHA256Hex(s string) bool {
	if len(s) != 2*sha256.Size {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ToTrustAnchor builds a TrustAnchor from the list's **active** entries only:
// suspended and revoked issuers are intentionally excluded (fail-closed). Only
// the DIDs are registered — NOT pinned key hashes. TrustAnchor.IsTrusted matches
// a DID OR a key hash independently, so registering a key hash here would trust
// that key under *any* DID, breaking the per-DID binding a `keyHash` pin is meant
// to express. For pin-enforcing checks (key authorized only for its DID) use
// Authorizes, which keeps the binding. The DID allow-list composes directly with
// ResolveAndVerifyAll.
func (tl *TrustList) ToTrustAnchor() *TrustAnchor {
	ta := NewTrustAnchor()
	for i := range tl.Entries {
		e := &tl.Entries[i]
		if e.Status != IssuerActive {
			continue
		}
		ta.AddDID(e.DID)
	}
	return ta
}

// Authorizes reports whether did is listed as an active issuer. When the matching
// entry pins a KeyHash, pub must match it (defense-in-depth key binding); when no
// KeyHash is pinned, any resolved key for the DID is accepted.
func (tl *TrustList) Authorizes(did string, pub ed25519.PublicKey) bool {
	for i := range tl.Entries {
		e := &tl.Entries[i]
		if e.DID != did || e.Status != IssuerActive {
			continue
		}
		if e.KeyHash == "" {
			return true
		}
		sum := sha256.Sum256(pub)
		return hex.EncodeToString(sum[:]) == e.KeyHash
	}
	return false
}

// AddKeyHash trusts an Ed25519 public key by its SHA-256 hex digest without
// needing the key bytes — used when loading pinned keys from a trust list. The
// digest is lowercased to match AddKey's stored form.
func (t *TrustAnchor) AddKeyHash(hexHash string) {
	t.mu.Lock()
	t.keyHashes[strings.ToLower(hexHash)] = true
	t.mu.Unlock()
}

// TrustListVerifier verifies successive trust lists from one authority and
// enforces monotonic versioning, defeating rollback attacks that replay an older
// list to re-trust a since-revoked issuer. Safe for concurrent use.
type TrustListVerifier struct {
	authority ed25519.PublicKey
	mu        sync.Mutex
	version   uint64
	seen      bool
}

// NewTrustListVerifier constructs a verifier pinned to the authority's key.
func NewTrustListVerifier(authorityPub ed25519.PublicKey) *TrustListVerifier {
	return &TrustListVerifier{authority: append(ed25519.PublicKey(nil), authorityPub...)}
}

// Verify checks signature + expiry + monotonic version at the current time,
// advancing the accepted version on success.
func (v *TrustListVerifier) Verify(signed string) (*TrustList, error) {
	return v.VerifyAt(signed, time.Now())
}

// VerifyAt is Verify with an injectable clock. A list whose version is lower than
// the highest already accepted is rejected with ErrTrustListRollback; a list with
// the same version is accepted (idempotent refresh) but does not lower the bar.
func (v *TrustListVerifier) VerifyAt(signed string, now time.Time) (*TrustList, error) {
	tl, err := VerifyTrustListAt(signed, v.authority, now)
	if err != nil {
		return nil, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.seen && tl.Version < v.version {
		return nil, fmt.Errorf("%w: got %d, current %d", ErrTrustListRollback, tl.Version, v.version)
	}
	if !v.seen || tl.Version > v.version {
		v.version = tl.Version
		v.seen = true
	}
	return tl, nil
}

// CurrentVersion returns the highest accepted version (0 before any accepted).
func (v *TrustListVerifier) CurrentVersion() uint64 {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.version
}
