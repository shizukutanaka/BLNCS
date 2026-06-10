package compliance

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// SD-JWT expiry validation (VerifySDJWT must reject expired / not-yet-valid)
// ============================================================================

func TestVerifySDJWTRejectsExpired(t *testing.T) {
	iss, _ := NewIssuer("did:web:test")
	sdjwt, _, err := iss.IssueSDJWT("sub", map[string]any{"x": 1}, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Within validity → ok.
	if _, err := VerifySDJWTAt(sdjwt, iss.PublicKey(), time.Now()); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	// Two hours later (past exp + leeway) → expired.
	if _, err := VerifySDJWTAt(sdjwt, iss.PublicKey(), time.Now().Add(2*time.Hour)); err != ErrSDJWTExpired {
		t.Fatalf("want ErrSDJWTExpired, got %v", err)
	}
}

func TestVerifySDJWTRejectsNotYetValid(t *testing.T) {
	iss, _ := NewIssuer("did:web:test")
	sdjwt, _, _ := iss.IssueSDJWT("sub", map[string]any{"x": 1}, nil, time.Hour)
	// Verify with clock two hours in the past → iat is in the future.
	if _, err := VerifySDJWTAt(sdjwt, iss.PublicKey(), time.Now().Add(-2*time.Hour)); err != ErrSDJWTNotYetValid {
		t.Fatalf("want ErrSDJWTNotYetValid, got %v", err)
	}
}

func TestVerifySDJWTNoExpiryNeverExpires(t *testing.T) {
	iss, _ := NewIssuer("did:web:test")
	sdjwt, _, _ := iss.IssueSDJWT("sub", map[string]any{"x": 1}, nil, 0) // no exp
	if _, err := VerifySDJWTAt(sdjwt, iss.PublicKey(), time.Now().Add(100*365*24*time.Hour)); err != nil {
		t.Fatalf("no-exp token should never expire: %v", err)
	}
}

// ============================================================================
// SD-JWT Key Binding (KB-JWT)
// ============================================================================

func TestIssueSDJWTBoundBadHolderKey(t *testing.T) {
	iss, _ := NewIssuer("did:web:issuer")
	if _, _, err := iss.IssueSDJWTBound("s", nil, nil, []byte("short"), time.Hour); err != ErrHolderKeyRequired {
		t.Fatalf("want ErrHolderKeyRequired, got %v", err)
	}
}

func TestPresentWithKeyBindingBadHolderKey(t *testing.T) {
	if _, err := PresentWithKeyBinding("jwt~", nil, []byte("short"), "n", "aud", time.Time{}); err != ErrHolderKeyRequired {
		t.Fatalf("want ErrHolderKeyRequired, got %v", err)
	}
}

func TestKeyBindingRoundTrip(t *testing.T) {
	iss, _ := NewIssuer("did:web:issuer")
	holderPub, holderPriv, _ := ed25519.GenerateKey(rand.Reader)
	sdjwt, _, err := iss.IssueSDJWTBound("holder-1",
		map[string]any{"carbon": 2.5}, map[string]any{"pid": "P1"}, holderPub, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// A bound credential presented WITHOUT a KB-JWT must be rejected.
	if _, err := VerifySDJWT(sdjwt, iss.PublicKey()); err != ErrKeyBindingMissing {
		t.Fatalf("bound cred without KB-JWT: want ErrKeyBindingMissing, got %v", err)
	}
	// Holder presents with a KB-JWT bound to the verifier nonce/aud.
	pres, err := PresentWithKeyBinding(sdjwt, []string{"carbon"}, holderPriv,
		"nonce-abc", "https://verifier.example", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	vc, err := VerifySDJWTWithBinding(pres, iss.PublicKey(), VerifyOptions{
		ExpectedNonce:    "nonce-abc",
		ExpectedAudience: "https://verifier.example",
	})
	if err != nil {
		t.Fatalf("bound verify: %v", err)
	}
	if !vc.KeyBound {
		t.Error("KeyBound should be true")
	}
	if vc.HolderKey == nil {
		t.Error("holder key should be extracted from cnf")
	}
	if vc.Claims["carbon"] == nil {
		t.Error("carbon claim should be disclosed")
	}
	if vc.Claims["pid"] != "P1" {
		t.Errorf("clear claim pid: %v", vc.Claims["pid"])
	}
}

func TestKeyBindingWrongNonce(t *testing.T) {
	iss, _ := NewIssuer("did:web:issuer")
	holderPub, holderPriv, _ := ed25519.GenerateKey(rand.Reader)
	sdjwt, _, _ := iss.IssueSDJWTBound("h", map[string]any{"a": 1}, nil, holderPub, time.Hour)
	pres, _ := PresentWithKeyBinding(sdjwt, []string{"a"}, holderPriv, "good-nonce", "aud", time.Time{})
	if _, err := VerifySDJWTWithBinding(pres, iss.PublicKey(), VerifyOptions{
		ExpectedNonce: "WRONG", ExpectedAudience: "aud",
	}); err != ErrKeyBindingNonce {
		t.Fatalf("want ErrKeyBindingNonce, got %v", err)
	}
}

func TestKeyBindingWrongAudience(t *testing.T) {
	iss, _ := NewIssuer("did:web:issuer")
	holderPub, holderPriv, _ := ed25519.GenerateKey(rand.Reader)
	sdjwt, _, _ := iss.IssueSDJWTBound("h", map[string]any{"a": 1}, nil, holderPub, time.Hour)
	pres, _ := PresentWithKeyBinding(sdjwt, []string{"a"}, holderPriv, "n", "good-aud", time.Time{})
	if _, err := VerifySDJWTWithBinding(pres, iss.PublicKey(), VerifyOptions{
		ExpectedNonce: "n", ExpectedAudience: "WRONG",
	}); err != ErrKeyBindingNonce {
		t.Fatalf("want ErrKeyBindingNonce, got %v", err)
	}
}

func TestKeyBindingWrongHolderKey(t *testing.T) {
	iss, _ := NewIssuer("did:web:issuer")
	holderPub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, evilPriv, _ := ed25519.GenerateKey(rand.Reader)
	sdjwt, _, _ := iss.IssueSDJWTBound("h", map[string]any{"a": 1}, nil, holderPub, time.Hour)
	// KB-JWT signed by a key that does NOT match cnf.
	pres, _ := PresentWithKeyBinding(sdjwt, []string{"a"}, evilPriv, "n", "aud", time.Time{})
	if _, err := VerifySDJWTWithBinding(pres, iss.PublicKey(), VerifyOptions{
		ExpectedNonce: "n", ExpectedAudience: "aud",
	}); err != ErrKeyBindingInvalid {
		t.Fatalf("want ErrKeyBindingInvalid, got %v", err)
	}
}

func TestKeyBindingTamperedDisclosures(t *testing.T) {
	iss, _ := NewIssuer("did:web:issuer")
	holderPub, holderPriv, _ := ed25519.GenerateKey(rand.Reader)
	sdjwt, discs, _ := iss.IssueSDJWTBound("h", map[string]any{"a": 1, "b": 2}, nil, holderPub, time.Hour)
	// Holder presents only "a"; sd_hash covers exactly that presentation.
	pres, _ := PresentWithKeyBinding(sdjwt, []string{"a"}, holderPriv, "n", "aud", time.Time{})
	// Attacker splices the hidden "b" disclosure in front of the KB-JWT.
	var bEnc string
	for _, d := range discs {
		if d.Name == "b" {
			bEnc = d.Encoded
		}
	}
	idx := strings.LastIndex(pres, "~")
	tampered := pres[:idx] + "~" + bEnc + pres[idx:]
	if _, err := VerifySDJWTWithBinding(tampered, iss.PublicKey(), VerifyOptions{
		ExpectedNonce: "n", ExpectedAudience: "aud",
	}); err != ErrKeyBindingSDHash {
		t.Fatalf("want ErrKeyBindingSDHash, got %v", err)
	}
}

func TestRequireKeyBindingRejectsUnbound(t *testing.T) {
	iss, _ := NewIssuer("did:web:issuer")
	sdjwt, _, _ := iss.IssueSDJWT("s", map[string]any{"a": 1}, nil, time.Hour) // no cnf
	if _, err := VerifySDJWTWithBinding(sdjwt, iss.PublicKey(), VerifyOptions{
		RequireKeyBinding: true,
	}); err != ErrHolderKeyRequired {
		t.Fatalf("want ErrHolderKeyRequired, got %v", err)
	}
}

// TestVerifyBareJWTNoTilde — a validly-signed JWT with no '~' separator (e.g. an
// attacker stripping the disclosure tail off an observed vp_token) must not panic.
func TestVerifyBareJWTNoTilde(t *testing.T) {
	iss, _ := NewIssuer("did:web:issuer")
	sdjwt, _, _ := iss.IssueSDJWT("s", map[string]any{"a": 1}, nil, time.Hour)
	bare := sdjwt[:strings.IndexByte(sdjwt, '~')] // "header.payload.sig", no '~'
	// Issuer signature is still valid; must return cleanly (no disclosures), not panic.
	vc, err := VerifySDJWTAt(bare, iss.PublicKey(), time.Now())
	if err != nil {
		t.Fatalf("bare JWT should verify without disclosures: %v", err)
	}
	if len(vc.Claims) != 0 {
		t.Errorf("bare JWT should disclose no SD claims, got %v", vc.Claims)
	}
	// A bare JWT carrying cnf (bound) but no KB-JWT must be rejected, not panic.
	holderPub, _, _ := ed25519.GenerateKey(rand.Reader)
	bound, _, _ := iss.IssueSDJWTBound("s", map[string]any{"a": 1}, nil, holderPub, time.Hour)
	bareBound := bound[:strings.IndexByte(bound, '~')]
	if _, err := VerifySDJWTAt(bareBound, iss.PublicKey(), time.Now()); err != ErrKeyBindingMissing {
		t.Fatalf("bare bound JWT: want ErrKeyBindingMissing, got %v", err)
	}
}

// TestKeyBindingAudienceArray — a KB-JWT whose `aud` is a JSON array (allowed by
// the JWT spec) must match when one element equals the expected audience.
func TestKeyBindingAudienceArray(t *testing.T) {
	if !audienceMatches([]any{"https://other.example", "https://verifier.example"}, "https://verifier.example") {
		t.Error("aud array containing the expected audience should match")
	}
	if audienceMatches([]any{"https://other.example"}, "https://verifier.example") {
		t.Error("aud array without the expected audience must not match")
	}
	if !audienceMatches("https://verifier.example", "https://verifier.example") {
		t.Error("string aud should still match")
	}
}

// TestKeyBindingMaxKBAge — a KB-JWT whose iat is older than MaxKBAge must be rejected.
func TestKeyBindingMaxKBAge(t *testing.T) {
	iss, _ := NewIssuer("did:web:issuer")
	holderPub, holderPriv, _ := ed25519.GenerateKey(rand.Reader)
	sdjwt, _, _ := iss.IssueSDJWTBound("h", map[string]any{"a": 1}, nil, holderPub, time.Hour)
	// KB-JWT signed at time T (time.Time{} → time.Now() inside PresentWithKeyBinding).
	presentedAt := time.Now()
	pres, _ := PresentWithKeyBinding(sdjwt, []string{"a"}, holderPriv, "n", "aud", presentedAt)
	// Verifier checks an hour later with MaxKBAge of 30 seconds → iat too old.
	if _, err := VerifySDJWTWithBinding(pres, iss.PublicKey(), VerifyOptions{
		ExpectedNonce:    "n",
		ExpectedAudience: "aud",
		Now:              presentedAt.Add(1 * time.Hour),
		MaxKBAge:         30 * time.Second,
	}); err != ErrKeyBindingInvalid {
		t.Fatalf("want ErrKeyBindingInvalid (MaxKBAge exceeded), got %v", err)
	}
}

// craftKBJWT builds a KB-JWT segment for testing edge-cases in verifyKBJWT.
func craftKBJWT(t *testing.T, holderPriv ed25519.PrivateKey, payload map[string]any) string {
	t.Helper()
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"kb+jwt"}`))
	plBytes, _ := json.Marshal(payload)
	pl := base64.RawURLEncoding.EncodeToString(plBytes)
	sig := ed25519.Sign(holderPriv, []byte(hdr+"."+pl))
	return hdr + "." + pl + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// sdHashFor computes the sd_hash that verifyKBJWT expects for a given base presentation.
// base must end with '~' (output of Present).
func sdHashFor(base string) string {
	h := sha256.Sum256([]byte(base))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// TestKeyBindingFutureIat — a KB-JWT whose iat is far in the future (beyond leeway) is rejected.
func TestKeyBindingFutureIat(t *testing.T) {
	iss, _ := NewIssuer("did:web:issuer")
	holderPub, holderPriv, _ := ed25519.GenerateKey(rand.Reader)
	sdjwt, _, _ := iss.IssueSDJWTBound("h", map[string]any{"a": 1}, nil, holderPub, time.Hour)
	base, _ := Present(sdjwt, []string{"a"})
	now := time.Now()
	kb := craftKBJWT(t, holderPriv, map[string]any{
		"iat":     float64(now.Add(10 * time.Minute).Unix()), // 10 min in future
		"nonce":   "n",
		"aud":     "aud",
		"sd_hash": sdHashFor(base),
	})
	pres := base + kb
	if _, err := VerifySDJWTWithBinding(pres, iss.PublicKey(), VerifyOptions{
		ExpectedNonce:    "n",
		ExpectedAudience: "aud",
		Now:              now,
		Leeway:           60 * time.Second, // only 60s allowed → 10min iat is future
	}); err != ErrKeyBindingInvalid {
		t.Fatalf("want ErrKeyBindingInvalid (future iat), got %v", err)
	}
}

// TestKeyBindingBadKBJWTFormat — various malformed KB-JWT formats must be rejected.
func TestKeyBindingBadKBJWTFormat(t *testing.T) {
	iss, _ := NewIssuer("did:web:issuer")
	holderPub, _, _ := ed25519.GenerateKey(rand.Reader)
	sdjwt, _, _ := iss.IssueSDJWTBound("h", map[string]any{"a": 1}, nil, holderPub, time.Hour)
	base, _ := Present(sdjwt, []string{"a"})

	// Attach a KB-JWT with too few segments (only 2 parts).
	pres1 := base + "onlytwo.parts"
	if _, err := VerifySDJWTWithBinding(pres1, iss.PublicKey(), VerifyOptions{}); err != ErrKeyBindingInvalid {
		t.Fatalf("two-segment KB-JWT: want ErrKeyBindingInvalid, got %v", err)
	}
	// Attach a KB-JWT whose header is invalid base64.
	pres2 := base + "!!!.payload.sig"
	if _, err := VerifySDJWTWithBinding(pres2, iss.PublicKey(), VerifyOptions{}); err != ErrKeyBindingInvalid {
		t.Fatalf("bad-base64 header: want ErrKeyBindingInvalid, got %v", err)
	}
	// Attach a KB-JWT with a valid base64 header but wrong typ.
	wrongTypHdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT"}`))
	pres3 := base + wrongTypHdr + ".payload.sig"
	if _, err := VerifySDJWTWithBinding(pres3, iss.PublicKey(), VerifyOptions{}); err != ErrKeyBindingInvalid {
		t.Fatalf("wrong typ: want ErrKeyBindingInvalid, got %v", err)
	}
}

// TestKeyBindingMissingIat — a KB-JWT without iat must be rejected.
func TestKeyBindingMissingIat(t *testing.T) {
	iss, _ := NewIssuer("did:web:issuer")
	holderPub, holderPriv, _ := ed25519.GenerateKey(rand.Reader)
	sdjwt, _, _ := iss.IssueSDJWTBound("h", map[string]any{"a": 1}, nil, holderPub, time.Hour)
	base, _ := Present(sdjwt, []string{"a"})
	kb := craftKBJWT(t, holderPriv, map[string]any{
		"nonce":   "n",
		"aud":     "aud",
		"sd_hash": sdHashFor(base),
		// no "iat" — must be rejected
	})
	pres := base + kb
	if _, err := VerifySDJWTWithBinding(pres, iss.PublicKey(), VerifyOptions{
		ExpectedNonce:    "n",
		ExpectedAudience: "aud",
	}); err != ErrKeyBindingInvalid {
		t.Fatalf("want ErrKeyBindingInvalid (missing iat), got %v", err)
	}
}
