package compliance

import (
	"crypto/ed25519"
	"crypto/rand"
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
