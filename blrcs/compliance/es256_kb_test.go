package compliance

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"blrcs/ecdsakey"
)

// ============================================================================
// Axis 142: ES256 (P-256) holder binding — KB-JWT
//
// An EUDI wallet's device key is P-256, so the key-binding JWT it produces is
// ES256-signed. The verifier previously pinned the KB-JWT alg to EdDSA and the
// cnf key to OKP/Ed25519, so a real EUDI presentation could not complete even
// though the credential (Axis 137) and its resolution (Axis 136) were fine.
// ============================================================================

func p256Holder(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ecdsakey.MarshalP256PublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

// TestES256HolderBindingRoundTrip is the full EUDI-shaped presentation: an
// ES256 issuer binds to a P-256 holder key, and the holder presents with an
// ES256 KB-JWT bound to the verifier's nonce/audience.
func TestES256HolderBindingRoundTrip(t *testing.T) {
	iss, err := NewES256Issuer("did:web:eudi-issuer.europa.eu")
	if err != nil {
		t.Fatal(err)
	}
	holderPriv, holderPub := p256Holder(t)

	sdjwt, _, err := iss.IssueSDJWTVCBound("DigitalProductPassport", "battery-001",
		map[string]any{"carbonKgCO2ePerKWh": 42.0}, nil, holderPub, time.Hour)
	if err != nil {
		t.Fatalf("issue bound: %v", err)
	}

	// The credential must carry an EC/P-256 cnf.
	payload := kbPayload(t, sdjwt)
	cnf := payload["cnf"].(map[string]any)["jwk"].(map[string]any)
	if cnf["kty"] != "EC" || cnf["crv"] != "P-256" {
		t.Fatalf("cnf should be EC/P-256, got %v", cnf)
	}

	const nonce, aud = "verifier-nonce-xyz", "did:web:verifier.example"
	presented, err := PresentWithKeyBindingES256(sdjwt, []string{"carbonKgCO2ePerKWh"},
		holderPriv, nonce, aud, nil, time.Now())
	if err != nil {
		t.Fatalf("present ES256 KB: %v", err)
	}

	vc, err := VerifySDJWTWithBinding(presented, iss.PublicKey(), VerifyOptions{
		RequireKeyBinding: true, ExpectedNonce: nonce, ExpectedAudience: aud,
	})
	if err != nil {
		t.Fatalf("ES256-bound presentation should verify: %v", err)
	}
	if !vc.KeyBound {
		t.Error("presentation should be reported as key-bound")
	}
	if len(vc.HolderKeyES256) != ecdsakey.P256UncompressedSize {
		t.Errorf("holder key should be P-256, got %d bytes / ed25519=%v", len(vc.HolderKeyES256), vc.HolderKey)
	}
	if vc.Claims["carbonKgCO2ePerKWh"] != 42.0 {
		t.Errorf("disclosed claim missing: %+v", vc.Claims)
	}
}

// TestES256KBWrongNonceRejected proves the KB-JWT is still bound to the session.
func TestES256KBWrongNonceRejected(t *testing.T) {
	iss, _ := NewES256Issuer("did:web:i")
	holderPriv, holderPub := p256Holder(t)
	sdjwt, _, _ := iss.IssueSDJWTVCBound("DigitalProductPassport", "s", map[string]any{"a": 1.0}, nil, holderPub, time.Hour)

	presented, err := PresentWithKeyBindingES256(sdjwt, []string{"a"}, holderPriv, "right-nonce", "aud", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySDJWTWithBinding(presented, iss.PublicKey(), VerifyOptions{
		RequireKeyBinding: true, ExpectedNonce: "WRONG-nonce", ExpectedAudience: "aud",
	}); err == nil {
		t.Fatal("a KB-JWT with the wrong nonce must not verify")
	}
}

// TestES256KBWrongHolderKeyRejected proves the binding is to THE cnf key: a
// KB-JWT signed by a different P-256 key must fail.
func TestES256KBWrongHolderKeyRejected(t *testing.T) {
	iss, _ := NewES256Issuer("did:web:i")
	_, boundPub := p256Holder(t)
	attackerPriv, _ := p256Holder(t)
	sdjwt, _, _ := iss.IssueSDJWTVCBound("DigitalProductPassport", "s", map[string]any{"a": 1.0}, nil, boundPub, time.Hour)

	// Attacker signs the KB-JWT with their own key, not the bound one.
	presented, err := PresentWithKeyBindingES256(sdjwt, []string{"a"}, attackerPriv, "n", "aud", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySDJWTWithBinding(presented, iss.PublicKey(), VerifyOptions{
		RequireKeyBinding: true, ExpectedNonce: "n", ExpectedAudience: "aud",
	}); err == nil {
		t.Fatal("a KB-JWT signed by a non-bound key must not verify")
	}
}

// TestKBAlgMustMatchCnfKey is the algorithm-confusion defence: a credential
// bound to a P-256 key must reject an EdDSA KB-JWT, and one bound to an Ed25519
// key must reject an ES256 KB-JWT — the binding is to the cnf key's algorithm.
func TestKBAlgMustMatchCnfKey(t *testing.T) {
	// Credential bound to a P-256 key, presented with an EdDSA KB-JWT.
	iss, _ := NewES256Issuer("did:web:i")
	_, holderPub := p256Holder(t)
	edPriv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	sdjwtP256, _, _ := iss.IssueSDJWTVCBound("DigitalProductPassport", "s", map[string]any{"a": 1.0}, nil, holderPub, time.Hour)
	presented, err := PresentWithKeyBindingTx(sdjwtP256, []string{"a"}, edPriv, "n", "aud", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySDJWTWithBinding(presented, iss.PublicKey(), VerifyOptions{
		RequireKeyBinding: true, ExpectedNonce: "n", ExpectedAudience: "aud",
	}); err == nil {
		t.Error("an EdDSA KB-JWT against a P-256 cnf must be rejected")
	}

	// Credential bound to an Ed25519 key, presented with an ES256 KB-JWT.
	edIss, _ := NewIssuer("did:web:ed")
	edHolderPub, _, _ := ed25519.GenerateKey(rand.Reader)
	p256Priv, _ := p256Holder(t)
	sdjwtEd, _, _ := edIss.IssueSDJWTVCBound("DigitalProductPassport", "s", map[string]any{"a": 1.0}, nil, edHolderPub, time.Hour)
	presentedEd, err := PresentWithKeyBindingES256(sdjwtEd, []string{"a"}, p256Priv, "n", "aud", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySDJWTWithBinding(presentedEd, edIss.PublicKey(), VerifyOptions{
		RequireKeyBinding: true, ExpectedNonce: "n", ExpectedAudience: "aud",
	}); err == nil {
		t.Error("an ES256 KB-JWT against an Ed25519 cnf must be rejected")
	}
}

// TestES256HolderTransactionDataBinding proves transaction_data binding works
// over the ES256 KB-JWT path too.
func TestES256HolderTransactionDataBinding(t *testing.T) {
	iss, _ := NewES256Issuer("did:web:i")
	holderPriv, holderPub := p256Holder(t)
	sdjwt, _, _ := iss.IssueSDJWTVCBound("DigitalProductPassport", "s", map[string]any{"a": 1.0}, nil, holderPub, time.Hour)

	txData := []string{base64.RawURLEncoding.EncodeToString([]byte(`{"type":"payment","amount":"100"}`))}
	presented, err := PresentWithKeyBindingES256(sdjwt, []string{"a"}, holderPriv, "n", "aud", txData, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Matching transaction_data verifies.
	if _, err := VerifySDJWTWithBinding(presented, iss.PublicKey(), VerifyOptions{
		RequireKeyBinding: true, ExpectedNonce: "n", ExpectedAudience: "aud", ExpectedTransactionData: txData,
	}); err != nil {
		t.Fatalf("matching transaction_data should verify: %v", err)
	}
	// Different transaction_data must fail.
	otherTx := []string{base64.RawURLEncoding.EncodeToString([]byte(`{"type":"payment","amount":"999"}`))}
	if _, err := VerifySDJWTWithBinding(presented, iss.PublicKey(), VerifyOptions{
		RequireKeyBinding: true, ExpectedNonce: "n", ExpectedAudience: "aud", ExpectedTransactionData: otherTx,
	}); err == nil {
		t.Error("mismatched transaction_data must be rejected")
	}
}

// TestExtractHolderKeyP256 unit-tests the cnf parser's P-256 branch, including
// the invalid-curve rejection.
func TestExtractHolderKeyP256(t *testing.T) {
	_, pub := p256Holder(t)
	x := base64.RawURLEncoding.EncodeToString(pub[1:33])
	y := base64.RawURLEncoding.EncodeToString(pub[33:])

	good := map[string]any{"cnf": map[string]any{"jwk": map[string]any{
		"kty": "EC", "crv": "P-256", "x": x, "y": y,
	}}}
	ed, ec := extractHolderKey(good)
	if ed != nil {
		t.Error("P-256 cnf must not yield an Ed25519 key")
	}
	if len(ec) != ecdsakey.P256UncompressedSize {
		t.Fatalf("P-256 cnf should yield a 65-byte SEC1 point, got %d", len(ec))
	}

	// An off-curve point (perturbed y) must be rejected.
	badY := make([]byte, 32)
	copy(badY, pub[33:])
	badY[31] ^= 0x01
	offCurve := map[string]any{"cnf": map[string]any{"jwk": map[string]any{
		"kty": "EC", "crv": "P-256", "x": x, "y": base64.RawURLEncoding.EncodeToString(badY),
	}}}
	if ed, ec := extractHolderKey(offCurve); ed != nil || ec != nil {
		t.Error("an off-curve cnf point must yield no holder key")
	}

	// Missing y must be rejected.
	noY := map[string]any{"cnf": map[string]any{"jwk": map[string]any{"kty": "EC", "crv": "P-256", "x": x}}}
	if ed, ec := extractHolderKey(noY); ed != nil || ec != nil {
		t.Error("a P-256 cnf without y must be rejected")
	}
}

// kbPayload decodes the issuer-JWT payload of an SD-JWT.
func kbPayload(t *testing.T, sdjwt string) map[string]any {
	t.Helper()
	jwt := strings.SplitN(sdjwt, "~", 2)[0]
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(jwt, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}
