package compliance

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"blrcs/ecdsakey"
)

// ============================================================================
// Axis 137: ES256 SD-JWT issuance
// ============================================================================

func newES256Issuer(t *testing.T) *ES256Issuer {
	t.Helper()
	iss, err := NewES256Issuer("did:web:eudi-issuer.europa.eu")
	if err != nil {
		t.Fatal(err)
	}
	return iss
}

// sdjwtHeader decodes the JWS protected header of an SD-JWT.
func sdjwtHeader(t *testing.T, sdjwt string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.SplitN(sdjwt, ".", 2)[0])
	if err != nil {
		t.Fatal(err)
	}
	var h map[string]any
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	return h
}

// TestES256IssueAndVerifyRoundTrip is the headline capability: BLRCS issues a
// credential a P-256-only (EUDI) ecosystem accepts, and can verify it back.
func TestES256IssueAndVerifyRoundTrip(t *testing.T) {
	iss := newES256Issuer(t)
	sdjwt, disclosures, err := iss.IssueSDJWTVC("DigitalProductPassport", "battery-001",
		map[string]any{"carbonKgCO2ePerKWh": 42.0},
		map[string]any{"batteryCategory": "ev"}, 365*24*time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if h := sdjwtHeader(t, sdjwt); h["alg"] != "ES256" || h["typ"] != "dc+sd-jwt" {
		t.Errorf("header should be ES256/dc+sd-jwt, got %v", h)
	}
	if len(disclosures) != 1 {
		t.Errorf("want 1 disclosure, got %d", len(disclosures))
	}
	vc, err := VerifySDJWTWithBinding(sdjwt, iss.PublicKey(), VerifyOptions{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if vc.Subject != "battery-001" || vc.Issuer != iss.ID {
		t.Errorf("claims: %+v", vc)
	}
	if vc.Claims["batteryCategory"] != "ev" {
		t.Errorf("clear claim missing: %+v", vc.Claims)
	}
}

// TestES256SignatureIsFixedWidth proves the issuer emits the RFC 7518 §3.4 wire
// form (64 octets, raw R‖S) and not ASN.1 DER — the interop-critical property.
func TestES256SignatureIsFixedWidth(t *testing.T) {
	iss := newES256Issuer(t)
	// Repeat: a short encoding only shows up when r or s has a leading zero
	// byte (~1 in 256 per coordinate), so a single sample would miss it.
	for n := 0; n < 300; n++ {
		sdjwt, _, err := iss.IssueSDJWT("s", map[string]any{"a": 1.0}, nil, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		jwt := strings.SplitN(sdjwt, "~", 2)[0]
		parts := strings.Split(jwt, ".")
		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatal(err)
		}
		if len(sig) != ecdsakey.ES256SignatureSize {
			t.Fatalf("iteration %d: signature is %d bytes, want exactly %d (raw R||S, never DER)",
				n, len(sig), ecdsakey.ES256SignatureSize)
		}
		// Deliberately NOT asserting sig[0] != 0x30 ("DER SEQUENCE tag"): in a raw
		// R‖S signature the first byte is simply the top byte of R, which is 0x30
		// about 1 time in 256 by chance, so that check is a false-positive
		// generator rather than a DER detector. The length is the sound test — a
		// DER-encoded P-256 signature carries 6+ bytes of ASN.1 overhead around
		// two ~32-byte integers, and the verify side separately proves DER is
		// rejected (TestES256DERSignatureRejectedEndToEnd).
	}
}

// TestES256NoncesDiffer is a smoke check on the catastrophic ECDSA failure
// mode: two signatures over the same message must not be identical, which they
// would be under a fixed or reused nonce.
func TestES256NoncesDiffer(t *testing.T) {
	iss := newES256Issuer(t)
	input := []byte("identical signing input")
	seen := make(map[string]bool)
	for n := 0; n < 50; n++ {
		sig, err := iss.signJWS(input)
		if err != nil {
			t.Fatal(err)
		}
		k := string(sig)
		if seen[k] {
			t.Fatal("identical signature produced twice over the same input: nonce reuse")
		}
		seen[k] = true
	}
}

func TestES256StatusAndHolderBinding(t *testing.T) {
	iss := newES256Issuer(t)

	withStatus, _, err := iss.IssueSDJWTVCStatus("DigitalProductPassport", "b1",
		map[string]any{"a": 1.0}, nil,
		&StatusRef{URI: "https://issuer.example/status/1", Index: 5}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	vc, err := VerifySDJWTWithBinding(withStatus, iss.PublicKey(), VerifyOptions{})
	if err != nil {
		t.Fatalf("status credential should verify: %v", err)
	}
	if vc.Status == nil || vc.Status.Index != 5 {
		t.Errorf("status reference not carried: %+v", vc.Status)
	}

	holderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bound, _, err := iss.IssueSDJWTVCBound("DigitalProductPassport", "b2",
		map[string]any{"a": 1.0}, nil, holderPub, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// A credential carrying cnf must be PRESENTED with a KB-JWT; verifying the
	// raw issued form is correctly refused (secure-by-default holder binding).
	if _, err := VerifySDJWTWithBinding(bound, iss.PublicKey(), VerifyOptions{}); err == nil {
		t.Error("a cnf-bound credential must not verify without a KB-JWT")
	}
	// What this axis is responsible for is that the holder key reached the
	// payload at all, so assert cnf directly.
	payloadRaw, err := base64.RawURLEncoding.DecodeString(
		strings.Split(strings.SplitN(bound, "~", 2)[0], ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Cnf struct {
			JWK struct {
				X   string `json:"x"`
				Crv string `json:"crv"`
			} `json:"jwk"`
		} `json:"cnf"`
	}
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Cnf.JWK.Crv != "Ed25519" ||
		payload.Cnf.JWK.X != base64.RawURLEncoding.EncodeToString(holderPub) {
		t.Errorf("cnf holder key not embedded correctly: %+v", payload.Cnf.JWK)
	}
}

// TestES256TamperAndWrongKey covers the basic negative cases end to end.
func TestES256TamperAndWrongKey(t *testing.T) {
	iss := newES256Issuer(t)
	other := newES256Issuer(t)
	sdjwt, _, err := iss.IssueSDJWT("s", map[string]any{"a": 1.0}, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySDJWTWithBinding(sdjwt, other.PublicKey(), VerifyOptions{}); err == nil {
		t.Error("must not verify under a different issuer key")
	}
	parts := strings.SplitN(sdjwt, ".", 3)
	forged, _ := json.Marshal(map[string]any{"iss": iss.ID, "sub": "EVIL", "vct": "x"})
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString(forged) + "." + parts[2]
	if _, err := VerifySDJWTWithBinding(tampered, iss.PublicKey(), VerifyOptions{}); err == nil {
		t.Error("tampered payload must not verify")
	}
}

// TestES256DecoyDigests proves the privacy feature works identically for the
// new algorithm — the shared builder means it cannot silently diverge.
func TestES256DecoyDigests(t *testing.T) {
	iss := newES256Issuer(t)
	iss.DecoyDigests = 5
	sdjwt, disclosures, err := iss.IssueSDJWT("s",
		map[string]any{"a": 1.0, "b": 2.0}, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	jwt := strings.SplitN(sdjwt, "~", 2)[0]
	payloadRaw, err := base64.RawURLEncoding.DecodeString(strings.Split(jwt, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		t.Fatal(err)
	}
	sd, _ := payload["_sd"].([]any)
	if len(sd) != len(disclosures)+5 {
		t.Errorf("_sd should hold %d real + 5 decoys, got %d", len(disclosures), len(sd))
	}
}

func TestES256IssuerConstructorValidation(t *testing.T) {
	if _, err := NewES256Issuer(""); err == nil {
		t.Error("empty issuer ID should be rejected")
	}
	if _, err := NewES256IssuerFromKey("id", nil); !errors.Is(err, ErrNotP256) {
		t.Error("nil key should be rejected")
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewES256IssuerFromKey("id", p384); !errors.Is(err, ErrNotP256) {
		t.Error("a P-384 key must be rejected for ES256")
	}
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	adopted, err := NewES256IssuerFromKey("did:web:hsm.example", p256)
	if err != nil {
		t.Fatalf("adopting a P-256 key should work: %v", err)
	}
	sdjwt, _, err := adopted.IssueSDJWT("s", map[string]any{"a": 1.0}, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySDJWTWithBinding(sdjwt, adopted.PublicKey(), VerifyOptions{}); err != nil {
		t.Errorf("adopted-key issuance should verify: %v", err)
	}
}

// TestEd25519IssuanceUnchanged is the regression guard for the shared-builder
// refactor: the default issuer must still emit exactly EdDSA.
func TestEd25519IssuanceUnchanged(t *testing.T) {
	iss, err := NewIssuer("did:web:factory.example")
	if err != nil {
		t.Fatal(err)
	}
	iss.DecoyDigests = 3
	sdjwt, disclosures, err := iss.IssueSDJWT("battery-9",
		map[string]any{"a": 1.0}, map[string]any{"b": "clear"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if h := sdjwtHeader(t, sdjwt); h["alg"] != "EdDSA" {
		t.Errorf("default issuer must still sign EdDSA, got %v", h["alg"])
	}
	if len(disclosures) != 1 {
		t.Errorf("disclosures: %d", len(disclosures))
	}
	if _, err := VerifySDJWTWithBinding(sdjwt, iss.PublicKey(), VerifyOptions{}); err != nil {
		t.Fatalf("EdDSA issuance must still verify: %v", err)
	}
}
