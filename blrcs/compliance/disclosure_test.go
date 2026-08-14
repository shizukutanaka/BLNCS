package compliance

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// ============================================================================
// Axis 139: RFC 9901 array-element and recursive disclosures
//
// These build credentials the way a CONFORMING THIRD-PARTY issuer would — using
// disclosure shapes BLRCS itself does not yet emit — so they are the interop
// tests that matter: before this axis every one of them was rejected as
// malformed.
// ============================================================================

// discOf encodes a disclosure and returns (encoded, digest).
func discOf(t *testing.T, elems ...any) (string, string) {
	t.Helper()
	raw, err := json.Marshal(elems)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(enc))
	return enc, base64.RawURLEncoding.EncodeToString(sum[:])
}

// signPayload signs an arbitrary payload as an SD-JWT issuer would.
func signPayload(t *testing.T, priv ed25519.PrivateKey, payload map[string]any) string {
	t.Helper()
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"dc+sd-jwt"}`))
	pl, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	si := hdr + "." + base64.RawURLEncoding.EncodeToString(pl)
	sig := ed25519.Sign(priv, []byte(si))
	return si + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// basePayload is a minimal valid SD-JWT-VC payload.
func basePayload(issuerID string) map[string]any {
	now := time.Now().UTC()
	return map[string]any{
		"iss": issuerID, "sub": "battery-001", "vct": "DigitalProductPassport",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "_sd_alg": "sha-256",
	}
}

func discIssuer(t *testing.T) *Issuer {
	t.Helper()
	iss, err := NewIssuer("did:web:third-party.example")
	if err != nil {
		t.Fatal(err)
	}
	return iss
}

// TestArrayElementDisclosure covers the 2-element [salt, value] form with the
// {"...": digest} placeholder — previously rejected outright.
func TestArrayElementDisclosure(t *testing.T) {
	iss := discIssuer(t)
	discDE, digestDE := discOf(t, "salt-de", "DE")
	discFR, digestFR := discOf(t, "salt-fr", "FR")

	p := basePayload(iss.ID)
	// Three markets: one always visible, two selectively disclosable.
	p["markets"] = []any{"JP", map[string]any{"...": digestDE}, map[string]any{"...": digestFR}}
	sdjwt := signPayload(t, iss.privateKey, p) + "~" + discDE + "~" + discFR + "~"

	vc, err := VerifySDJWTWithBinding(sdjwt, iss.PublicKey(), VerifyOptions{})
	if err != nil {
		t.Fatalf("array-element disclosures should verify: %v", err)
	}
	markets, ok := vc.Claims["markets"].([]any)
	if !ok {
		t.Fatalf("markets not an array: %T", vc.Claims["markets"])
	}
	// Order must be preserved: that is why redaction leaves a placeholder.
	want := []string{"JP", "DE", "FR"}
	if len(markets) != len(want) {
		t.Fatalf("want %d markets, got %d (%v)", len(want), len(markets), markets)
	}
	for i, w := range want {
		if markets[i] != w {
			t.Errorf("markets[%d] = %v, want %s", i, markets[i], w)
		}
	}
}

// TestArrayElementUndisclosedIsOmitted proves a placeholder with no matching
// disclosure vanishes rather than erroring — that is selective disclosure.
func TestArrayElementUndisclosedIsOmitted(t *testing.T) {
	iss := discIssuer(t)
	discDE, digestDE := discOf(t, "salt-de", "DE")
	_, digestSecret := discOf(t, "salt-x", "CLASSIFIED")

	p := basePayload(iss.ID)
	p["markets"] = []any{map[string]any{"...": digestDE}, map[string]any{"...": digestSecret}}
	// Only the DE disclosure is presented.
	sdjwt := signPayload(t, iss.privateKey, p) + "~" + discDE + "~"

	vc, err := VerifySDJWTWithBinding(sdjwt, iss.PublicKey(), VerifyOptions{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	markets := vc.Claims["markets"].([]any)
	if len(markets) != 1 || markets[0] != "DE" {
		t.Errorf("undisclosed element should be omitted, got %v", markets)
	}
}

// TestRecursiveDisclosure is the case the old top-level-only check made
// impossible: a disclosed value that itself carries `_sd`.
func TestRecursiveDisclosure(t *testing.T) {
	iss := discIssuer(t)
	// Inner: the street of an address.
	discStreet, digestStreet := discOf(t, "salt-street", "street", "1-2-3 Chuo")
	// Outer: the address object, whose value contains the inner digest.
	address := map[string]any{"country": "JP", "_sd": []any{digestStreet}}
	discAddr, digestAddr := discOf(t, "salt-addr", "address", address)

	p := basePayload(iss.ID)
	p["_sd"] = []any{digestAddr} // only the OUTER digest is at top level
	sdjwt := signPayload(t, iss.privateKey, p) + "~" + discAddr + "~" + discStreet + "~"

	vc, err := VerifySDJWTWithBinding(sdjwt, iss.PublicKey(), VerifyOptions{})
	if err != nil {
		t.Fatalf("recursive disclosure should verify: %v", err)
	}
	addr, ok := vc.Claims["address"].(map[string]any)
	if !ok {
		t.Fatalf("address not an object: %T", vc.Claims["address"])
	}
	if addr["country"] != "JP" {
		t.Errorf("country: %v", addr["country"])
	}
	if addr["street"] != "1-2-3 Chuo" {
		t.Errorf("nested disclosure not resolved: %+v", addr)
	}
	if _, leaked := addr["_sd"]; leaked {
		t.Error("_sd should not survive into the resolved claims")
	}
}

// TestRecursiveArrayInsideDisclosure combines both shapes: a disclosed object
// containing an array with its own placeholders.
func TestRecursiveArrayInsideDisclosure(t *testing.T) {
	iss := discIssuer(t)
	discCert, digestCert := discOf(t, "salt-c", "ISO14001")
	inner := map[string]any{"certs": []any{map[string]any{"...": digestCert}}}
	discComp, digestComp := discOf(t, "salt-comp", "compliance", inner)

	p := basePayload(iss.ID)
	p["_sd"] = []any{digestComp}
	sdjwt := signPayload(t, iss.privateKey, p) + "~" + discComp + "~" + discCert + "~"

	vc, err := VerifySDJWTWithBinding(sdjwt, iss.PublicKey(), VerifyOptions{})
	if err != nil {
		t.Fatalf("nested array-in-object disclosure should verify: %v", err)
	}
	comp := vc.Claims["compliance"].(map[string]any)
	certs := comp["certs"].([]any)
	if len(certs) != 1 || certs[0] != "ISO14001" {
		t.Errorf("nested array element not resolved: %v", certs)
	}
}

// TestUnusedDisclosureRejected: the spec requires rejection, because an unused
// disclosure means disclosures were mixed between credentials.
func TestUnusedDisclosureRejected(t *testing.T) {
	iss := discIssuer(t)
	discA, digestA := discOf(t, "salt-a", "a", 1)
	discOrphan, _ := discOf(t, "salt-o", "orphan", "from another credential")

	p := basePayload(iss.ID)
	p["_sd"] = []any{digestA}
	sdjwt := signPayload(t, iss.privateKey, p) + "~" + discA + "~" + discOrphan + "~"

	if _, err := VerifySDJWTWithBinding(sdjwt, iss.PublicKey(), VerifyOptions{}); !errors.Is(err, ErrDisclosureUnused) {
		t.Fatalf("want ErrDisclosureUnused, got %v", err)
	}
}

// TestDisclosureReferencedTwiceRejected prevents one disclosure being expanded
// into two places.
func TestDisclosureReferencedTwiceRejected(t *testing.T) {
	iss := discIssuer(t)
	discX, digestX := discOf(t, "salt-x", "x", 1)

	p := basePayload(iss.ID)
	// Same digest referenced from two different objects.
	p["_sd"] = []any{digestX}
	p["nested"] = map[string]any{"_sd": []any{digestX}}
	sdjwt := signPayload(t, iss.privateKey, p) + "~" + discX + "~"

	if _, err := VerifySDJWTWithBinding(sdjwt, iss.PublicKey(), VerifyOptions{}); !errors.Is(err, ErrDisclosureReused) {
		t.Fatalf("want ErrDisclosureReused, got %v", err)
	}
}

// TestShapeConfusionRejected: an array-element disclosure must not satisfy an
// `_sd` reference, nor an object-property disclosure an array placeholder.
func TestShapeConfusionRejected(t *testing.T) {
	iss := discIssuer(t)

	// 2-element disclosure referenced from _sd.
	discArr, digestArr := discOf(t, "salt", "value-only")
	p1 := basePayload(iss.ID)
	p1["_sd"] = []any{digestArr}
	s1 := signPayload(t, iss.privateKey, p1) + "~" + discArr + "~"
	if _, err := VerifySDJWTWithBinding(s1, iss.PublicKey(), VerifyOptions{}); !errors.Is(err, ErrDisclosureMalformed) {
		t.Errorf("array-element disclosure in _sd should be rejected, got %v", err)
	}

	// 3-element disclosure referenced from an array placeholder.
	discObj, digestObj := discOf(t, "salt", "name", "value")
	p2 := basePayload(iss.ID)
	p2["list"] = []any{map[string]any{"...": digestObj}}
	s2 := signPayload(t, iss.privateKey, p2) + "~" + discObj + "~"
	if _, err := VerifySDJWTWithBinding(s2, iss.PublicKey(), VerifyOptions{}); !errors.Is(err, ErrDisclosureMalformed) {
		t.Errorf("object-property disclosure in an array placeholder should be rejected, got %v", err)
	}
}

// TestPlaceholderWithExtraKeysRejected: the placeholder is a single-member
// object; extra keys could smuggle data past the resolver.
func TestPlaceholderWithExtraKeysRejected(t *testing.T) {
	iss := discIssuer(t)
	discA, digestA := discOf(t, "salt", "hidden")

	p := basePayload(iss.ID)
	p["list"] = []any{map[string]any{"...": digestA, "extra": "smuggled"}}
	sdjwt := signPayload(t, iss.privateKey, p) + "~" + discA + "~"

	if _, err := VerifySDJWTWithBinding(sdjwt, iss.PublicKey(), VerifyOptions{}); !errors.Is(err, ErrDisclosureMalformed) {
		t.Fatalf("want ErrDisclosureMalformed, got %v", err)
	}
}

// TestReservedNameViaNestedDisclosureRejected proves the collision check applies
// at depth too, not only at the top level.
func TestReservedNameViaNestedDisclosureRejected(t *testing.T) {
	iss := discIssuer(t)
	discIss, digestIss := discOf(t, "salt-i", "iss", "did:web:evil.example")
	outer := map[string]any{"_sd": []any{digestIss}}
	discOuter, digestOuter := discOf(t, "salt-o", "outer", outer)

	p := basePayload(iss.ID)
	p["_sd"] = []any{digestOuter}
	sdjwt := signPayload(t, iss.privateKey, p) + "~" + discOuter + "~" + discIss + "~"

	if _, err := VerifySDJWTWithBinding(sdjwt, iss.PublicKey(), VerifyOptions{}); !errors.Is(err, ErrDisclosureCollision) {
		t.Fatalf("a nested disclosure must not introduce a reserved claim, got %v", err)
	}
}

// TestDeepNestingBounded guards the stack-exhaustion path: the presenter
// controls nesting depth.
func TestDeepNestingBounded(t *testing.T) {
	iss := discIssuer(t)
	p := basePayload(iss.ID)
	// Build an array nested far deeper than the limit.
	var deep any = "leaf"
	for i := 0; i < maxDisclosureDepth+10; i++ {
		deep = []any{deep}
	}
	p["deep"] = deep
	sdjwt := signPayload(t, iss.privateKey, p) + "~"

	if _, err := VerifySDJWTWithBinding(sdjwt, iss.PublicKey(), VerifyOptions{}); !errors.Is(err, ErrDisclosureMalformed) {
		t.Fatalf("excessive nesting should be rejected, got %v", err)
	}
}

// TestFlatDisclosuresStillWork is the regression guard for the credentials
// BLRCS itself issues.
func TestFlatDisclosuresStillWork(t *testing.T) {
	iss := discIssuer(t)
	sdjwt, disclosures, err := iss.IssueSDJWT("battery-1",
		map[string]any{"carbonKgCO2ePerKWh": 42.0, "recycledCoPct": 12.0},
		map[string]any{"batteryCategory": "ev"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(disclosures) != 2 {
		t.Fatalf("want 2 disclosures, got %d", len(disclosures))
	}
	vc, err := VerifySDJWTWithBinding(sdjwt, iss.PublicKey(), VerifyOptions{})
	if err != nil {
		t.Fatalf("flat issuance must still verify: %v", err)
	}
	if vc.Claims["carbonKgCO2ePerKWh"] != 42.0 || vc.Claims["batteryCategory"] != "ev" {
		t.Errorf("claims: %+v", vc.Claims)
	}
}

// TestNoSDClaimsOmitsSDMember proves the issuer no longer emits `"_sd": null`,
// which is not a valid digest array and which a strict verifier may reject.
func TestNoSDClaimsOmitsSDMember(t *testing.T) {
	iss := discIssuer(t)
	sdjwt, _, err := iss.IssueSDJWT("sub", nil, map[string]any{"a": "clear"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	payloadRaw, err := base64.RawURLEncoding.DecodeString(
		splitJWTPayload(t, sdjwt))
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		t.Fatal(err)
	}
	if v, present := payload["_sd"]; present {
		t.Errorf("_sd should be omitted when empty, got %v", v)
	}
	if _, err := VerifySDJWTWithBinding(sdjwt, iss.PublicKey(), VerifyOptions{}); err != nil {
		t.Errorf("credential with no SD claims must still verify: %v", err)
	}
}

// TestNullSDTolerated keeps interop with issuers (including older BLRCS
// releases) that serialise an empty digest list as null.
func TestNullSDTolerated(t *testing.T) {
	iss := discIssuer(t)
	p := basePayload(iss.ID)
	p["_sd"] = nil
	sdjwt := signPayload(t, iss.privateKey, p) + "~"

	if _, err := VerifySDJWTWithBinding(sdjwt, iss.PublicKey(), VerifyOptions{}); err != nil {
		t.Errorf(`"_sd": null should be treated as absent, got %v`, err)
	}
	// A non-null, non-array _sd is still a hard error.
	p["_sd"] = "not-an-array"
	bad := signPayload(t, iss.privateKey, p) + "~"
	if _, err := VerifySDJWTWithBinding(bad, iss.PublicKey(), VerifyOptions{}); !errors.Is(err, ErrDisclosureMalformed) {
		t.Errorf("non-array _sd should be rejected, got %v", err)
	}
}

// splitJWTPayload returns the base64url payload segment of an SD-JWT.
func splitJWTPayload(t *testing.T, sdjwt string) string {
	t.Helper()
	jwt := sdjwt
	if i := indexByte(jwt, '~'); i >= 0 {
		jwt = jwt[:i]
	}
	first := indexByte(jwt, '.')
	if first < 0 {
		t.Fatal("malformed JWT")
	}
	rest := jwt[first+1:]
	second := indexByte(rest, '.')
	if second < 0 {
		t.Fatal("malformed JWT")
	}
	return rest[:second]
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
