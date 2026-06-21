package compliance

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// test helpers
// ============================================================================

// craftSignedJWT builds a signed vc+sd-jwt using the given private key.
func craftSignedJWT(priv ed25519.PrivateKey, payloadMap map[string]any) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"vc+sd-jwt"}`))
	payBytes, _ := json.Marshal(payloadMap)
	pay := base64.RawURLEncoding.EncodeToString(payBytes)
	sig := ed25519.Sign(priv, []byte(hdr+"."+pay))
	return hdr + "." + pay + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// discHash returns the base64url SHA-256 digest of a disclosure string (used in _sd).
func discHash(disc string) string {
	h := sha256.Sum256([]byte(disc))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// baseSDPayload returns a minimal valid SD-JWT payload for iss.
func baseSDPayload(iss *Issuer) map[string]any {
	return map[string]any{
		"iss": iss.ID,
		"sub": "sub",
		"vct": "https://example.com/vct/v1",
		"iat": float64(time.Now().Unix()),
		"_sd": []any{},
	}
}

// ============================================================================
// PrivateKey / NewIssuerFromKey
// ============================================================================

func TestPrivateKeyExposed(t *testing.T) {
	iss, _ := NewIssuer("did:web:test")
	if len(iss.PrivateKey()) != ed25519.PrivateKeySize {
		t.Errorf("private key size: %d", len(iss.PrivateKey()))
	}
}

func TestNewIssuerFromKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	iss, err := NewIssuerFromKey("did:web:test", priv)
	if err != nil {
		t.Fatal(err)
	}
	if iss.ID != "did:web:test" {
		t.Errorf("ID: %s", iss.ID)
	}
	// Issue + verify round-trip
	cred, err := iss.Issue(PassportClaim{ProductID: "X"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(cred, iss.PublicKey()); err != nil {
		t.Fatal(err)
	}
}

func TestNewIssuerFromKeyBadSize(t *testing.T) {
	_, err := NewIssuerFromKey("did:web:test", []byte("too short"))
	if err == nil {
		t.Fatal("bad key size should fail")
	}
}

// sdArrayLen returns the number of entries in the signed `_sd` array of an SD-JWT.
func sdArrayLen(t *testing.T, sdjwt string) int {
	t.Helper()
	jwt := strings.SplitN(sdjwt, "~", 2)[0]
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", jwt)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var pl struct {
		SD []string `json:"_sd"`
	}
	if err := json.Unmarshal(raw, &pl); err != nil {
		t.Fatal(err)
	}
	return len(pl.SD)
}

// TestDecoyDigestsObscureClaimCount pins the privacy fix (Axis 11): with
// DecoyDigests>0 the signed `_sd` array no longer reveals the true number of
// selectively-disclosable claims, yet the credential still verifies and decoys
// disclose nothing.
func TestDecoyDigestsObscureClaimCount(t *testing.T) {
	iss, _ := NewIssuer("did:web:test")
	iss.DecoyDigests = 5

	sd := map[string]any{"category": "battery", "carbon": 1.5}
	sdjwt, _, err := iss.IssueSDJWT("subj", sd, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// _sd carries the 2 real claims + 5 decoys, hiding the real count.
	if got := sdArrayLen(t, sdjwt); got != 7 {
		t.Errorf("_sd length: want 7 (2 real + 5 decoy), got %d", got)
	}
	// Verification still succeeds and yields exactly the real claims.
	vc, err := VerifySDJWT(sdjwt, iss.PublicKey())
	if err != nil {
		t.Fatalf("verify with decoys: %v", err)
	}
	if vc.Claims["category"] != "battery" {
		t.Errorf("category: %v", vc.Claims["category"])
	}
	if f, ok := vc.Claims["carbon"].(float64); !ok || f != 1.5 {
		t.Errorf("carbon: %v", vc.Claims["carbon"])
	}
	if len(vc.Claims) != 2 {
		t.Errorf("decoys must not surface as claims: got %d claims", len(vc.Claims))
	}
}

// TestDecoyDigestsDefaultOff confirms backward-compat: DecoyDigests=0 (default)
// produces an `_sd` array sized exactly to the real claims.
func TestDecoyDigestsDefaultOff(t *testing.T) {
	iss, _ := NewIssuer("did:web:test")
	sd := map[string]any{"a": 1, "b": 2, "c": 3}
	sdjwt, _, err := iss.IssueSDJWT("subj", sd, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got := sdArrayLen(t, sdjwt); got != 3 {
		t.Errorf("default (no decoys): want _sd length 3, got %d", got)
	}
}

func TestNewIssuerFromKeyEmptyID(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, err := NewIssuerFromKey("", priv)
	if err == nil {
		t.Fatal("empty ID should fail")
	}
}

// ============================================================================
// SD-JWT
// ============================================================================

func TestIssueSDJWTBasic(t *testing.T) {
	iss, _ := NewIssuer("did:web:sdjwt.test")
	sdjwt, disclosures, err := iss.IssueSDJWT("subj-1",
		map[string]any{"secret": "value", "number": 42},
		map[string]any{"public": "data"},
		time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sdjwt, "~") {
		t.Error("SD-JWT must contain disclosure separator")
	}
	if len(disclosures) != 2 {
		t.Errorf("expected 2 disclosures, got %d", len(disclosures))
	}
}

func TestVerifySDJWTRoundTrip(t *testing.T) {
	iss, _ := NewIssuer("did:web:sdjwt.test")
	sdjwt, _, _ := iss.IssueSDJWT("subj-1",
		map[string]any{"a": 1, "b": "two", "c": 3.14},
		map[string]any{"clear": "always-visible"},
		time.Hour,
	)
	vc, err := VerifySDJWT(sdjwt, iss.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if vc.Issuer != iss.ID {
		t.Errorf("issuer: %s", vc.Issuer)
	}
	if vc.Subject != "subj-1" {
		t.Errorf("subject: %s", vc.Subject)
	}
	// SD claims present (all disclosed)
	if vc.Claims["a"] == nil || vc.Claims["b"] == nil || vc.Claims["c"] == nil {
		t.Errorf("sd claims missing: %v", vc.Claims)
	}
	// Clear claim always present
	if vc.Claims["clear"] != "always-visible" {
		t.Errorf("clear claim: %v", vc.Claims["clear"])
	}
}

func TestVerifySDJWTBadSignature(t *testing.T) {
	iss, _ := NewIssuer("did:web:iss1")
	iss2, _ := NewIssuer("did:web:iss2")
	sdjwt, _, _ := iss.IssueSDJWT("s", map[string]any{"x": 1}, nil, 0)
	// Verify with wrong key
	if _, err := VerifySDJWT(sdjwt, iss2.PublicKey()); err == nil {
		t.Fatal("wrong key should fail")
	}
}

func TestVerifySDJWTMalformed(t *testing.T) {
	iss, _ := NewIssuer("did:web:test")
	cases := []string{
		"",
		"not.valid",
		"a.b",
		"a.b.c~disc~",
	}
	for _, c := range cases {
		if _, err := VerifySDJWT(c, iss.PublicKey()); err == nil {
			t.Errorf("should reject %q", c)
		}
	}
}

func TestPresentSelectiveDisclosure(t *testing.T) {
	iss, _ := NewIssuer("did:web:present.test")
	sdjwt, _, _ := iss.IssueSDJWT("s",
		map[string]any{
			"public_ok": "show",
			"secret":    "hide",
			"also_ok":   42,
		},
		map[string]any{"clear": "always"},
		time.Hour,
	)
	// Reveal only public_ok and also_ok
	presented, err := Present(sdjwt, []string{"public_ok", "also_ok"})
	if err != nil {
		t.Fatal(err)
	}
	vc, err := VerifySDJWT(presented, iss.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	// Disclosed claims present
	if vc.Claims["public_ok"] != "show" {
		t.Errorf("public_ok: %v", vc.Claims["public_ok"])
	}
	if vc.Claims["also_ok"] == nil {
		t.Error("also_ok should be disclosed")
	}
	// Secret must NOT be present
	if _, leaked := vc.Claims["secret"]; leaked {
		t.Error("CRITICAL: secret leaked")
	}
	// Clear claim always present
	if vc.Claims["clear"] != "always" {
		t.Errorf("clear: %v", vc.Claims["clear"])
	}
}

func TestPresentNoDisclosure(t *testing.T) {
	iss, _ := NewIssuer("did:web:test")
	sdjwt, _, _ := iss.IssueSDJWT("s",
		map[string]any{"a": 1, "b": 2},
		map[string]any{"public": "x"},
		0,
	)
	presented, _ := Present(sdjwt, []string{})
	vc, _ := VerifySDJWT(presented, iss.PublicKey())
	if _, ok := vc.Claims["a"]; ok {
		t.Error("a should not be disclosed")
	}
	if _, ok := vc.Claims["b"]; ok {
		t.Error("b should not be disclosed")
	}
	if vc.Claims["public"] != "x" {
		t.Errorf("clear claim missing: %v", vc.Claims["public"])
	}
}

// ============================================================================
// GS1 Digital Link
// ============================================================================

func TestBuildAndParseDLURI(t *testing.T) {
	uri, err := BuildDLURI("dpp.example", GS1Key{GTIN: "04012345678901", Serial: "ABC"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(uri, "https://dpp.example/01/04012345678901/21/ABC") {
		t.Errorf("URI: %s", uri)
	}
	// Parse back
	domain, key, err := ParseDLURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	if domain != "dpp.example" {
		t.Errorf("domain: %s", domain)
	}
	if key.GTIN != "04012345678901" {
		t.Errorf("GTIN: %s", key.GTIN)
	}
	if key.Serial != "ABC" {
		t.Errorf("serial: %s", key.Serial)
	}
}

func TestBuildDLURIWithBatch(t *testing.T) {
	uri, _ := BuildDLURI("x.example", GS1Key{GTIN: "04012345678901", Batch: "LOT-42"})
	if !strings.Contains(uri, "/10/LOT-42") {
		t.Errorf("batch missing: %s", uri)
	}
}

func TestBuildDLURIInvalidGTIN(t *testing.T) {
	cases := []GS1Key{
		{GTIN: ""},
		{GTIN: "999"},               // too short
		{GTIN: "abcdef"},            // non-digit
		{GTIN: "12345678901234567"}, // too long
	}
	for _, k := range cases {
		if _, err := BuildDLURI("x", k); err == nil {
			t.Errorf("should reject GTIN %q", k.GTIN)
		}
	}
}

func TestParseDLURIInvalid(t *testing.T) {
	cases := []string{
		"",
		"http://x/01/123",  // not https
		"https://x/02/123", // wrong AI
		"https://x/01/",    // empty GTIN
		"not-a-url",
	}
	for _, u := range cases {
		if _, _, err := ParseDLURI(u); err == nil {
			t.Errorf("should reject %q", u)
		}
	}
}

func TestComputeGTINCheckDigit(t *testing.T) {
	gtin14, err := ComputeGTINCheckDigit("0401234567890")
	if err != nil {
		t.Fatal(err)
	}
	if len(gtin14) != 14 {
		t.Errorf("length: %d", len(gtin14))
	}
	// Verify check digit is correct by building and parsing a DL URI
	_, err = BuildDLURI("test", GS1Key{GTIN: gtin14})
	if err != nil {
		t.Fatal(err)
	}
}

func TestComputeGTINCheckDigitBadInput(t *testing.T) {
	cases := []string{
		"",
		"123",            // too short
		"12345678901234", // too long
		"abcdefghijklm",  // non-digit
	}
	for _, c := range cases {
		if _, err := ComputeGTINCheckDigit(c); err == nil {
			t.Errorf("should reject %q", c)
		}
	}
}

// ============================================================================
// Battery Passport
// ============================================================================

func TestIssueBatteryPassport(t *testing.T) {
	iss, _ := NewIssuer("did:web:battery.factory")
	cred, err := iss.IssueBatteryPassport(BatteryPassportClaim{
		BatteryID:                   "BAT-001",
		Category:                    BatteryCategoryEV,
		Chemistry:                   ChemistryNMC,
		CapacityKWh:                 75.0,
		CarbonFootprintKgCO2ePerKWh: 48.5,
		DueDiligenceReportURL:       "https://factory.example/due-diligence/2026.pdf",
	}, 3650*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Type marker
	hasBattery := false
	for _, tp := range cred.Type {
		if tp == "BatteryPassport" {
			hasBattery = true
		}
	}
	if !hasBattery {
		t.Error("BatteryPassport type marker missing")
	}
	// Verify
	if err := Verify(cred, iss.PublicKey()); err != nil {
		t.Fatalf("issued battery passport fails verify: %v", err)
	}
}

func TestIssueBatteryPassportMissingID(t *testing.T) {
	iss, _ := NewIssuer("did:web:test")
	_, err := iss.IssueBatteryPassport(BatteryPassportClaim{}, 0)
	if err == nil {
		t.Fatal("missing batteryID should fail")
	}
}

// ============================================================================
// EU 2023/1542 Annex XIII regulatory completeness
// ============================================================================

func TestBatteryPassportDueDiligenceEnforced_EV(t *testing.T) {
	iss, _ := NewIssuer("did:web:dd.factory")
	// EV battery without due-diligence URL → must fail (Art.52)
	_, err := iss.IssueBatteryPassport(BatteryPassportClaim{
		BatteryID:   "EV-NO-DD",
		Category:    BatteryCategoryEV,
		Chemistry:   ChemistryNMC,
		CapacityKWh: 75.0,
	}, time.Hour)
	if err != ErrDueDiligenceRequired {
		t.Fatalf("EV without due-diligence should fail, got: %v", err)
	}
}

func TestBatteryPassportDueDiligenceEnforced_IndustrialLarge(t *testing.T) {
	iss, _ := NewIssuer("did:web:dd.factory")
	// Industrial >2kWh without due-diligence → must fail
	_, err := iss.IssueBatteryPassport(BatteryPassportClaim{
		BatteryID:   "IND-LARGE",
		Category:    BatteryCategoryIndustrial,
		Chemistry:   ChemistryLFP,
		CapacityKWh: 50.0,
	}, time.Hour)
	if err != ErrDueDiligenceRequired {
		t.Fatalf("large industrial without due-diligence should fail, got: %v", err)
	}
}

func TestBatteryPassportDueDiligenceExempt_SmallIndustrial(t *testing.T) {
	iss, _ := NewIssuer("did:web:dd.factory")
	// Industrial <=2kWh → exempt, should succeed without due-diligence
	cred, err := iss.IssueBatteryPassport(BatteryPassportClaim{
		BatteryID:   "IND-SMALL",
		Category:    BatteryCategoryIndustrial,
		Chemistry:   ChemistryLFP,
		CapacityKWh: 1.5,
	}, time.Hour)
	if err != nil {
		t.Fatalf("small industrial should be exempt: %v", err)
	}
	if cred == nil {
		t.Error("credential should be issued")
	}
}

func TestBatteryPassportDueDiligenceExempt_Portable(t *testing.T) {
	iss, _ := NewIssuer("did:web:dd.factory")
	// Portable batteries are exempt from Art.52
	_, err := iss.IssueBatteryPassport(BatteryPassportClaim{
		BatteryID:   "PORT-001",
		Category:    BatteryCategoryPortable,
		Chemistry:   ChemistryNMC,
		CapacityKWh: 0.05,
	}, time.Hour)
	if err != nil {
		t.Fatalf("portable should be exempt: %v", err)
	}
}

func TestBatteryPassportFullAnnexXIII(t *testing.T) {
	iss, _ := NewIssuer("did:web:full.factory")
	cred, err := iss.IssueBatteryPassport(BatteryPassportClaim{
		BatteryID:                    "FULL-001",
		GTIN:                         "04012345678901",
		SerialNo:                     "SN-2026-001",
		Category:                     BatteryCategoryEV,
		Chemistry:                    ChemistryNMC,
		CapacityKWh:                  75.0,
		VoltageV:                     400,
		WeightKg:                     450,
		PlaceOfMfr:                   "Gigafactory Berlin",
		ModelID:                      "Model-X-2026",
		DateOfMfr:                    time.Now().Add(-30 * 24 * time.Hour),
		CommissioningDate:            time.Now(),
		CarbonFootprintKgCO2ePerKWh:  48.5,
		CarbonFootprintClass:         "A",
		RecycledContent:              RecycledContent{Cobalt: 0.16, Lithium: 0.06, Nickel: 0.06, Lead: 0.0},
		RenewableContentPct:          35.0,
		HazardousSubstances:          []string{"lithium-hexafluorophosphate"},
		StateOfHealthPct:             100.0,
		CycleCount:                   0,
		ExpectedLifetimeYears:        15.0,
		EUDeclarationOfConformityURL: "https://factory.example/doc/conformity.pdf",
		DueDiligenceReportURL:        "https://factory.example/dd/2026.pdf",
		SeparateCollection:           true,
		Recyclable:                   true,
	}, 3650*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Verify all Annex XIII attrs embedded
	attrs := cred.Subject.Attrs
	checks := map[string]string{
		"renewableContentPct":          "35.00",
		"expectedLifetimeYears":        "15.0",
		"euDeclarationOfConformityUrl": "https://factory.example/doc/conformity.pdf",
		"dueDiligenceReportUrl":        "https://factory.example/dd/2026.pdf",
		"separateCollection":           "true",
		"carbonFootprintClass":         "A",
	}
	for k, want := range checks {
		if attrs[k] != want {
			t.Errorf("attr %s = %q, want %q", k, attrs[k], want)
		}
	}
	// Verify signature still valid after embedding
	if err := Verify(cred, iss.PublicKey()); err != nil {
		t.Errorf("full passport signature invalid: %v", err)
	}
}

// ============================================================================
// SD-JWT VC: vct claim conformance (draft-ietf-oauth-sd-jwt-vc)
// ============================================================================

func TestSDJWTVCTDefault(t *testing.T) {
	iss, _ := NewIssuer("did:web:vct.test")
	sdjwt, _, err := iss.IssueSDJWT("subject-1", map[string]any{"carbon": 2.5}, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	vc, err := VerifySDJWT(sdjwt, iss.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if vc.VCT != VCTDigitalProductPassport {
		t.Errorf("vct = %q, want %q", vc.VCT, VCTDigitalProductPassport)
	}
}

func TestSDJWTVCTCustom(t *testing.T) {
	iss, _ := NewIssuer("did:web:vct.test")
	customVCT := "https://example.com/credentials/battery-passport/v2"
	sdjwt, _, err := iss.IssueSDJWTVC(customVCT, "subject-1",
		map[string]any{"x": 1}, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	vc, err := VerifySDJWT(sdjwt, iss.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if vc.VCT != customVCT {
		t.Errorf("vct = %q, want %q", vc.VCT, customVCT)
	}
}

func TestSDJWTVCTSurvivesSelectiveDisclosure(t *testing.T) {
	iss, _ := NewIssuer("did:web:vct.test")
	sdjwt, _, _ := iss.IssueSDJWT("subj",
		map[string]any{"secret": "hidden", "shown": "visible"}, nil, time.Hour)

	// Present revealing only "shown" — vct must still be present (it's a registered claim)
	presented, err := Present(sdjwt, []string{"shown"})
	if err != nil {
		t.Fatal(err)
	}
	vc, err := VerifySDJWT(presented, iss.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if vc.VCT != VCTDigitalProductPassport {
		t.Errorf("vct lost after selective disclosure: %q", vc.VCT)
	}
	// Verify secret is NOT disclosed but vct IS
	if vc.Claims["secret"] != nil {
		t.Error("secret should not be disclosed")
	}
}

func TestIssueSDJWTTieredBound(t *testing.T) {
	iss, err := NewIssuer("did:web:tiered.test")
	if err != nil {
		t.Fatal(err)
	}
	holderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tc := NewTieredClaims()
	tc.Set("batteryCategory", "ev", TierPublic)
	tc.Set("supplierSecret", "acme", TierRestricted)

	sdjwt, disclosures, err := iss.IssueSDJWTTieredBound("battery-1", tc, holderPub, time.Hour)
	if err != nil {
		t.Fatalf("IssueSDJWTTieredBound: %v", err)
	}
	if sdjwt == "" {
		t.Error("empty sdjwt")
	}
	if len(disclosures) == 0 {
		t.Error("expected disclosures for restricted tier claims")
	}
}

func TestIssueSDJWTReservedClearClaim(t *testing.T) {
	iss, err := NewIssuer("did:web:reserved.test")
	if err != nil {
		t.Fatal(err)
	}
	// "iss" is a reserved claim — must be rejected
	_, _, err = iss.IssueSDJWT("sub", nil, map[string]any{"iss": "evil"}, time.Hour)
	if err == nil {
		t.Fatal("reserved clearClaim 'iss' should be rejected")
	}
	if !strings.Contains(err.Error(), "reserved") {
		t.Errorf("error should mention 'reserved': %v", err)
	}
}

// ============================================================================
// Present — edge cases
// ============================================================================

func TestPresentEmptySDJWT2(t *testing.T) {
	_, err := Present("", []string{"any"})
	if !errors.Is(err, ErrSDJWTEmpty) {
		t.Errorf("empty sdjwt: want ErrSDJWTEmpty, got %v", err)
	}
}

func TestPresentNoDisclosures(t *testing.T) {
	iss, _ := NewIssuer("did:web:p.test")
	// Issue with no SD claims — resulting token has no disclosures
	sdjwt, _, err := iss.IssueSDJWT("sub", nil, map[string]any{"public": "val"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Present revealing nothing — should return just the JWT header part + trailing ~
	presented, err := Present(sdjwt, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(presented, "~") {
		t.Errorf("presented should end with ~: %q", presented)
	}
}

// ============================================================================
// extractHolderKey — edge cases (tested indirectly via VerifySDJWTWithBinding)
// ============================================================================

func TestVerifySDJWTWithBindingCNFNotMap(t *testing.T) {
	// Craft a token where cnf is a string (not map) — extractHolderKey returns nil
	// → no binding required, verify should succeed without KB-JWT
	iss, _ := NewIssuer("did:web:cnf.test")
	sdjwt, _, err := iss.IssueSDJWT("sub", map[string]any{"x": 1}, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// The token has no cnf → HolderKey is nil → RequireKeyBinding=false succeeds
	vc, err := VerifySDJWTWithBinding(sdjwt, iss.PublicKey(), VerifyOptions{})
	if err != nil {
		t.Fatalf("no cnf, no RequireKeyBinding: %v", err)
	}
	if vc.HolderKey != nil {
		t.Error("no cnf should give nil HolderKey")
	}
}

func TestVerifySDJWTWithBindingCNFBadX(t *testing.T) {
	// IssueSDJWTBound embeds a valid cnf. For this path we need a token where
	// cnf.jwk.x is present but wrong length. This is an adversarial token —
	// fabricate one using IssueSDJWTBound with a key, then verify with a different
	// issuer key (sig will fail). Use a real bound token but verify with wrong key
	// so we exercise the sig-fail path.
	iss, _ := NewIssuer("did:web:bad-x.test")
	holderPub, _, _ := ed25519.GenerateKey(rand.Reader)
	sdjwt, _, _ := iss.IssueSDJWTBound("sub", map[string]any{"v": 1}, nil, holderPub, time.Hour)

	otherIss, _ := NewIssuer("did:web:other.test")
	_, err := VerifySDJWTWithBinding(sdjwt, otherIss.PublicKey(), VerifyOptions{})
	if !errors.Is(err, ErrSDJWTSigFailed) {
		t.Errorf("wrong issuer key: want ErrSDJWTSigFailed, got %v", err)
	}
}

// TestExtractHolderKeyEdgeCases covers the internal extractHolderKey branches
// that aren't exercised by the indirect tests above.
func TestExtractHolderKeyEdgeCases(t *testing.T) {
	// cnf is a map but has no "jwk" key → nil
	noJWK := map[string]any{"cnf": map[string]any{"other": "value"}}
	if k := extractHolderKey(noJWK); k != nil {
		t.Error("cnf without jwk should return nil")
	}

	// cnf is a map, jwk is a non-map value → nil
	badJWK := map[string]any{"cnf": map[string]any{"jwk": "not-a-map"}}
	if k := extractHolderKey(badJWK); k != nil {
		t.Error("cnf with non-map jwk should return nil")
	}

	// cnf.jwk present but "x" is not a string → nil
	noX := map[string]any{"cnf": map[string]any{"jwk": map[string]any{"kty": "OKP"}}}
	if k := extractHolderKey(noX); k != nil {
		t.Error("jwk without x should return nil")
	}

	// cnf.jwk.x is valid base64url but wrong length → nil
	shortX := map[string]any{"cnf": map[string]any{"jwk": map[string]any{"x": "dG9vc2hvcnQ"}}} // "tooshort"
	if k := extractHolderKey(shortX); k != nil {
		t.Error("jwk.x with wrong length should return nil")
	}

	// --- kty/crv pinning (RFC 7800 cnf.jwk MUST be a valid OKP/Ed25519 JWK) ---
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	validX := base64.RawURLEncoding.EncodeToString(pub)

	// Wrong kty (EC P-256) with an otherwise valid 32-byte x must be rejected —
	// no cross-algorithm reinterpretation of the x-coordinate as Ed25519.
	wrongKty := map[string]any{"cnf": map[string]any{"jwk": map[string]any{
		"kty": "EC", "crv": "P-256", "x": validX,
	}}}
	if k := extractHolderKey(wrongKty); k != nil {
		t.Error("non-OKP kty must be rejected")
	}

	// Right kty, wrong crv (X25519, not a signature curve) must be rejected.
	wrongCrv := map[string]any{"cnf": map[string]any{"jwk": map[string]any{
		"kty": "OKP", "crv": "X25519", "x": validX,
	}}}
	if k := extractHolderKey(wrongCrv); k != nil {
		t.Error("non-Ed25519 crv must be rejected")
	}

	// Missing kty entirely must be rejected (no kty ⇒ not a valid JWK).
	noKty := map[string]any{"cnf": map[string]any{"jwk": map[string]any{"x": validX}}}
	if k := extractHolderKey(noKty); k != nil {
		t.Error("jwk without kty must be rejected")
	}

	// A fully valid OKP/Ed25519 JWK returns exactly the embedded key.
	good := map[string]any{"cnf": map[string]any{"jwk": map[string]any{
		"kty": "OKP", "crv": "Ed25519", "x": validX,
	}}}
	if k := extractHolderKey(good); string(k) != string(pub) {
		t.Error("valid OKP/Ed25519 jwk must return the embedded key")
	}
}

// ============================================================================
// VerifySDJWTWithBinding — malformed JWT header / sig / payload segments
// ============================================================================

func TestVerifySDJWTBadHeaderJSON(t *testing.T) {
	// Header decodes successfully but is not a JSON object → ErrSDJWTMalformed (line 271).
	iss, _ := NewIssuer("did:web:badhdr.test")
	// "aGVsbG8" = base64url("hello"), which is not JSON
	badJWT := "aGVsbG8.payload.sig"
	_, err := VerifySDJWTWithBinding(badJWT+"~", iss.PublicKey(), VerifyOptions{})
	if err != ErrSDJWTMalformed {
		t.Errorf("bad header JSON: want ErrSDJWTMalformed, got %v", err)
	}
}

func TestVerifySDJWTBadSigEncoding(t *testing.T) {
	// Sig segment contains chars invalid for base64url (line 280).
	iss, _ := NewIssuer("did:web:badsig.test")
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"vc+sd-jwt"}`))
	pay := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"x"}`))
	badJWT := hdr + "." + pay + ".!invalid!sig!"
	_, err := VerifySDJWTWithBinding(badJWT+"~", iss.PublicKey(), VerifyOptions{})
	if err == nil || !strings.Contains(err.Error(), "sig encoding") {
		t.Errorf("bad sig encoding: want sig encoding error, got %v", err)
	}
}

func TestVerifySDJWTBadPayloadEncoding(t *testing.T) {
	// Payload segment has padding '=' (invalid for RawURLEncoding) (line 287).
	// We sign over the raw string so sig verify passes, then payload decode fails.
	iss, _ := NewIssuer("did:web:badpayenc.test")
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"vc+sd-jwt"}`))
	pay := "aGVsbG8=" // standard base64 of "hello" — has padding '='
	sig := ed25519.Sign(iss.privateKey, []byte(hdr+"."+pay))
	badJWT := hdr + "." + pay + "." + base64.RawURLEncoding.EncodeToString(sig)
	_, err := VerifySDJWTWithBinding(badJWT+"~", iss.PublicKey(), VerifyOptions{})
	if err == nil || !strings.Contains(err.Error(), "payload encoding") {
		t.Errorf("bad payload encoding: want payload encoding error, got %v", err)
	}
}

func TestVerifySDJWTBadPayloadJSON(t *testing.T) {
	// Payload decodes to non-JSON (line 291).
	iss, _ := NewIssuer("did:web:badpayjson.test")
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"vc+sd-jwt"}`))
	pay := base64.RawURLEncoding.EncodeToString([]byte("not json!!"))
	sig := ed25519.Sign(iss.privateKey, []byte(hdr+"."+pay))
	badJWT := hdr + "." + pay + "." + base64.RawURLEncoding.EncodeToString(sig)
	_, err := VerifySDJWTWithBinding(badJWT+"~", iss.PublicKey(), VerifyOptions{})
	if err == nil || !strings.Contains(err.Error(), "payload JSON") {
		t.Errorf("bad payload JSON: want payload JSON error, got %v", err)
	}
}

// ============================================================================
// VerifySDJWTWithBinding — disclosure processing error paths
// ============================================================================

func TestVerifySDJWTDisclosureNotInSD(t *testing.T) {
	// Disclosure whose digest is not in _sd → ErrSDJWTMalformed (line 366).
	iss, _ := NewIssuer("did:web:notinsd.test")
	payload := baseSDPayload(iss) // _sd is empty
	jwt := craftSignedJWT(iss.privateKey, payload)
	extraDisc := base64.RawURLEncoding.EncodeToString([]byte(`["salt","key","val"]`))
	sdjwt := jwt + "~" + extraDisc + "~"
	_, err := VerifySDJWTWithBinding(sdjwt, iss.PublicKey(), VerifyOptions{})
	if err != ErrSDJWTMalformed {
		t.Errorf("disc not in _sd: want ErrSDJWTMalformed, got %v", err)
	}
}

func TestVerifySDJWTDisclosureBadBase64(t *testing.T) {
	// Disclosure has invalid base64url chars; its hash IS in _sd → ErrSDJWTMalformed (line 373).
	iss, _ := NewIssuer("did:web:baddisc.test")
	badDisc := "not!valid!base64url"
	payload := baseSDPayload(iss)
	payload["_sd"] = []any{discHash(badDisc)}
	jwt := craftSignedJWT(iss.privateKey, payload)
	sdjwt := jwt + "~" + badDisc + "~"
	_, err := VerifySDJWTWithBinding(sdjwt, iss.PublicKey(), VerifyOptions{})
	if err != ErrSDJWTMalformed {
		t.Errorf("bad base64 disc: want ErrSDJWTMalformed, got %v", err)
	}
}

func TestVerifySDJWTDisclosureNotJSONArray(t *testing.T) {
	// Disclosure decodes to an object, not an array → ErrSDJWTMalformed (line 377).
	iss, _ := NewIssuer("did:web:notarr.test")
	disc := base64.RawURLEncoding.EncodeToString([]byte(`{"key":"value"}`))
	payload := baseSDPayload(iss)
	payload["_sd"] = []any{discHash(disc)}
	jwt := craftSignedJWT(iss.privateKey, payload)
	sdjwt := jwt + "~" + disc + "~"
	_, err := VerifySDJWTWithBinding(sdjwt, iss.PublicKey(), VerifyOptions{})
	if err != ErrSDJWTMalformed {
		t.Errorf("not-array disc: want ErrSDJWTMalformed, got %v", err)
	}
}

func TestVerifySDJWTDisclosureWrongArrayLength(t *testing.T) {
	// Disclosure decodes to a 2-element array (must be 3) → ErrSDJWTMalformed (line 380).
	iss, _ := NewIssuer("did:web:arrlen.test")
	disc := base64.RawURLEncoding.EncodeToString([]byte(`["salt","name"]`))
	payload := baseSDPayload(iss)
	payload["_sd"] = []any{discHash(disc)}
	jwt := craftSignedJWT(iss.privateKey, payload)
	sdjwt := jwt + "~" + disc + "~"
	_, err := VerifySDJWTWithBinding(sdjwt, iss.PublicKey(), VerifyOptions{})
	if err != ErrSDJWTMalformed {
		t.Errorf("wrong arr len: want ErrSDJWTMalformed, got %v", err)
	}
}

func TestVerifySDJWTDisclosureNonStringName(t *testing.T) {
	// Disclosure arr[1] is a number, not a string → ErrSDJWTMalformed (line 384).
	iss, _ := NewIssuer("did:web:nonstr.test")
	disc := base64.RawURLEncoding.EncodeToString([]byte(`["salt",123,"val"]`))
	payload := baseSDPayload(iss)
	payload["_sd"] = []any{discHash(disc)}
	jwt := craftSignedJWT(iss.privateKey, payload)
	sdjwt := jwt + "~" + disc + "~"
	_, err := VerifySDJWTWithBinding(sdjwt, iss.PublicKey(), VerifyOptions{})
	if err != ErrSDJWTMalformed {
		t.Errorf("non-string name: want ErrSDJWTMalformed, got %v", err)
	}
}

func TestVerifySDJWTDisclosureReservedName(t *testing.T) {
	// Disclosure uses a reserved claim name "iss" → ErrSDJWTMalformed (line 389).
	iss, _ := NewIssuer("did:web:resname.test")
	disc := base64.RawURLEncoding.EncodeToString([]byte(`["salt","iss","evil"]`))
	payload := baseSDPayload(iss)
	payload["_sd"] = []any{discHash(disc)}
	jwt := craftSignedJWT(iss.privateKey, payload)
	sdjwt := jwt + "~" + disc + "~"
	_, err := VerifySDJWTWithBinding(sdjwt, iss.PublicKey(), VerifyOptions{})
	if err != ErrSDJWTMalformed {
		t.Errorf("reserved name: want ErrSDJWTMalformed, got %v", err)
	}
}

func TestVerifySDJWTDisclosureDuplicateClaim(t *testing.T) {
	// Disclosure uses a name that already exists as a clear claim → ErrSDJWTMalformed (line 392).
	iss, _ := NewIssuer("did:web:dupname.test")
	disc := base64.RawURLEncoding.EncodeToString([]byte(`["salt","foo","val2"]`))
	payload := baseSDPayload(iss)
	payload["foo"] = "val1"                // clear claim
	payload["_sd"] = []any{discHash(disc)} // also a disclosed claim with the same name
	jwt := craftSignedJWT(iss.privateKey, payload)
	sdjwt := jwt + "~" + disc + "~"
	_, err := VerifySDJWTWithBinding(sdjwt, iss.PublicKey(), VerifyOptions{})
	if err != ErrSDJWTMalformed {
		t.Errorf("duplicate claim: want ErrSDJWTMalformed, got %v", err)
	}
}

// TestVerifySDJWTTooManyDisclosures verifies that an SD-JWT with more than
// maxSDJWTSegments "~"-separated segments is rejected before any slice
// allocation proportional to the segment count occurs. This guards against a
// DoS where an attacker appends thousands of "~" characters to any SD-JWT —
// the issuer signature covers only the first segment, so the trailer is
// attacker-editable without a valid issuer key.
func TestVerifySDJWTTooManyDisclosures(t *testing.T) {
	// Build a syntactically invalid (but oversized) SD-JWT with 257 "~" chars.
	oversized := "header.payload.sig" + strings.Repeat("~", maxSDJWTSegments+1)

	_, err := VerifySDJWTWithBinding(oversized, nil, VerifyOptions{})
	if err != ErrSDJWTTooManyDisclosures {
		t.Errorf("too many segments: want ErrSDJWTTooManyDisclosures, got %v", err)
	}

	// Same check via the backward-compat wrapper.
	_, err = VerifySDJWT(oversized, nil)
	if err != ErrSDJWTTooManyDisclosures {
		t.Errorf("VerifySDJWT: want ErrSDJWTTooManyDisclosures, got %v", err)
	}

	// Present() also applies the cap.
	_, err = Present(oversized, nil)
	if err != ErrSDJWTTooManyDisclosures {
		t.Errorf("Present: want ErrSDJWTTooManyDisclosures, got %v", err)
	}
}

// TestVerifySDJWTRejectsStringExp guards against a fail-open: a credential whose
// "exp" is a JSON string (rather than a NumericDate number) must be rejected, not
// silently treated as non-expiring. Some non-conformant issuer libraries emit
// string timestamps; before the fix the type assertion failed and expiry
// enforcement was disabled.
func TestVerifySDJWTRejectsStringExp(t *testing.T) {
	iss, _ := NewIssuer("did:web:strexp.test")
	payload := baseSDPayload(iss)
	payload["exp"] = "1700000000" // string, not a number — non-conformant
	sdjwt := craftSignedJWT(iss.privateKey, payload) + "~"
	_, err := VerifySDJWTWithBinding(sdjwt, iss.PublicKey(), VerifyOptions{})
	if err != ErrSDJWTMalformed {
		t.Errorf("string exp: want ErrSDJWTMalformed, got %v", err)
	}
}

// TestVerifySDJWTRejectsNonNumericTimeClaims covers iat/nbf with wrong JSON types
// (bool, string) — each must fail closed.
func TestVerifySDJWTRejectsNonNumericTimeClaims(t *testing.T) {
	iss, _ := NewIssuer("did:web:badtime.test")
	for _, tc := range []struct {
		name  string
		key   string
		value any
	}{
		{"iat as string", "iat", "1700000000"},
		{"iat as bool", "iat", true},
		{"nbf as string", "nbf", "1700000000"},
		{"exp as array", "exp", []any{1.0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := baseSDPayload(iss)
			payload[tc.key] = tc.value
			sdjwt := craftSignedJWT(iss.privateKey, payload) + "~"
			_, err := VerifySDJWTWithBinding(sdjwt, iss.PublicKey(), VerifyOptions{})
			if err != ErrSDJWTMalformed {
				t.Errorf("%s: want ErrSDJWTMalformed, got %v", tc.name, err)
			}
		})
	}
}

// TestVerifySDJWTAbsentTimeClaimsOK confirms the fix did not break the legitimate
// "claim absent" path: a credential with no exp/nbf still verifies (no expiry).
func TestVerifySDJWTAbsentTimeClaimsOK(t *testing.T) {
	iss, _ := NewIssuer("did:web:noexp.test")
	payload := baseSDPayload(iss) // has iat (number), no exp/nbf
	sdjwt := craftSignedJWT(iss.privateKey, payload) + "~"
	if _, err := VerifySDJWTWithBinding(sdjwt, iss.PublicKey(), VerifyOptions{}); err != nil {
		t.Errorf("absent exp/nbf should verify, got %v", err)
	}
}

// TestVerifySDJWTRejectsCritHeader verifies RFC 7515 §4.1.11: an issuer JWS
// header carrying a `crit` list (extension params the verifier must understand)
// is rejected, since BLRCS implements no JWS extensions.
func TestVerifySDJWTRejectsCritHeader(t *testing.T) {
	iss, _ := NewIssuer("did:web:crit.test")
	payload := baseSDPayload(iss)
	// Craft a signed JWT whose header includes a crit field.
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"vc+sd-jwt","crit":["x-custom"]}`))
	payBytes, _ := json.Marshal(payload)
	pay := base64.RawURLEncoding.EncodeToString(payBytes)
	sig := ed25519.Sign(iss.privateKey, []byte(hdr+"."+pay))
	sdjwt := hdr + "." + pay + "." + base64.RawURLEncoding.EncodeToString(sig) + "~"

	_, err := VerifySDJWTWithBinding(sdjwt, iss.PublicKey(), VerifyOptions{})
	if err != ErrSDJWTCritUnsupported {
		t.Errorf("crit header: want ErrSDJWTCritUnsupported, got %v", err)
	}
}

// ============================================================================
// verifyKBJWT — error paths (lines 470, 477, 481)
// ============================================================================

// appendKBJWT strips the trailing "~" from a bound SDJWT and appends a custom KB-JWT.
func appendKBJWT(sdjwt, kbjwt string) string {
	return strings.TrimSuffix(sdjwt, "~") + "~" + kbjwt
}

func TestVerifyKBJWTBadHeaderBase64(t *testing.T) {
	// KB-JWT header segment has invalid base64url chars → ErrKeyBindingInvalid (line 470).
	iss, _ := NewIssuer("did:web:kbhdr.test")
	holderPub, _, _ := ed25519.GenerateKey(rand.Reader)
	sdjwt, _, _ := iss.IssueSDJWTBound("sub", nil, nil, holderPub, time.Hour)
	sdjwt = appendKBJWT(sdjwt, "!!!.pay.sig")
	_, err := VerifySDJWTWithBinding(sdjwt, iss.PublicKey(), VerifyOptions{})
	if !errors.Is(err, ErrKeyBindingInvalid) {
		t.Errorf("bad KB header b64: want ErrKeyBindingInvalid, got %v", err)
	}
}

func TestVerifyKBJWTBadSigBase64(t *testing.T) {
	// KB-JWT sig segment has invalid base64url chars → ErrKeyBindingInvalid (line 477).
	iss, _ := NewIssuer("did:web:kbsig.test")
	holderPub, _, _ := ed25519.GenerateKey(rand.Reader)
	sdjwt, _, _ := iss.IssueSDJWTBound("sub", nil, nil, holderPub, time.Hour)
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"kb+jwt"}`))
	pay := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	sdjwt = appendKBJWT(sdjwt, hdr+"."+pay+".!!!invalidsig!!!")
	_, err := VerifySDJWTWithBinding(sdjwt, iss.PublicKey(), VerifyOptions{})
	if !errors.Is(err, ErrKeyBindingInvalid) {
		t.Errorf("bad KB sig b64: want ErrKeyBindingInvalid, got %v", err)
	}
}

func TestVerifyKBJWTBadPayloadBase64(t *testing.T) {
	// KB-JWT payload segment has invalid base64url (padding '=') → ErrKeyBindingInvalid (line 477).
	// Sign over the raw string so sig verify passes, then RawURLEncoding.Decode fails.
	iss, _ := NewIssuer("did:web:kbplb64.test")
	holderPub, holderPriv, _ := ed25519.GenerateKey(rand.Reader)
	sdjwt, _, _ := iss.IssueSDJWTBound("sub", nil, nil, holderPub, time.Hour)
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"kb+jwt"}`))
	pay := "aGVsbG8=" // standard base64 — padding '=' is invalid for RawURLEncoding
	sig := ed25519.Sign(holderPriv, []byte(hdr+"."+pay))
	kbjwt := hdr + "." + pay + "." + base64.RawURLEncoding.EncodeToString(sig)
	sdjwt = appendKBJWT(sdjwt, kbjwt)
	_, err := VerifySDJWTWithBinding(sdjwt, iss.PublicKey(), VerifyOptions{})
	if !errors.Is(err, ErrKeyBindingInvalid) {
		t.Errorf("bad KB payload b64: want ErrKeyBindingInvalid, got %v", err)
	}
}

func TestVerifyKBJWTBadPayloadJSON(t *testing.T) {
	// KB-JWT payload decodes successfully but is not a JSON map → ErrKeyBindingInvalid (line 481).
	// We sign over "hdr.payload" with holderPriv so sig verify passes, then JSON unmarshal fails.
	iss, _ := NewIssuer("did:web:kbpljson.test")
	holderPub, holderPriv, _ := ed25519.GenerateKey(rand.Reader)
	sdjwt, _, _ := iss.IssueSDJWTBound("sub", nil, nil, holderPub, time.Hour)
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"kb+jwt"}`))
	pay := base64.RawURLEncoding.EncodeToString([]byte("not json!")) // valid b64url, bad JSON
	sig := ed25519.Sign(holderPriv, []byte(hdr+"."+pay))
	kbjwt := hdr + "." + pay + "." + base64.RawURLEncoding.EncodeToString(sig)
	sdjwt = appendKBJWT(sdjwt, kbjwt)
	_, err := VerifySDJWTWithBinding(sdjwt, iss.PublicKey(), VerifyOptions{})
	if !errors.Is(err, ErrKeyBindingInvalid) {
		t.Errorf("bad KB payload JSON: want ErrKeyBindingInvalid, got %v", err)
	}
}

// ============================================================================
// PresentWithKeyBinding — error path (line 565)
// ============================================================================

func TestPresentWithKeyBindingEmptySJWT(t *testing.T) {
	// Present("") returns ErrSDJWTEmpty which PresentWithKeyBinding propagates (line 565).
	_, holderPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, err := PresentWithKeyBinding("", nil, holderPriv, "nonce", "aud", time.Now())
	if !errors.Is(err, ErrSDJWTEmpty) {
		t.Errorf("empty sdjwt: want ErrSDJWTEmpty, got %v", err)
	}
}

// ============================================================================
// BuildDLURI — non-digit GTIN (line 612)
// ============================================================================

func TestBuildDLURIGTINNonDigit(t *testing.T) {
	// GTIN of valid length (8) but containing a non-digit character → error (line 612).
	_, err := BuildDLURI("example.com", GS1Key{GTIN: "1234567A"})
	if err == nil || !strings.Contains(err.Error(), "non-digit") {
		t.Errorf("non-digit GTIN: want non-digit error, got %v", err)
	}
}

// ============================================================================
// issueSDJWT claim-set validation — fail-fast at issuance (Axis 7)
// ============================================================================

// TestIssueSDJWTSDClaimReserved pins that passing a reserved JWT/SD-JWT claim
// name (e.g. "iss") inside sdClaims is rejected at issuance time.
//
// Without this guard the issuer signs and returns the credential; the verifier
// then always rejects it with ErrSDJWTMalformed (disclosure collides with reserved
// claim) — the credential subject has no indication the credential was broken.
func TestIssueSDJWTSDClaimReserved(t *testing.T) {
	iss, _ := NewIssuer("did:web:test")
	for _, reserved := range []string{"iss", "sub", "vct", "iat", "exp", "_sd", "_sd_alg", "cnf", "status"} {
		_, _, err := iss.IssueSDJWT("s", map[string]any{reserved: "injected"}, nil, time.Hour)
		if err == nil || !strings.Contains(err.Error(), "reserved claim") {
			t.Errorf("sdClaims[%q]: want reserved-claim error, got %v", reserved, err)
		}
	}
}

// TestIssueSDJWTClearSDOverlap pins that a claim appearing in both sdClaims and
// clearClaims is rejected at issuance time.
//
// Without this guard the issuer produces a credential that always fails verification:
// the verifier finds the clear claim already in vc.Claims when it processes the
// matching disclosure, and returns ErrSDJWTMalformed.
func TestIssueSDJWTClearSDOverlap(t *testing.T) {
	iss, _ := NewIssuer("did:web:test")
	_, _, err := iss.IssueSDJWT(
		"s",
		map[string]any{"category": "battery"},   // sdClaims
		map[string]any{"category": "duplicate"}, // clearClaims — same key
		time.Hour,
	)
	if err == nil || !strings.Contains(err.Error(), "both sdClaims and clearClaims") {
		t.Errorf("sd/clear overlap: want overlap error, got %v", err)
	}
}

// TestVerifySDJWTExpectedIssuerMismatch verifies that VerifyOptions.ExpectedIssuer
// prevents key-confusion attacks where a verifier's trusted issuer key is used to
// verify a credential from a different issuer (e.g. a relay attacker obtaining a
// valid token signed by a different, also-trusted key and presenting it as-is).
func TestVerifySDJWTExpectedIssuerMismatch(t *testing.T) {
	issuerA, _ := NewIssuer("did:web:issuer-a.example")
	issuerB, _ := NewIssuer("did:web:issuer-b.example")

	// Issuer A signs a credential.
	sdjwt, _, err := issuerA.IssueSDJWT("sub", map[string]any{"tier": "A"}, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Case 1: ExpectedIssuer matches — must succeed.
	_, err = VerifySDJWTWithBinding(sdjwt, issuerA.PublicKey(), VerifyOptions{
		ExpectedIssuer: "did:web:issuer-a.example",
	})
	if err != nil {
		t.Fatalf("correct ExpectedIssuer: want nil, got %v", err)
	}

	// Case 2: ExpectedIssuer empty — backward-compat, must succeed.
	_, err = VerifySDJWTWithBinding(sdjwt, issuerA.PublicKey(), VerifyOptions{})
	if err != nil {
		t.Fatalf("empty ExpectedIssuer: want nil, got %v", err)
	}

	// Case 3: ExpectedIssuer set to B but credential claims A — key-confusion rejected.
	_, err = VerifySDJWTWithBinding(sdjwt, issuerA.PublicKey(), VerifyOptions{
		ExpectedIssuer: "did:web:issuer-b.example",
	})
	if !errors.Is(err, ErrSDJWTIssuerMismatch) {
		t.Errorf("wrong ExpectedIssuer: want ErrSDJWTIssuerMismatch, got %v", err)
	}

	// Case 4: Issuer B has a different key — even if the verifier somehow has B's
	// key, verifying A's credential against it fails at the sig step first.
	_, err = VerifySDJWTWithBinding(sdjwt, issuerB.PublicKey(), VerifyOptions{
		ExpectedIssuer: "did:web:issuer-a.example",
	})
	if !errors.Is(err, ErrSDJWTSigFailed) {
		t.Errorf("wrong key: want ErrSDJWTSigFailed, got %v", err)
	}
}
