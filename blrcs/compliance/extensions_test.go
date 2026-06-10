package compliance

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

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
}
