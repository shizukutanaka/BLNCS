package builder

import (
	"strings"
	"testing"
	"time"

	"blrcs/compliance"
	"blrcs/types"
)

func mustIssuer(t *testing.T) *compliance.Issuer {
	t.Helper()
	iss, err := compliance.NewIssuer("did:web:factory.builder.test")
	if err != nil {
		t.Fatal(err)
	}
	return iss
}

// ============================================================================
// DPP Builder
// ============================================================================

func TestDPPBuilderHappyPath(t *testing.T) {
	iss := mustIssuer(t)
	gtin := types.MustGTIN("04012345678901")
	country := types.MustCountryCode("JP")
	carbon := types.MustCarbonFootprint(2.47)
	recycled := types.MustPercent(82)

	cred, err := NewDPP().
		Issuer(types.MustDID(iss.ID)).
		ProductID(gtin).
		Category("textile/garment").
		OriginCountry(country).
		Carbon(carbon).
		Recyclability(recycled).
		Build(iss)
	if err != nil {
		t.Fatal(err)
	}
	if err := compliance.Verify(cred, iss.PublicKey()); err != nil {
		t.Fatalf("issued credential fails verification: %v", err)
	}
	if cred.Subject.ProductID != gtin.String() {
		t.Errorf("productID: %s", cred.Subject.ProductID)
	}
	if cred.Subject.Recyclability != float32(82.0/100) {
		t.Errorf("recyclability: %f", cred.Subject.Recyclability)
	}
	if cred.Subject.CarbonKgCO2e != 2.47 {
		t.Errorf("carbon: %f", cred.Subject.CarbonKgCO2e)
	}
}

func TestDPPBuilderMissingProductID(t *testing.T) {
	iss := mustIssuer(t)
	_, err := NewDPP().
		Issuer(types.MustDID(iss.ID)).
		Category("textile").
		Build(iss)
	if err == nil {
		t.Fatal("should fail without GTIN")
	}
	if !strings.Contains(err.Error(), "GTIN") {
		t.Errorf("error should mention GTIN, got: %s", err.Error())
	}
}

func TestDPPBuilderMissingIssuer(t *testing.T) {
	iss := mustIssuer(t)
	_, err := NewDPP().
		ProductID(types.MustGTIN("04012345678901")).
		Category("textile").
		Build(iss)
	if err == nil {
		t.Fatal("should fail without issuer DID")
	}
}

func TestDPPBuilderInvalidLifecyclePhase(t *testing.T) {
	iss := mustIssuer(t)
	_, err := NewDPP().
		Issuer(types.MustDID(iss.ID)).
		ProductID(types.MustGTIN("04012345678901")).
		Category("textile").
		LifecyclePhase("invalid-phase"). // invalid
		Build(iss)
	if err == nil {
		t.Fatal("invalid lifecycle phase should fail")
	}
	if !strings.Contains(err.Error(), "lifecyclePhase") {
		t.Errorf("missing field name in error: %s", err.Error())
	}
}

func TestDPPBuilderHazardousAndAttrs(t *testing.T) {
	iss := mustIssuer(t)
	cred, err := NewDPP().
		Issuer(types.MustDID(iss.ID)).
		ProductID(types.MustGTIN("04012345678901")).
		Category("electronics").
		Hazardous("Lead", "Cadmium").
		Attr("dismantlingGuide", "https://example.com/guide").
		Build(iss)
	if err != nil {
		t.Fatal(err)
	}
	if len(cred.Subject.HazardousContent) != 2 {
		t.Errorf("hazardous count: %d", len(cred.Subject.HazardousContent))
	}
	if cred.Subject.Attrs["dismantlingGuide"] != "https://example.com/guide" {
		t.Error("attr not preserved")
	}
}

func TestDPPBuilderDefaultSensible(t *testing.T) {
	iss := mustIssuer(t)
	cred, err := NewDPP().
		Issuer(types.MustDID(iss.ID)).
		ProductID(types.MustGTIN("04012345678901")).
		Category("textile").
		Build(iss)
	if err != nil {
		t.Fatal(err)
	}
	// Default lifecycle phase should be "manufacture"
	if cred.Subject.LifecyclePhase != "manufacture" {
		t.Errorf("default lifecycle: %s", cred.Subject.LifecyclePhase)
	}
	// Default validity should be 1 year (expiration set)
	if cred.ValidUntil == nil {
		t.Error("default should set validUntil")
	}
}

// ============================================================================
// Battery Builder
// ============================================================================

func TestBatteryBuilderHappyPath(t *testing.T) {
	iss := mustIssuer(t)
	gtin := types.MustGTIN("04012345678901")

	cred, err := NewBattery().
		BatteryID("BAT-2026-001").
		GTIN(gtin).
		Category(compliance.BatteryCategoryEV).
		DueDiligenceReport("https://factory.example/dd.pdf").
		Chemistry(compliance.ChemistryNMC).
		CapacityKWh(75).
		VoltageV(400).
		WeightKg(450).
		CarbonIntensity(types.MustCarbonFootprint(48.5)).
		CarbonClass("B").
		RecycledContent(16, 6, 12, 0).
		PlaceOfManufacture("Kyoto, JP").
		ModelID("PackX-75").
		Build(iss)
	if err != nil {
		t.Fatal(err)
	}
	if err := compliance.Verify(cred, iss.PublicKey()); err != nil {
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
}

func TestBatteryBuilderMissingRequired(t *testing.T) {
	iss := mustIssuer(t)
	cases := []struct {
		name string
		fn   func() (*compliance.Credential, error)
	}{
		{"missing batteryID", func() (*compliance.Credential, error) {
			return NewBattery().Category(compliance.BatteryCategoryEV).
				DueDiligenceReport("https://factory.example/dd.pdf").Chemistry(compliance.ChemistryLFP).CapacityKWh(75).Build(iss)
		}},
		{"missing category", func() (*compliance.Credential, error) {
			return NewBattery().BatteryID("X").Chemistry(compliance.ChemistryLFP).CapacityKWh(75).Build(iss)
		}},
		{"missing chemistry", func() (*compliance.Credential, error) {
			return NewBattery().BatteryID("X").Category(compliance.BatteryCategoryEV).
				DueDiligenceReport("https://factory.example/dd.pdf").CapacityKWh(75).Build(iss)
		}},
		{"zero capacity", func() (*compliance.Credential, error) {
			return NewBattery().BatteryID("X").Category(compliance.BatteryCategoryEV).
				DueDiligenceReport("https://factory.example/dd.pdf").Chemistry(compliance.ChemistryLFP).Build(iss)
		}},
	}
	for _, c := range cases {
		_, err := c.fn()
		if err == nil {
			t.Errorf("%s: should fail", c.name)
		}
	}
}

func TestBatteryBuilderInvalidCarbonClass(t *testing.T) {
	iss := mustIssuer(t)
	_, err := NewBattery().
		BatteryID("B1").
		Category(compliance.BatteryCategoryEV).
		DueDiligenceReport("https://factory.example/dd.pdf").
		Chemistry(compliance.ChemistryNMC).
		CapacityKWh(75).
		CarbonClass("Z"). // invalid
		Build(iss)
	if err == nil {
		t.Fatal("invalid carbon class should fail")
	}
	if !strings.Contains(err.Error(), "CarbonClass") {
		t.Errorf("error should mention CarbonClass: %s", err.Error())
	}
}

func TestBatteryBuilderInvalidRecycledContent(t *testing.T) {
	iss := mustIssuer(t)
	_, err := NewBattery().
		BatteryID("B1").
		Category(compliance.BatteryCategoryEV).
		DueDiligenceReport("https://factory.example/dd.pdf").
		Chemistry(compliance.ChemistryNMC).
		CapacityKWh(75).
		RecycledContent(150, 0, 0, 0). // 150% invalid
		Build(iss)
	if err == nil {
		t.Fatal("150% recycled should fail")
	}
}

// ============================================================================
// Error accumulation (Apple: show ALL errors at once)
// ============================================================================

func TestBuildValidationErrorString(t *testing.T) {
	e := &BuildValidationError{Issues: []string{"field A missing", "field B invalid"}}
	s := e.Error()
	if !strings.Contains(s, "field A missing") || !strings.Contains(s, "field B invalid") {
		t.Errorf("both issues should appear: %s", s)
	}
}

func TestSingleErrorString(t *testing.T) {
	e := &BuildValidationError{Issues: []string{"just one problem"}}
	s := e.Error()
	if !strings.Contains(s, "just one problem") {
		t.Errorf("single issue: %s", s)
	}
}

// ============================================================================
// Coverage uplift: ValidFor, Serial, DateOfManufacture, StateOfHealth, CycleCount
// ============================================================================

func TestDPPBuilderValidFor(t *testing.T) {
	iss, _ := compliance.NewIssuer("did:web:test")
	_, err := NewDPP().
		Issuer(types.MustDID(iss.ID)).
		ProductID(types.MustGTIN("04012345678901")).
		Category("battery/ev").
		ValidFor(5 * 365 * 24 * time.Hour).
		Build(iss)
	if err != nil {
		t.Fatalf("ValidFor: %v", err)
	}
}

func TestDPPBuilderLifecyclePhaseProduce(t *testing.T) {
	iss, _ := compliance.NewIssuer("did:web:test")
	_, err := NewDPP().
		Issuer(types.MustDID(iss.ID)).
		ProductID(types.MustGTIN("04012345678901")).
		Category("battery/ev").
		LifecyclePhase("manufacture").
		Build(iss)
	if err != nil {
		t.Fatalf("lifecycle phase produce: %v", err)
	}
}

func TestBatteryBuilderSerial(t *testing.T) {
	iss, _ := compliance.NewIssuer("did:web:test")
	cf, _ := types.NewCarbonFootprint(48.5)
	_, err := NewBattery().
		BatteryID("BAT-001").
		Category(compliance.BatteryCategoryEV).
		DueDiligenceReport("https://factory.example/dd.pdf").
		Chemistry(compliance.ChemistryNMC).
		CapacityKWh(75.0).
		CarbonIntensity(cf).
		CarbonClass("A").
		RecycledContent(0.42, 0.1, 0.2, 0.05).
		Serial("SN-2025-001").
		Build(iss)
	if err != nil {
		t.Fatalf("battery serial: %v", err)
	}
}

func TestBatteryBuilderDateOfManufacture(t *testing.T) {
	iss, _ := compliance.NewIssuer("did:web:test")
	cf, _ := types.NewCarbonFootprint(30.0)
	mfr := time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC)
	_, err := NewBattery().
		BatteryID("BAT-002").
		Category(compliance.BatteryCategoryEV).
		DueDiligenceReport("https://factory.example/dd.pdf").
		Chemistry(compliance.ChemistryLFP).
		CapacityKWh(50.0).
		CarbonIntensity(cf).
		CarbonClass("B").
		RecycledContent(0.30, 0.10, 0.15, 0.03).
		DateOfManufacture(mfr).
		StateOfHealth(0.98).
		CycleCount(12).
		ValidFor(10 * 365 * 24 * time.Hour).
		Build(iss)
	if err != nil {
		t.Fatalf("battery date/health/cycle: %v", err)
	}
}
