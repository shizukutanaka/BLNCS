package compliance_test

import (
	"fmt"
	"time"

	"blrcs/compliance"
)

// Demonstrates issuing a fully EU 2023/1542 Annex XIII-compliant battery passport.
func Example_batteryPassportAnnexXIII() {
	iss, _ := compliance.NewIssuer("did:web:gigafactory.example")

	cred, err := iss.IssueBatteryPassport(compliance.BatteryPassportClaim{
		BatteryID:                    "EV-BAT-2026-001",
		Category:                     compliance.BatteryCategoryEV,
		Chemistry:                    compliance.ChemistryNMC,
		CapacityKWh:                  75.0,
		VoltageV:                     400,
		CarbonFootprintKgCO2ePerKWh:  48.5,
		CarbonFootprintClass:         "A",
		RecycledContent:              compliance.RecycledContent{Cobalt: 0.16, Lithium: 0.06, Nickel: 0.06},
		RenewableContentPct:          35.0,
		ExpectedLifetimeYears:        15.0,
		EUDeclarationOfConformityURL: "https://gigafactory.example/doc/2026.pdf",
		DueDiligenceReportURL:        "https://gigafactory.example/dd/2026.pdf", // Art.52 required for EV
		SeparateCollection:           true,
		Recyclable:                   true,
	}, 15*365*24*time.Hour)
	if err != nil {
		panic(err)
	}

	fmt.Println("issued:", cred.Subject.ProductID)
	fmt.Println("carbon class:", cred.Subject.Attrs["carbonFootprintClass"])
	fmt.Println("due-diligence:", cred.Subject.Attrs["dueDiligenceReportUrl"] != "")
	// Output:
	// issued: EV-BAT-2026-001
	// carbon class: A
	// due-diligence: true
}

// Demonstrates that EV batteries without a due-diligence report are rejected (Art.52).
func Example_batteryPassportDueDiligenceRequired() {
	iss, _ := compliance.NewIssuer("did:web:factory.example")

	_, err := iss.IssueBatteryPassport(compliance.BatteryPassportClaim{
		BatteryID:   "EV-NO-DD",
		Category:    compliance.BatteryCategoryEV,
		Chemistry:   compliance.ChemistryNMC,
		CapacityKWh: 75.0,
		// DueDiligenceReportURL omitted → rejected
	}, time.Hour)

	fmt.Println("rejected:", err == compliance.ErrDueDiligenceRequired)
	// Output: rejected: true
}
