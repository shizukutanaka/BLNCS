package compliance_test

import (
	"fmt"
	"time"

	"blrcs/compliance"
)

// Demonstrates issuing and verifying a Digital Product Passport.
func Example_issueDPP() {
	issuer, _ := compliance.NewIssuer("did:web:factory.example")
	cred, _ := issuer.Issue(compliance.PassportClaim{
		ProductID:    "04012345678901",
		Category:     "battery/ev",
		CarbonKgCO2e: 48.5,
	}, 365*24*time.Hour)
	err := compliance.Verify(cred, issuer.PublicKey())
	fmt.Println("verified:", err == nil)
	// Output: verified: true
}

// Demonstrates SD-JWT selective disclosure — revealing only chosen fields.
func Example_selectiveDisclosure() {
	issuer, _ := compliance.NewIssuer("did:web:factory.example")
	sdjwt, _, _ := issuer.IssueSDJWT("holder-1",
		map[string]any{"carbon": 48.5, "secret": "hidden"},
		map[string]any{"public": "always"},
		time.Hour,
	)
	presented, _ := compliance.Present(sdjwt, []string{"carbon"})
	vc, _ := compliance.VerifySDJWT(presented, issuer.PublicKey())
	fmt.Println("carbon:", vc.Claims["carbon"])
	fmt.Println("secret leaked:", vc.Claims["secret"] != nil)
	// Output:
	// carbon: 48.5
	// secret leaked: false
}

// Demonstrates building a GS1 Digital Link URI.
func Example_gs1DigitalLink() {
	uri, _ := compliance.BuildDLURI("id.gs1.org", compliance.GS1Key{
		GTIN: "04012345678901", Serial: "SN-001",
	})
	fmt.Println(uri)
	// Output: https://id.gs1.org/01/04012345678901/21/SN-001
}

// Demonstrates the GS1 Digital Link discovery flow: a scanned GTIN resolves to a
// linkset that routes to the DPP, conformity doc, and sustainability info.
func Example_gs1DigitalLinkDiscovery() {
	// A QR code encodes this GTIN-based Digital Link URI.
	uri, _ := compliance.BuildDLURI("id.example.com", compliance.GS1Key{GTIN: "04012345678901"})

	// Resolving it returns a linkset routing to each related resource by linkType.
	ls := compliance.NewLinkset(uri).
		Add(compliance.LinkTypeDPP,
			compliance.Link{Href: "https://dpp.example/p/1", Type: "application/vc+ld+json"}).
		Add(compliance.LinkTypeCertification,
			compliance.Link{Href: "https://doc.example/conformity.pdf", Type: "application/pdf"})

	fmt.Println("anchor:", ls.Anchor)
	fmt.Println("passport:", ls.Get(compliance.LinkTypeDPP)[0].Href)
	// Output:
	// anchor: https://id.example.com/01/04012345678901
	// passport: https://dpp.example/p/1
}

// Demonstrates the ESPR three-tier access model: public data is always readable,
// restricted/authority data is selectively disclosed.
func Example_threeTierAccess() {
	iss, _ := compliance.NewIssuer("did:web:factory.example")

	claims := compliance.NewTieredClaims().
		Set("carbonKgCO2ePerKWh", 12.5, compliance.TierPublic).          // consumer-visible
		Set("materialComposition", "NMC811", compliance.TierRestricted). // recyclers
		Set("supplierContract", "ref-9982", compliance.TierAuthority)    // market surveillance

	// A market-surveillance authority is entitled to everything.
	authView := claims.ClaimsAtOrBelow(compliance.TierAuthority)
	// A consumer sees only public data.
	publicView := claims.ClaimsAtOrBelow(compliance.TierPublic)

	fmt.Println("authority sees:", len(authView), "claims")
	fmt.Println("consumer sees:", len(publicView), "claim")

	_, disclosures, _ := iss.IssueSDJWTTiered("battery-1", claims, 0)
	fmt.Println("selectively-disclosable (non-public):", len(disclosures))
	// Output:
	// authority sees: 3 claims
	// consumer sees: 1 claim
	// selectively-disclosable (non-public): 2
}
