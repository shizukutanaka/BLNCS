package compliance_test

import (
	"fmt"
	"time"

	"blrcs/compliance"
	"blrcs/types"
)

// ============================================================================
// These are the README's "Library usage" examples, as executable Go Examples.
//
// They live here rather than only in README.md because documentation that is
// not compiled rots silently: the previous README example was written against
// the `builder` package and kept claiming to work for as long as nobody tried
// it. A Go Example with an Output comment is compiled AND run by `go test`, so
// the front-door documentation now fails the build the moment it stops being
// true. Keep these and README.md in sync.
//
// Only deterministic values are printed — issuance uses fresh salts, keys and
// timestamps, so anything else would make the Output comment flaky.
// ============================================================================

// Example_issueCredential is the README's W3C Verifiable Credential example.
func Example_issueCredential() {
	issuer, err := compliance.NewIssuer("did:web:factory.example")
	if err != nil {
		panic(err)
	}

	cred, err := issuer.Issue(compliance.PassportClaim{
		ProductID:     types.MustGTIN("04012345678901").String(),
		Category:      "battery/ev",
		OriginCountry: types.MustCountryCode("JP").String(),
		Manufacturer:  issuer.ID,
		CarbonKgCO2e:  48.5,
		Recyclability: 0.82,
	}, 10*365*24*time.Hour)
	if err != nil {
		panic(err)
	}

	// The default suite is the current W3C REC, not the legacy one.
	fmt.Println("proof:", cred.Proof.Type, cred.Proof.Cryptosuite)
	fmt.Println("product:", cred.Subject.ProductID)
	fmt.Println("verify:", compliance.Verify(cred, issuer.PublicKey()))

	// Output:
	// proof: DataIntegrityProof eddsa-jcs-2022
	// product: 04012345678901
	// verify: <nil>
}

// Example_nestedSelectiveDisclosure is the README's selective-disclosure
// example: mark disclosable positions with SD, present by path, and the holder
// reveals one nested field without its siblings.
func Example_nestedSelectiveDisclosure() {
	issuer, err := compliance.NewIssuer("did:web:factory.example")
	if err != nil {
		panic(err)
	}

	sdjwt, _, err := issuer.IssueSDJWTVC("DigitalProductPassport", "battery-001",
		nil, map[string]any{
			"address": map[string]any{
				"country": compliance.SD("JP"),
				"city":    compliance.SD("Osaka"),
			},
			"markets": []any{compliance.SD("JP"), compliance.SD("DE")},
		}, time.Hour)
	if err != nil {
		panic(err)
	}

	// Reveal only the country. Ancestor disclosures are included automatically.
	presented, err := compliance.PresentPaths(sdjwt, [][]any{{"address", "country"}})
	if err != nil {
		panic(err)
	}
	vc, err := compliance.VerifySDJWT(presented, issuer.PublicKey())
	if err != nil {
		panic(err)
	}

	address := vc.Claims["address"].(map[string]any)
	_, cityDisclosed := address["city"]
	_, marketsDisclosed := vc.Claims["markets"]
	fmt.Println("country:", address["country"])
	fmt.Println("city disclosed:", cityDisclosed)
	fmt.Println("markets disclosed:", marketsDisclosed)

	// Output:
	// country: JP
	// city disclosed: false
	// markets disclosed: true
}
