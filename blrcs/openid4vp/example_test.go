package openid4vp_test

import (
	"fmt"

	"blrcs/openid4vp"
)

// Demonstrates an OpenID4VP v1.0 verifier requesting a DPP credential via DCQL.
//
// Presentation Exchange was removed in OID4VP v1.0; DCQL is the only query
// language. This requests an SD-JWT VC of the DPP type disclosing the carbon claim.
func Example_dcqlRequest() {
	query := openid4vp.DCQLQuery{
		Credentials: []openid4vp.CredentialQuery{{
			ID:     "dpp",
			Format: "dc+sd-jwt",
			Meta: &openid4vp.CredentialQueryMeta{
				VCTValues: []string{"https://schema.europa.eu/dpp/sd-jwt-vc/v1"},
			},
			Claims: []openid4vp.ClaimQuery{
				{Path: []string{"carbonKgCO2ePerKWh"}},
			},
		}},
	}

	// A holder's credential is checked against the query.
	presented := map[string]any{"carbonKgCO2ePerKWh": 12.5}
	match := query.Credentials[0].MatchClaims(presented)
	fmt.Println("credential satisfies query:", match)

	wire, _ := openid4vp.MarshalDCQL(query)
	fmt.Println("wire uses dc+sd-jwt:", contains(string(wire), "dc+sd-jwt"))
	// Output:
	// credential satisfies query: true
	// wire uses dc+sd-jwt: true
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
