package openid4vp

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"blrcs/compliance"
)

// helpers shared across complexity tests
func makeCredQuery(id string, nClaims, pathDepth, nValues int) CredentialQuery {
	claims := make([]ClaimQuery, nClaims)
	for i := range claims {
		path := make([]string, pathDepth)
		for p := range path {
			path[p] = "k"
		}
		vals := make([]any, nValues)
		for v := range vals {
			vals[v] = v
		}
		claims[i] = ClaimQuery{Path: path, Values: vals}
	}
	return CredentialQuery{ID: id, Format: "dc+sd-jwt", Claims: claims}
}

func TestDCQLValidateHappy(t *testing.T) {
	q := DCQLQuery{
		Credentials: []CredentialQuery{{
			ID:     "dpp",
			Format: "dc+sd-jwt",
			Meta:   &CredentialQueryMeta{VCTValues: []string{"https://schema.europa.eu/dpp/sd-jwt-vc/v1"}},
			Claims: []ClaimQuery{{Path: []string{"carbonKgCO2ePerKWh"}}},
		}},
	}
	if err := q.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestDCQLValidateEmpty(t *testing.T) {
	q := DCQLQuery{}
	if err := q.Validate(); err == nil {
		t.Error("empty credentials should fail")
	}
}

func TestDCQLValidateMissingID(t *testing.T) {
	q := DCQLQuery{Credentials: []CredentialQuery{{Format: "dc+sd-jwt"}}}
	if err := q.Validate(); err == nil {
		t.Error("missing id should fail")
	}
}

func TestDCQLValidateMissingFormat(t *testing.T) {
	q := DCQLQuery{Credentials: []CredentialQuery{{ID: "x"}}}
	if err := q.Validate(); err == nil {
		t.Error("missing format should fail")
	}
}

func TestDCQLValidateDuplicateID(t *testing.T) {
	q := DCQLQuery{Credentials: []CredentialQuery{
		{ID: "x", Format: "dc+sd-jwt"},
		{ID: "x", Format: "mso_mdoc"},
	}}
	if err := q.Validate(); err == nil {
		t.Error("duplicate id should fail")
	}
}

func TestDCQLValidateCredentialSetUnknownID(t *testing.T) {
	q := DCQLQuery{
		Credentials:    []CredentialQuery{{ID: "a", Format: "dc+sd-jwt"}},
		CredentialSets: []CredentialSetQuery{{Options: [][]string{{"b"}}}},
	}
	if err := q.Validate(); err == nil {
		t.Error("credential_set referencing unknown id should fail")
	}
}

func TestDCQLValidateCredentialSetEmptyOptions(t *testing.T) {
	q := DCQLQuery{
		Credentials:    []CredentialQuery{{ID: "a", Format: "dc+sd-jwt"}},
		CredentialSets: []CredentialSetQuery{{Options: [][]string{}}},
	}
	if err := q.Validate(); err == nil {
		t.Error("empty options should fail")
	}
}

// ============================================================================
// Axis 128: claim_sets (§6.3.1)
// ============================================================================

func TestDCQLValidateClaimSetsHappy(t *testing.T) {
	q := DCQLQuery{
		Credentials: []CredentialQuery{{
			ID:     "id-doc",
			Format: "dc+sd-jwt",
			Claims: []ClaimQuery{
				{ID: "passport_number", Path: []string{"passportNumber"}},
				{ID: "license_number", Path: []string{"licenseNumber"}},
			},
			ClaimSets: [][]string{{"passport_number"}, {"license_number"}},
		}},
	}
	if err := q.Validate(); err != nil {
		t.Fatalf("valid claim_sets should pass: %v", err)
	}
}

func TestDCQLValidateClaimSetsRequiresIDs(t *testing.T) {
	q := DCQLQuery{
		Credentials: []CredentialQuery{{
			ID:     "id-doc",
			Format: "dc+sd-jwt",
			Claims: []ClaimQuery{
				{ID: "passport_number", Path: []string{"passportNumber"}},
				{Path: []string{"licenseNumber"}}, // no id
			},
			ClaimSets: [][]string{{"passport_number"}},
		}},
	}
	if err := q.Validate(); err == nil {
		t.Error("claim_sets with an unlabeled claim should fail")
	}
}

func TestDCQLValidateClaimSetsUnknownID(t *testing.T) {
	q := DCQLQuery{
		Credentials: []CredentialQuery{{
			ID:        "id-doc",
			Format:    "dc+sd-jwt",
			Claims:    []ClaimQuery{{ID: "a", Path: []string{"a"}}},
			ClaimSets: [][]string{{"nonexistent"}},
		}},
	}
	if err := q.Validate(); err == nil {
		t.Error("claim_sets referencing unknown claim id should fail")
	}
}

func TestDCQLValidateClaimSetsEmptyOption(t *testing.T) {
	q := DCQLQuery{
		Credentials: []CredentialQuery{{
			ID:        "id-doc",
			Format:    "dc+sd-jwt",
			Claims:    []ClaimQuery{{ID: "a", Path: []string{"a"}}},
			ClaimSets: [][]string{{}},
		}},
	}
	if err := q.Validate(); err == nil {
		t.Error("empty claim_sets option should fail")
	}
}

func TestDCQLValidateClaimSetsDuplicateClaimID(t *testing.T) {
	q := DCQLQuery{
		Credentials: []CredentialQuery{{
			ID:     "id-doc",
			Format: "dc+sd-jwt",
			Claims: []ClaimQuery{
				{ID: "dup", Path: []string{"a"}},
				{ID: "dup", Path: []string{"b"}},
			},
		}},
	}
	if err := q.Validate(); err == nil {
		t.Error("duplicate claim id within a credential query should fail")
	}
}

// TestMatchClaimsClaimSetsAlternative proves the OR-of-ANDs semantics: a
// credential disclosing EITHER a passport number OR a license number (not
// both) satisfies the query, but one disclosing neither does not.
func TestMatchClaimsClaimSetsAlternative(t *testing.T) {
	cq := CredentialQuery{
		ID:     "id-doc",
		Format: "dc+sd-jwt",
		Claims: []ClaimQuery{
			{ID: "passport_number", Path: []string{"passportNumber"}},
			{ID: "license_number", Path: []string{"licenseNumber"}},
		},
		ClaimSets: [][]string{{"passport_number"}, {"license_number"}},
	}
	if !cq.MatchClaims(map[string]any{"passportNumber": "P123"}) {
		t.Error("passport-only disclosure should satisfy the first option")
	}
	if !cq.MatchClaims(map[string]any{"licenseNumber": "L456"}) {
		t.Error("license-only disclosure should satisfy the second option")
	}
	if !cq.MatchClaims(map[string]any{"passportNumber": "P123", "licenseNumber": "L456"}) {
		t.Error("disclosing both should still satisfy (first option fully covered)")
	}
	if cq.MatchClaims(map[string]any{"unrelated": "x"}) {
		t.Error("neither option satisfied should not match")
	}
}

// TestMatchClaimsClaimSetsMultiClaimOption proves an option requiring
// multiple claim ids needs ALL of them present (AND within an option).
func TestMatchClaimsClaimSetsMultiClaimOption(t *testing.T) {
	cq := CredentialQuery{
		ID:     "addr",
		Format: "dc+sd-jwt",
		Claims: []ClaimQuery{
			{ID: "street", Path: []string{"street"}},
			{ID: "city", Path: []string{"city"}},
			{ID: "poBox", Path: []string{"poBox"}},
		},
		ClaimSets: [][]string{{"street", "city"}, {"poBox"}},
	}
	if !cq.MatchClaims(map[string]any{"street": "Main St", "city": "Berlin"}) {
		t.Error("street+city option fully disclosed should match")
	}
	if cq.MatchClaims(map[string]any{"street": "Main St"}) {
		t.Error("partial option (missing city) should not match")
	}
	if !cq.MatchClaims(map[string]any{"poBox": "123"}) {
		t.Error("poBox-only option should match")
	}
}

// TestMatchClaimsClaimSetsValueConstraint proves value constraints on a
// claim referenced by claim_sets are still enforced.
func TestMatchClaimsClaimSetsValueConstraint(t *testing.T) {
	cq := CredentialQuery{
		ID:     "cat",
		Format: "dc+sd-jwt",
		Claims: []ClaimQuery{
			{ID: "category", Path: []string{"category"}, Values: []any{"EV"}},
		},
		ClaimSets: [][]string{{"category"}},
	}
	if !cq.MatchClaims(map[string]any{"category": "EV"}) {
		t.Error("matching value should satisfy")
	}
	if cq.MatchClaims(map[string]any{"category": "ICE"}) {
		t.Error("non-matching value should not satisfy despite id being present")
	}
}

func TestDCQLFromPresentationDefinition(t *testing.T) {
	def := PresentationDefinition{
		ID:             "battery-check",
		Format:         "sd-jwt",
		RequiredClaims: []string{"carbonKgCO2ePerKWh", "batteryCategory"},
	}
	q := DCQLFromPresentationDefinition(def)
	if err := q.Validate(); err != nil {
		t.Fatalf("bridged query invalid: %v", err)
	}
	if len(q.Credentials) != 1 {
		t.Fatalf("expected 1 credential query, got %d", len(q.Credentials))
	}
	cq := q.Credentials[0]
	if cq.Format != "dc+sd-jwt" {
		t.Errorf("format: %s", cq.Format)
	}
	if cq.ID != "battery-check" {
		t.Errorf("id: %s", cq.ID)
	}
	if len(cq.Claims) != 2 {
		t.Errorf("expected 2 claims, got %d", len(cq.Claims))
	}
	if cq.Meta == nil || len(cq.Meta.VCTValues) != 1 {
		t.Error("SD-JWT VC should carry vct_values")
	}
}

func TestDCQLFromPresentationDefinitionMdoc(t *testing.T) {
	def := PresentationDefinition{Format: "mso-mdoc", RequiredClaims: []string{"x"}}
	q := DCQLFromPresentationDefinition(def)
	if q.Credentials[0].Format != "mso_mdoc" {
		t.Errorf("mdoc format: %s", q.Credentials[0].Format)
	}
	// mdoc should not have vct_values
	if q.Credentials[0].Meta != nil {
		t.Error("mdoc should not carry vct_values")
	}
}

func TestDCQLFromPresentationDefinitionDefaultID(t *testing.T) {
	def := PresentationDefinition{Format: "sd-jwt", RequiredClaims: []string{"x"}}
	q := DCQLFromPresentationDefinition(def)
	if q.Credentials[0].ID == "" {
		t.Error("empty def ID should get a default")
	}
}

func TestCredentialQueryMatchClaims(t *testing.T) {
	cq := CredentialQuery{
		ID:     "dpp",
		Format: "dc+sd-jwt",
		Claims: []ClaimQuery{
			{Path: []string{"batteryCategory"}, Values: []any{"EV", "industrial"}},
			{Path: []string{"carbonKgCO2ePerKWh"}},
		},
	}
	// All required claims present, value matches
	if !cq.MatchClaims(map[string]any{"batteryCategory": "EV", "carbonKgCO2ePerKWh": 12.5}) {
		t.Error("should match: EV + carbon present")
	}
	// Missing a required claim
	if cq.MatchClaims(map[string]any{"batteryCategory": "EV"}) {
		t.Error("should not match: carbon missing")
	}
	// Value not in allowed set
	if cq.MatchClaims(map[string]any{"batteryCategory": "consumer", "carbonKgCO2ePerKWh": 1}) {
		t.Error("should not match: consumer not in {EV,industrial}")
	}
}

// TestMatchClaimsCompositeValues exercises value matching where both the DCQL
// `values` entry and the disclosed claim are composite JSON (array/object). The
// previous `val == want` comparison panicked when both operands shared an
// uncomparable dynamic type ([]any / map[string]any); reflect.DeepEqual must
// instead match them structurally without panicking.
func TestMatchClaimsCompositeValues(t *testing.T) {
	cq := CredentialQuery{
		ID:     "c",
		Format: "dc+sd-jwt",
		Claims: []ClaimQuery{
			{Path: []string{"roles"}, Values: []any{[]any{"admin", "user"}}},
			{Path: []string{"meta"}, Values: []any{map[string]any{"k": "v"}}},
		},
	}
	// Matching composites must satisfy the query (no panic, structural equality).
	match := map[string]any{
		"roles": []any{"admin", "user"},
		"meta":  map[string]any{"k": "v"},
	}
	if !cq.MatchClaims(match) {
		t.Error("composite values should match structurally")
	}
	// A different array value must NOT match (and must not panic).
	noMatch := map[string]any{
		"roles": []any{"admin"},
		"meta":  map[string]any{"k": "v"},
	}
	if cq.MatchClaims(noMatch) {
		t.Error("differing composite value should not match")
	}
	// A disclosed composite against a scalar allowed-value must not panic, just
	// fail to match.
	scalarQ := CredentialQuery{
		ID: "s", Format: "dc+sd-jwt",
		Claims: []ClaimQuery{{Path: []string{"x"}, Values: []any{"scalar"}}},
	}
	if scalarQ.MatchClaims(map[string]any{"x": []any{"composite"}}) {
		t.Error("composite claim vs scalar allowed-value should not match")
	}
}

// TestMatchClaimsEmptyPathSkipped verifies that a claim with an empty Path is
// skipped (treated as a non-constraint) rather than failing the match.
func TestMatchClaimsEmptyPathSkipped(t *testing.T) {
	cq := CredentialQuery{
		ID:     "c",
		Format: "dc+sd-jwt",
		Claims: []ClaimQuery{
			{Path: nil},                       // empty path → skipped
			{Path: []string{"present_claim"}}, // real constraint
		},
	}
	if !cq.MatchClaims(map[string]any{"present_claim": "ok"}) {
		t.Error("empty-path claim should be skipped; match should succeed")
	}
}

func TestDCQLMarshalRoundTrip(t *testing.T) {
	q := DCQLQuery{
		Credentials: []CredentialQuery{{
			ID:     "dpp",
			Format: "dc+sd-jwt",
			Meta:   &CredentialQueryMeta{VCTValues: []string{"https://schema.europa.eu/dpp/sd-jwt-vc/v1"}},
			Claims: []ClaimQuery{{Path: []string{"carbonKgCO2ePerKWh"}}},
		}},
	}
	data, err := MarshalDCQL(q)
	if err != nil {
		t.Fatal(err)
	}
	// Wire format must use snake_case keys per spec
	s := string(data)
	if !strings.Contains(s, "dc+sd-jwt") || !strings.Contains(s, "vct_values") {
		t.Errorf("wire format wrong: %s", s)
	}
	parsed, err := ParseDCQL(data)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Credentials[0].ID != "dpp" {
		t.Errorf("round-trip id: %s", parsed.Credentials[0].ID)
	}
}

func TestParseDCQLInvalid(t *testing.T) {
	if _, err := ParseDCQL([]byte(`{not json`)); err == nil {
		t.Error("bad JSON should fail")
	}
	if _, err := ParseDCQL([]byte(`{"credentials":[]}`)); err == nil {
		t.Error("empty credentials should fail validation")
	}
}

func TestCreateRequestDCQL(t *testing.T) {
	v := NewVerifier("https://verifier.example", "https://verifier.example/cb", NewMemoryStore())
	q := DCQLQuery{Credentials: []CredentialQuery{{ID: "dpp", Format: "dc+sd-jwt"}}}
	url, state, err := v.CreateRequestDCQL(q)
	if err != nil {
		t.Fatal(err)
	}
	if url == "" || state == "" {
		t.Error("expected non-empty url and state")
	}
}

func TestCreateRequestDCQLInvalid(t *testing.T) {
	v := NewVerifier("https://verifier.example", "https://verifier.example/cb", NewMemoryStore())
	_, _, err := v.CreateRequestDCQL(DCQLQuery{})
	if err == nil {
		t.Error("invalid DCQL should fail CreateRequestDCQL")
	}
}

func TestAuthorizationRequestDCQLSerialization(t *testing.T) {
	// When DCQL is set, JSON must contain dcql_query (OID4VP v1.0 conformance).
	req := &AuthorizationRequest{
		ClientID:     "x",
		ResponseType: "vp_token",
		DCQLQuery:    &DCQLQuery{Credentials: []CredentialQuery{{ID: "a", Format: "dc+sd-jwt"}}},
	}
	data, _ := json.Marshal(req)
	if !strings.Contains(string(data), "dcql_query") {
		t.Error("should contain dcql_query")
	}
	// The dcql_query must carry the credential query
	if !strings.Contains(string(data), `"id":"a"`) {
		t.Error("dcql_query should serialize the credential query")
	}
}

// ============================================================================
// MatchClaims — nested path support (DCQL §6.3)
// ============================================================================

func TestMatchClaimsNestedPath(t *testing.T) {
	cq := CredentialQuery{
		ID:     "q",
		Format: "dc+sd-jwt",
		Claims: []ClaimQuery{
			{Path: []string{"address", "country"}},
			{Path: []string{"name"}},
		},
	}
	presented := map[string]any{
		"name": "Alice",
		"address": map[string]any{
			"country": "DE",
			"city":    "Berlin",
		},
	}
	if !cq.MatchClaims(presented) {
		t.Error("nested path should match")
	}
}

func TestMatchClaimsNestedPathMissing(t *testing.T) {
	cq := CredentialQuery{
		ID:     "q",
		Format: "dc+sd-jwt",
		Claims: []ClaimQuery{
			{Path: []string{"address", "country"}},
		},
	}
	// No nested "address" object → must not match.
	if cq.MatchClaims(map[string]any{"address": "flat string"}) {
		t.Error("flat value at intermediate path should not match nested query")
	}
	// Missing top-level key.
	if cq.MatchClaims(map[string]any{"name": "Bob"}) {
		t.Error("missing top-level key should not match")
	}
}

func TestMarshalDCQLInvalidQuery(t *testing.T) {
	// Empty credentials → Validate() should fail → MarshalDCQL returns error
	_, err := MarshalDCQL(DCQLQuery{})
	if err == nil {
		t.Error("MarshalDCQL(empty) should return error")
	}
}

func TestMatchClaimsNestedValues(t *testing.T) {
	cq := CredentialQuery{
		ID:     "q",
		Format: "dc+sd-jwt",
		Claims: []ClaimQuery{
			{Path: []string{"address", "country"}, Values: []any{"DE", "FR"}},
		},
	}
	match := map[string]any{"address": map[string]any{"country": "DE"}}
	noMatch := map[string]any{"address": map[string]any{"country": "US"}}
	if !cq.MatchClaims(match) {
		t.Error("country=DE should match Values=[DE,FR]")
	}
	if cq.MatchClaims(noMatch) {
		t.Error("country=US should not match Values=[DE,FR]")
	}
}

// ============================================================================
// DCQL end-to-end verification (OpenID4VP v1.0 §6) — wired into ProcessResponse
// ============================================================================

// dcqlQuery builds a single dc+sd-jwt credential query requiring the given claims,
// constrained to the default DPP vct.
func dcqlQuery(id string, claims ...string) DCQLQuery {
	cqs := make([]ClaimQuery, 0, len(claims))
	for _, c := range claims {
		cqs = append(cqs, ClaimQuery{Path: []string{c}})
	}
	return DCQLQuery{Credentials: []CredentialQuery{{
		ID:     id,
		Format: "dc+sd-jwt",
		Meta:   &CredentialQueryMeta{VCTValues: []string{compliance.VCTDigitalProductPassport}},
		Claims: cqs,
	}}}
}

// TestE2EDCQLFlow proves that a DCQL-only Authorization Request (no
// PresentationDefinition) can be completed end-to-end. Before TrustedIssuers +
// enforceDCQLConstraints were wired in, ProcessResponse returned "no acceptable
// issuers configured" for every DCQL flow, making the v1.0 query language unusable.
func TestE2EDCQLFlow(t *testing.T) {
	iss, err := compliance.NewIssuer("did:web:factory.blrcs.example")
	if err != nil {
		t.Fatal(err)
	}
	ver := NewVerifier("https://verify.blrcs.example", "https://verify.blrcs.example/cb", nil)
	ver.TrustedIssuers = map[string][]byte{iss.ID: iss.PublicKey()}

	q := dcqlQuery("dpp", "batteryCategory", "carbonKgCO2ePerKWh")
	reqURL, state, err := ver.CreateRequestDCQL(q)
	if err != nil {
		t.Fatal(err)
	}

	sd := map[string]any{
		"batteryCategory":    "ev",
		"carbonKgCO2ePerKWh": 48.5,
		"supplierName":       "SecretCobaltCorp",
	}
	presented := boundPresent(t, iss, reqURL, "battery-xyz", sd, nil,
		[]string{"batteryCategory", "carbonKgCO2ePerKWh"})

	vp, err := ver.ProcessResponse(&AuthorizationResponse{VPToken: presented, State: state})
	if err != nil {
		t.Fatalf("DCQL ProcessResponse: %v", err)
	}
	if vp.Issuer != iss.ID {
		t.Errorf("issuer: %s", vp.Issuer)
	}
	if _, ok := vp.Claims["batteryCategory"]; !ok {
		t.Error("required DCQL claim batteryCategory not disclosed")
	}
	if _, ok := vp.Claims["supplierName"]; ok {
		t.Error("undisclosed claim supplierName leaked")
	}
}

// TestDCQLFlowNoTrustAnchor confirms a DCQL request still fails closed when the
// verifier has no TrustedIssuers configured.
func TestDCQLFlowNoTrustAnchor(t *testing.T) {
	iss, _ := compliance.NewIssuer("did:web:factory.blrcs.example")
	ver := NewVerifier("https://verify.blrcs.example", "https://verify.blrcs.example/cb", nil)
	// TrustedIssuers intentionally left nil.
	q := dcqlQuery("dpp", "batteryCategory")
	reqURL, state, _ := ver.CreateRequestDCQL(q)
	presented := boundPresent(t, iss, reqURL, "s", map[string]any{"batteryCategory": "ev"}, nil,
		[]string{"batteryCategory"})
	_, err := ver.ProcessResponse(&AuthorizationResponse{VPToken: presented, State: state})
	if err == nil || !strings.Contains(err.Error(), "no acceptable issuers") {
		t.Fatalf("want no-acceptable-issuers error, got %v", err)
	}
}

// TestDCQLConstraintUnsatisfied confirms that a presentation missing a DCQL-required
// claim is rejected with ErrDCQLUnsatisfied (the constraint is now enforced, not
// merely transmitted).
func TestDCQLConstraintUnsatisfied(t *testing.T) {
	iss, _ := compliance.NewIssuer("did:web:factory.blrcs.example")
	ver := NewVerifier("https://verify.blrcs.example", "https://verify.blrcs.example/cb", nil)
	ver.TrustedIssuers = map[string][]byte{iss.ID: iss.PublicKey()}

	// Query requires two claims; holder discloses only one.
	q := dcqlQuery("dpp", "batteryCategory", "criticalClaim")
	reqURL, state, _ := ver.CreateRequestDCQL(q)
	sd := map[string]any{"batteryCategory": "ev", "criticalClaim": "secret"}
	presented := boundPresent(t, iss, reqURL, "s", sd, nil, []string{"batteryCategory"})
	_, err := ver.ProcessResponse(&AuthorizationResponse{VPToken: presented, State: state})
	if !errors.Is(err, ErrDCQLUnsatisfied) {
		t.Fatalf("want ErrDCQLUnsatisfied, got %v", err)
	}
}

// TestDCQLConstraintVCTMismatch confirms a credential whose vct is outside the
// query's vct_values does not satisfy the credential query.
func TestDCQLConstraintVCTMismatch(t *testing.T) {
	iss, _ := compliance.NewIssuer("did:web:factory.blrcs.example")
	ver := NewVerifier("https://verify.blrcs.example", "https://verify.blrcs.example/cb", nil)
	ver.TrustedIssuers = map[string][]byte{iss.ID: iss.PublicKey()}

	q := DCQLQuery{Credentials: []CredentialQuery{{
		ID:     "dpp",
		Format: "dc+sd-jwt",
		Meta:   &CredentialQueryMeta{VCTValues: []string{"https://example.com/some-other-vct"}},
		Claims: []ClaimQuery{{Path: []string{"batteryCategory"}}},
	}}}
	reqURL, state, _ := ver.CreateRequestDCQL(q)
	// boundPresent issues with the default DPP vct, which is not in the query's set.
	presented := boundPresent(t, iss, reqURL, "s", map[string]any{"batteryCategory": "ev"}, nil,
		[]string{"batteryCategory"})
	_, err := ver.ProcessResponse(&AuthorizationResponse{VPToken: presented, State: state})
	if !errors.Is(err, ErrDCQLUnsatisfied) {
		t.Fatalf("want ErrDCQLUnsatisfied for vct mismatch, got %v", err)
	}
}

// TestEnforceDCQLConstraintsValueMatch directly exercises the value-constraint and
// vct-gate branches of enforceDCQLConstraints.
func TestEnforceDCQLConstraintsValueMatch(t *testing.T) {
	q := &DCQLQuery{Credentials: []CredentialQuery{{
		ID:     "dpp",
		Format: "dc+sd-jwt",
		Claims: []ClaimQuery{{Path: []string{"batteryCategory"}, Values: []any{"ev"}}},
	}}}
	ok := &compliance.VerifiedClaims{VCT: compliance.VCTDigitalProductPassport, Claims: map[string]any{"batteryCategory": "ev"}}
	if err := enforceDCQLConstraints(q, ok); err != nil {
		t.Fatalf("matching value should satisfy: %v", err)
	}
	bad := &compliance.VerifiedClaims{VCT: compliance.VCTDigitalProductPassport, Claims: map[string]any{"batteryCategory": "industrial"}}
	if err := enforceDCQLConstraints(q, bad); !errors.Is(err, ErrDCQLUnsatisfied) {
		t.Fatalf("non-matching value should fail: %v", err)
	}
}

// ============================================================================
// credential_sets enforcement (OpenID4VP v1.0 §6.2)
// ============================================================================

// TestEnforceDCQLCredentialSets exercises the §6.2 combination constraints against
// a single presented credential that satisfies query "a" but not "b".
func TestEnforceDCQLCredentialSets(t *testing.T) {
	vc := &compliance.VerifiedClaims{
		VCT:    compliance.VCTDigitalProductPassport,
		Claims: map[string]any{"x": "1"},
	}
	base := []CredentialQuery{
		{ID: "a", Format: "dc+sd-jwt", Claims: []ClaimQuery{{Path: []string{"x"}}}},
		{ID: "b", Format: "dc+sd-jwt", Claims: []ClaimQuery{{Path: []string{"y"}}}},
	}

	cases := []struct {
		name    string
		sets    []CredentialSetQuery
		wantErr bool
	}{
		{"required option {a} satisfied", []CredentialSetQuery{{Options: [][]string{{"a"}}, Required: true}}, false},
		{"required option {b} unsatisfied", []CredentialSetQuery{{Options: [][]string{{"b"}}, Required: true}}, true},
		{"optional set {b} does not gate", []CredentialSetQuery{{Options: [][]string{{"b"}}, Required: false}}, false},
		{"alternative options {b} OR {a}", []CredentialSetQuery{{Options: [][]string{{"b"}, {"a"}}, Required: true}}, false},
		{"required multi-id option {a,b} unsatisfiable by one cred", []CredentialSetQuery{{Options: [][]string{{"a", "b"}}, Required: true}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			q := &DCQLQuery{Credentials: base, CredentialSets: c.sets}
			err := enforceDCQLConstraints(q, vc)
			if c.wantErr && !errors.Is(err, ErrDCQLUnsatisfied) {
				t.Fatalf("want ErrDCQLUnsatisfied, got %v", err)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("want satisfied, got %v", err)
			}
		})
	}
}

// TestCredentialSetRequiredDefault verifies the §6.2 default for `required` is true
// when the JSON member is absent, and that an explicit false is honored.
func TestCredentialSetRequiredDefault(t *testing.T) {
	absent := []byte(`{"credentials":[{"id":"a","format":"dc+sd-jwt"}],"credential_sets":[{"options":[["a"]]}]}`)
	q, err := ParseDCQL(absent)
	if err != nil {
		t.Fatal(err)
	}
	if !q.CredentialSets[0].Required {
		t.Error("absent `required` must default to true (§6.2)")
	}

	explicit := []byte(`{"credentials":[{"id":"a","format":"dc+sd-jwt"}],"credential_sets":[{"options":[["a"]],"required":false}]}`)
	q2, err := ParseDCQL(explicit)
	if err != nil {
		t.Fatal(err)
	}
	if q2.CredentialSets[0].Required {
		t.Error("explicit `required:false` must be honored")
	}
}

// ============================================================================
// Axis 85 — DCQL query complexity bounds (DoS hardening)
// ============================================================================

// TestDCQLTooManyCredentials verifies that a query exceeding dcqlMaxCredentials
// is rejected with ErrDCQLQueryTooComplex from Validate / ParseDCQL.
func TestDCQLTooManyCredentials(t *testing.T) {
	creds := make([]CredentialQuery, dcqlMaxCredentials+1)
	for i := range creds {
		creds[i] = CredentialQuery{ID: fmt.Sprintf("c%d", i), Format: "dc+sd-jwt"}
	}
	q := DCQLQuery{Credentials: creds}
	err := q.Validate()
	if !errors.Is(err, ErrDCQLQueryTooComplex) {
		t.Fatalf("want ErrDCQLQueryTooComplex for %d credentials, got %v",
			len(creds), err)
	}
}

// TestDCQLAtMaxCredentials verifies that exactly dcqlMaxCredentials credentials
// pass Validate (boundary: limit is inclusive).
func TestDCQLAtMaxCredentials(t *testing.T) {
	creds := make([]CredentialQuery, dcqlMaxCredentials)
	for i := range creds {
		creds[i] = CredentialQuery{ID: fmt.Sprintf("c%d", i), Format: "dc+sd-jwt"}
	}
	q := &DCQLQuery{Credentials: creds}
	if err := q.Validate(); err != nil {
		t.Fatalf("exactly %d credentials should pass: %v", dcqlMaxCredentials, err)
	}
}

// TestDCQLTooManyClaims verifies that a credential query with more than
// dcqlMaxClaims claim entries is rejected.
func TestDCQLTooManyClaims(t *testing.T) {
	q := DCQLQuery{Credentials: []CredentialQuery{
		makeCredQuery("x", dcqlMaxClaims+1, 1, 0),
	}}
	err := q.Validate()
	if !errors.Is(err, ErrDCQLQueryTooComplex) {
		t.Fatalf("want ErrDCQLQueryTooComplex for %d claims, got %v",
			dcqlMaxClaims+1, err)
	}
}

// TestDCQLPathTooDeep verifies that a ClaimQuery.Path exceeding dcqlMaxPathDepth
// is rejected.
func TestDCQLPathTooDeep(t *testing.T) {
	q := DCQLQuery{Credentials: []CredentialQuery{
		makeCredQuery("x", 1, dcqlMaxPathDepth+1, 0),
	}}
	err := q.Validate()
	if !errors.Is(err, ErrDCQLQueryTooComplex) {
		t.Fatalf("want ErrDCQLQueryTooComplex for path depth %d, got %v",
			dcqlMaxPathDepth+1, err)
	}
}

// TestDCQLTooManyValues verifies that a ClaimQuery with more than
// dcqlMaxValuesPerClaim allowed values is rejected.
func TestDCQLTooManyValues(t *testing.T) {
	q := DCQLQuery{Credentials: []CredentialQuery{
		makeCredQuery("x", 1, 1, dcqlMaxValuesPerClaim+1),
	}}
	err := q.Validate()
	if !errors.Is(err, ErrDCQLQueryTooComplex) {
		t.Fatalf("want ErrDCQLQueryTooComplex for %d values, got %v",
			dcqlMaxValuesPerClaim+1, err)
	}
}

// TestDCQLAtLimitsHappyPath verifies a query right at every limit passes.
func TestDCQLAtLimitsHappyPath(t *testing.T) {
	q := DCQLQuery{Credentials: []CredentialQuery{
		makeCredQuery("x", dcqlMaxClaims, dcqlMaxPathDepth, dcqlMaxValuesPerClaim),
	}}
	if err := q.Validate(); err != nil {
		t.Fatalf("query at all limits should pass Validate: %v", err)
	}
}

// TestParseDCQLRejectsTooComplex verifies ParseDCQL propagates ErrDCQLQueryTooComplex
// from Validate so the parse boundary is fully protected.
func TestParseDCQLRejectsTooComplex(t *testing.T) {
	// Build a JSON query exceeding the credentials limit.
	creds := make([]CredentialQuery, dcqlMaxCredentials+1)
	for i := range creds {
		creds[i] = CredentialQuery{ID: fmt.Sprintf("c%d", i), Format: "dc+sd-jwt"}
	}
	data, _ := json.Marshal(DCQLQuery{Credentials: creds})
	_, err := ParseDCQL(data)
	if !errors.Is(err, ErrDCQLQueryTooComplex) {
		t.Fatalf("ParseDCQL should reject oversized query: got %v", err)
	}
}
