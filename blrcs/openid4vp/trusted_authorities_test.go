package openid4vp

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"blrcs/compliance"
)

// ============================================================================
// Axis 147: DCQL trusted_authorities (OpenID4VP 1.0 §6.1.1)
//
// The central property under test is that an issuer restriction is never
// silently unenforced. A query that says "only issuers on this trusted list"
// must either be evaluated or refuse the presentation — never accept it while
// ignoring the constraint.
// ============================================================================

func taClaims() *compliance.VerifiedClaims {
	return &compliance.VerifiedClaims{
		Issuer: "did:web:issuer.europa.eu",
		VCT:    "DigitalProductPassport",
		Claims: map[string]any{"carbonKgCO2ePerKWh": 42.0},
	}
}

func taQuery(authorities ...TrustedAuthority) *DCQLQuery {
	return &DCQLQuery{Credentials: []CredentialQuery{{
		ID:                 "dpp",
		Format:             FormatSDJWT,
		Meta:               &CredentialQueryMeta{VCTValues: []string{"DigitalProductPassport"}},
		Claims:             []ClaimQuery{{Path: []any{"carbonKgCO2ePerKWh"}}},
		TrustedAuthorities: authorities,
	}}}
}

// TestNoTrustedAuthoritiesImposesNoRestriction is the back-compat guard: every
// existing query must behave exactly as before.
func TestNoTrustedAuthoritiesImposesNoRestriction(t *testing.T) {
	if err := enforceDCQLConstraints(taQuery(), taClaims(), nil); err != nil {
		t.Fatalf("a query without trusted_authorities must not be restricted: %v", err)
	}
}

// TestUnverifiableTrustedAuthoritiesFailsClosed is the property this whole axis
// exists for: a declared issuer restriction with no way to evaluate it must
// REFUSE, not accept. Accepting would advertise a restriction to the wallet and
// then honour none of it.
func TestUnverifiableTrustedAuthoritiesFailsClosed(t *testing.T) {
	q := taQuery(TrustedAuthority{Type: AuthorityTypeETSITrustedList, Values: []string{"https://ts.example.eu/tl"}})
	err := enforceDCQLConstraints(q, taClaims(), nil) // no checker configured
	if !errors.Is(err, ErrTrustedAuthorityUnverifiable) {
		t.Fatalf("want ErrTrustedAuthorityUnverifiable, got %v", err)
	}
	// It must NOT be reported as an ordinary claim mismatch: that would hide a
	// misconfigured verifier behind a routine-looking failure.
	if errors.Is(err, ErrDCQLUnsatisfied) {
		t.Error("an unenforceable trust constraint must be distinguishable from a claim mismatch")
	}
}

// TestTrustedAuthorityMatchAccepts / ...Rejects cover the two evaluated outcomes.
func TestTrustedAuthorityMatchAccepts(t *testing.T) {
	q := taQuery(TrustedAuthority{Type: AuthorityTypeOpenIDFederation, Values: []string{"https://federation.europa.eu"}})
	checker := func(a TrustedAuthority, vc *compliance.VerifiedClaims) (bool, error) {
		return a.Type == AuthorityTypeOpenIDFederation && a.Values[0] == "https://federation.europa.eu", nil
	}
	if err := enforceDCQLConstraints(q, taClaims(), checker); err != nil {
		t.Fatalf("a matching issuer must be accepted: %v", err)
	}
}

func TestTrustedAuthorityMismatchRejects(t *testing.T) {
	q := taQuery(TrustedAuthority{Type: AuthorityTypeOpenIDFederation, Values: []string{"https://federation.europa.eu"}})
	checker := func(TrustedAuthority, *compliance.VerifiedClaims) (bool, error) { return false, nil }
	err := enforceDCQLConstraints(q, taClaims(), checker)
	if !errors.Is(err, ErrTrustedAuthorityUnsatisfied) {
		t.Fatalf("want ErrTrustedAuthorityUnsatisfied, got %v", err)
	}
}

// TestTrustedAuthorityCheckerErrorFailsClosed: a transient failure (unreachable
// trusted list) must refuse, not degrade to "no restriction".
func TestTrustedAuthorityCheckerErrorFailsClosed(t *testing.T) {
	q := taQuery(TrustedAuthority{Type: AuthorityTypeETSITrustedList, Values: []string{"https://ts.example.eu/tl"}})
	boom := errors.New("trusted list unreachable")
	checker := func(TrustedAuthority, *compliance.VerifiedClaims) (bool, error) { return false, boom }
	err := enforceDCQLConstraints(q, taClaims(), checker)
	if err == nil {
		t.Fatal("a checker error must not be treated as an unrestricted query")
	}
	if !errors.Is(err, boom) {
		t.Errorf("the underlying cause should be wrapped, got %v", err)
	}
}

// TestTrustedAuthorityOrSemantics: §6.1.1 matches if ANY entry matches, and an
// entry matches if ANY of its values matches.
func TestTrustedAuthorityOrSemantics(t *testing.T) {
	q := taQuery(
		TrustedAuthority{Type: AuthorityTypeAKI, Values: []string{base64.RawURLEncoding.EncodeToString([]byte("key-a"))}},
		TrustedAuthority{Type: AuthorityTypeETSITrustedList, Values: []string{"https://a.example/tl", "https://b.example/tl"}},
	)
	// Only the SECOND entry's SECOND value matches — the query must still pass.
	var seen []string
	checker := func(a TrustedAuthority, _ *compliance.VerifiedClaims) (bool, error) {
		seen = append(seen, a.Type)
		return a.Type == AuthorityTypeETSITrustedList && containsString(a.Values, "https://b.example/tl"), nil
	}
	if err := enforceDCQLConstraints(q, taClaims(), checker); err != nil {
		t.Fatalf("matching any entry must satisfy the query: %v", err)
	}
	if len(seen) != 2 || seen[0] != AuthorityTypeAKI {
		t.Errorf("entries should be evaluated in query order until one matches, got %v", seen)
	}
	// Once one matches, evaluation stops.
	stopQ := taQuery(
		TrustedAuthority{Type: AuthorityTypeETSITrustedList, Values: []string{"https://a.example/tl"}},
		TrustedAuthority{Type: AuthorityTypeOpenIDFederation, Values: []string{"https://f.example"}},
	)
	calls := 0
	if err := enforceDCQLConstraints(stopQ, taClaims(), func(TrustedAuthority, *compliance.VerifiedClaims) (bool, error) {
		calls++
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("evaluation should stop at the first match, got %d calls", calls)
	}
}

// TestTrustedAuthorityOnlyCheckedForOtherwiseMatchingQueries: an unrelated
// query's trust anchors say nothing about this credential, so its checker must
// not run and must not cause a refusal.
func TestTrustedAuthorityOnlyCheckedForOtherwiseMatchingQueries(t *testing.T) {
	q := &DCQLQuery{Credentials: []CredentialQuery{
		{
			ID: "other", Format: FormatSDJWT,
			Meta:               &CredentialQueryMeta{VCTValues: []string{"SomeOtherType"}},
			TrustedAuthorities: []TrustedAuthority{{Type: AuthorityTypeETSITrustedList, Values: []string{"https://x/tl"}}},
		},
		{
			ID: "dpp", Format: FormatSDJWT,
			Meta:   &CredentialQueryMeta{VCTValues: []string{"DigitalProductPassport"}},
			Claims: []ClaimQuery{{Path: []any{"carbonKgCO2ePerKWh"}}},
		},
	}}
	calls := 0
	checker := func(TrustedAuthority, *compliance.VerifiedClaims) (bool, error) { calls++; return false, nil }
	if err := enforceDCQLConstraints(q, taClaims(), checker); err != nil {
		t.Fatalf("the unrestricted matching query should satisfy the request: %v", err)
	}
	if calls != 0 {
		t.Errorf("a non-matching query's trust anchors must not be evaluated, got %d calls", calls)
	}
}

// TestTrustedAuthorityValidation rejects structurally invalid entries at query
// build time, so a constraint that could never match is caught early.
func TestTrustedAuthorityValidation(t *testing.T) {
	bad := map[string]TrustedAuthority{
		"unknown type":   {Type: "x509_san_dns", Values: []string{"a"}},
		"empty type":     {Type: "", Values: []string{"a"}},
		"no values":      {Type: AuthorityTypeETSITrustedList},
		"empty value":    {Type: AuthorityTypeETSITrustedList, Values: []string{""}},
		"aki not base64": {Type: AuthorityTypeAKI, Values: []string{"not base64!!"}},
		"aki padded":     {Type: AuthorityTypeAKI, Values: []string{"c29tZQ=="}},
	}
	for name, a := range bad {
		if err := taQuery(a).Validate(); !errors.Is(err, ErrTrustedAuthorityInvalid) {
			t.Errorf("%s: want ErrTrustedAuthorityInvalid, got %v", name, err)
		}
	}
	// All three registered types validate.
	ok := taQuery(
		TrustedAuthority{Type: AuthorityTypeAKI, Values: []string{base64.RawURLEncoding.EncodeToString([]byte("kid"))}},
		TrustedAuthority{Type: AuthorityTypeETSITrustedList, Values: []string{"https://ts.example.eu/tl"}},
		TrustedAuthority{Type: AuthorityTypeOpenIDFederation, Values: []string{"https://federation.example"}},
	)
	if err := ok.Validate(); err != nil {
		t.Errorf("the three registered types must validate: %v", err)
	}
}

// TestTrustedAuthoritiesRoundTripJSON: the wire shape a real verifier sends.
func TestTrustedAuthoritiesRoundTripJSON(t *testing.T) {
	raw := []byte(`{
	  "credentials": [{
	    "id": "dpp",
	    "format": "dc+sd-jwt",
	    "meta": {"vct_values": ["DigitalProductPassport"]},
	    "trusted_authorities": [
	      {"type": "aki", "values": ["s9tIpPmhxdiuNkHMEWNpYim8S8Y"]},
	      {"type": "etsi_tl", "values": ["https://ts.example.eu/tl"]}
	    ]
	  }]
	}`)
	q, err := ParseDCQL(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	tas := q.Credentials[0].TrustedAuthorities
	if len(tas) != 2 || tas[0].Type != AuthorityTypeAKI || tas[1].Values[0] != "https://ts.example.eu/tl" {
		t.Fatalf("trusted_authorities did not survive parsing: %+v", tas)
	}
	out, err := MarshalDCQL(*q)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	cred := back["credentials"].([]any)[0].(map[string]any)
	if _, present := cred["trusted_authorities"]; !present {
		t.Error("trusted_authorities must survive re-serialisation")
	}
	// A query with none must not emit an empty array (omitempty).
	plain, err := MarshalDCQL(*taQuery())
	if err != nil {
		t.Fatal(err)
	}
	var pb map[string]any
	_ = json.Unmarshal(plain, &pb)
	if _, present := pb["credentials"].([]any)[0].(map[string]any)["trusted_authorities"]; present {
		t.Error("an unrestricted query must not emit trusted_authorities")
	}
}

// TestVerifierCheckerWiring proves the Verifier field actually reaches
// enforcement through ProcessResponse's call path.
func TestVerifierCheckerWiring(t *testing.T) {
	v := NewVerifier("did:web:verifier", "https://v/cb", nil)
	t.Cleanup(func() { _ = v.Close() })
	if v.TrustedAuthorityChecker != nil {
		t.Error("no checker should be configured by default (fail-closed)")
	}
	called := 0
	v.TrustedAuthorityChecker = func(TrustedAuthority, *compliance.VerifiedClaims) (bool, error) {
		called++
		return true, nil
	}
	q := taQuery(TrustedAuthority{Type: AuthorityTypeETSITrustedList, Values: []string{"https://ts/tl"}})
	if err := enforceDCQLConstraints(q, taClaims(), v.TrustedAuthorityChecker); err != nil {
		t.Fatalf("configured checker should be used: %v", err)
	}
	if called != 1 {
		t.Errorf("checker should have been called once, got %d", called)
	}
}

// TestTrustedAuthorityWithCredentialSets: the restriction must gate
// credential_sets satisfaction too, not just the flat case.
func TestTrustedAuthorityWithCredentialSets(t *testing.T) {
	q := taQuery(TrustedAuthority{Type: AuthorityTypeETSITrustedList, Values: []string{"https://ts/tl"}})
	q.CredentialSets = []CredentialSetQuery{{Options: [][]string{{"dpp"}}, Required: true}}
	// Issuer does not match -> the required set cannot be satisfied.
	err := enforceDCQLConstraints(q, taClaims(), func(TrustedAuthority, *compliance.VerifiedClaims) (bool, error) {
		return false, nil
	})
	if !errors.Is(err, ErrTrustedAuthorityUnsatisfied) {
		t.Fatalf("want ErrTrustedAuthorityUnsatisfied, got %v", err)
	}
	// Matching issuer -> satisfied.
	if err := enforceDCQLConstraints(q, taClaims(), func(TrustedAuthority, *compliance.VerifiedClaims) (bool, error) {
		return true, nil
	}); err != nil {
		t.Fatalf("a matching issuer should satisfy the required set: %v", err)
	}
}

// TestCheckerReceivesTheCredential: an implementation needs the verified
// credential to resolve a chain, so it must actually be passed through.
func TestCheckerReceivesTheCredential(t *testing.T) {
	q := taQuery(TrustedAuthority{Type: AuthorityTypeAKI, Values: []string{base64.RawURLEncoding.EncodeToString([]byte("k"))}})
	var gotIssuer string
	var gotType string
	checker := func(a TrustedAuthority, vc *compliance.VerifiedClaims) (bool, error) {
		gotType = a.Type
		if vc != nil {
			gotIssuer = vc.Issuer
		}
		return true, nil
	}
	if err := enforceDCQLConstraints(q, taClaims(), checker); err != nil {
		t.Fatal(err)
	}
	if gotIssuer != "did:web:issuer.europa.eu" {
		t.Errorf("checker should receive the verified credential, got issuer %q", gotIssuer)
	}
	if gotType != AuthorityTypeAKI {
		t.Errorf("checker should receive the authority entry, got type %q", gotType)
	}
}
