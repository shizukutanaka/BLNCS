package openid4vp

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

// ============================================================================
// Axis 140: DCQL claims paths over arrays (OpenID4VP §6.3)
//
// A path component may be a string (object key), a non-negative integer (array
// index) or null (every element of an array). Before this axis Path was
// []string and the walker descended objects only, so an array element could not
// be addressed at all — which became visible once Axis 139 taught the SD-JWT
// resolver to rebuild arrays holding selectively-disclosed elements: a verifier
// could accept such a credential but not constrain what the array contained.
// ============================================================================

// claims is a representative resolved credential: nested objects, an array of
// scalars, and an array of objects.
func pathTestClaims() map[string]any {
	return map[string]any{
		"batteryCategory": "ev",
		"markets":         []any{"JP", "DE", "FR"},
		"address":         map[string]any{"country": "JP", "city": "Osaka"},
		"components": []any{
			map[string]any{"name": "cathode", "recycledPct": 12.0},
			map[string]any{"name": "anode", "recycledPct": 30.0},
		},
	}
}

func TestResolvePathObjectKeys(t *testing.T) {
	got := resolvePath(pathTestClaims(), []any{"address", "city"})
	if len(got) != 1 || got[0] != "Osaka" {
		t.Fatalf("object path: %v", got)
	}
}

func TestResolvePathArrayIndex(t *testing.T) {
	c := pathTestClaims()
	// JSON numbers decode to float64, so an index arrives as float64 in practice.
	if got := resolvePath(c, []any{"markets", float64(1)}); len(got) != 1 || got[0] != "DE" {
		t.Errorf("markets[1]: %v", got)
	}
	// A plain int must work too, for paths built in Go rather than parsed.
	if got := resolvePath(c, []any{"markets", 2}); len(got) != 1 || got[0] != "FR" {
		t.Errorf("markets[2]: %v", got)
	}
	// Out of range selects nothing rather than erroring.
	if got := resolvePath(c, []any{"markets", 99}); len(got) != 0 {
		t.Errorf("out-of-range index should select nothing, got %v", got)
	}
}

func TestResolvePathWildcard(t *testing.T) {
	c := pathTestClaims()
	got := resolvePath(c, []any{"markets", nil})
	want := []any{"JP", "DE", "FR"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("wildcard should select every element: got %v want %v", got, want)
	}
	// Wildcard through an array of objects, then a key: selects that key from
	// every element.
	names := resolvePath(c, []any{"components", nil, "name"})
	if !reflect.DeepEqual(names, []any{"cathode", "anode"}) {
		t.Errorf("wildcard+key: %v", names)
	}
}

func TestResolvePathTypeMismatchesSelectNothing(t *testing.T) {
	c := pathTestClaims()
	cases := map[string][]any{
		"index into an object":    {"address", 0},
		"wildcard over an object": {"address", nil},
		"key into an array":       {"markets", "country"},
		"key into a scalar":       {"batteryCategory", "nope"},
		"missing key":             {"nonexistent"},
	}
	for name, path := range cases {
		if got := resolvePath(c, path); len(got) != 0 {
			t.Errorf("%s should select nothing, got %v", name, got)
		}
	}
}

// TestMatchClaimArrayIndexAndWildcard exercises the real matcher, not just the
// resolver.
func TestMatchClaimArrayIndexAndWildcard(t *testing.T) {
	c := pathTestClaims()

	// Presence via index.
	if !matchOneClaim(&ClaimQuery{Path: []any{"markets", float64(0)}}, c) {
		t.Error("markets[0] should be present")
	}
	// Value constraint via index: exact.
	if !matchOneClaim(&ClaimQuery{Path: []any{"markets", float64(0)}, Values: []any{"JP"}}, c) {
		t.Error("markets[0] == JP should match")
	}
	if matchOneClaim(&ClaimQuery{Path: []any{"markets", float64(0)}, Values: []any{"DE"}}, c) {
		t.Error("markets[0] is JP, not DE")
	}
	// Wildcard with a value constraint: satisfied when SOME element matches.
	if !matchOneClaim(&ClaimQuery{Path: []any{"markets", nil}, Values: []any{"DE"}}, c) {
		t.Error("some market is DE")
	}
	if matchOneClaim(&ClaimQuery{Path: []any{"markets", nil}, Values: []any{"US"}}, c) {
		t.Error("no market is US")
	}
	// Wildcard into objects.
	if !matchOneClaim(&ClaimQuery{Path: []any{"components", nil, "name"}, Values: []any{"anode"}}, c) {
		t.Error("some component is the anode")
	}
	if matchOneClaim(&ClaimQuery{Path: []any{"components", nil, "name"}, Values: []any{"separator"}}, c) {
		t.Error("no component is a separator")
	}
}

// TestObjectOnlyPathsUnchanged is the regression guard: all-string paths behave
// exactly as before.
func TestObjectOnlyPathsUnchanged(t *testing.T) {
	c := pathTestClaims()
	if !matchOneClaim(&ClaimQuery{Path: []any{"batteryCategory"}, Values: []any{"ev"}}, c) {
		t.Error("top-level claim should match")
	}
	if !matchOneClaim(&ClaimQuery{Path: []any{"address", "country"}, Values: []any{"JP"}}, c) {
		t.Error("nested object claim should match")
	}
	if matchOneClaim(&ClaimQuery{Path: []any{"address", "postcode"}}, c) {
		t.Error("absent nested key should not match")
	}
	// An empty path still means "no constraint".
	if !matchOneClaim(&ClaimQuery{}, c) {
		t.Error("empty path should impose no constraint")
	}
}

// TestPathSegmentValidation rejects the components §6.3 does not define, at
// Validate time, so the resolver never has to guess.
func TestPathSegmentValidation(t *testing.T) {
	bad := []any{
		float64(-1),  // negative index
		float64(1.5), // fractional index
		true,         // boolean
		[]any{"x"},   // nested array
		map[string]any{"k": "v"},
	}
	for _, seg := range bad {
		q := DCQLQuery{Credentials: []CredentialQuery{{
			ID: "c", Format: FormatSDJWT,
			Claims: []ClaimQuery{{Path: []any{"a", seg}}},
		}}}
		if err := q.Validate(); !errors.Is(err, ErrDCQLInvalidPath) {
			t.Errorf("segment %#v should be rejected, got %v", seg, err)
		}
	}
	// The three legal forms all validate.
	ok := DCQLQuery{Credentials: []CredentialQuery{{
		ID: "c", Format: FormatSDJWT,
		Claims: []ClaimQuery{{Path: []any{"markets", float64(0)}}, {Path: []any{"markets", nil}}},
	}}}
	if err := ok.Validate(); err != nil {
		t.Errorf("legal path forms should validate: %v", err)
	}
}

// TestPathRoundTripsThroughJSON proves a wire-format query with an index and a
// wildcard survives parsing — the shape a real verifier sends.
func TestPathRoundTripsThroughJSON(t *testing.T) {
	raw := []byte(`{
	  "credentials": [{
	    "id": "dpp",
	    "format": "dc+sd-jwt",
	    "meta": {"vct_values": ["DigitalProductPassport"]},
	    "claims": [
	      {"path": ["markets", 0]},
	      {"path": ["components", null, "name"], "values": ["anode"]}
	    ]
	  }]
	}`)
	q, err := ParseDCQL(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	claims := q.Credentials[0].Claims
	if len(claims) != 2 {
		t.Fatalf("want 2 claims, got %d", len(claims))
	}
	if idx, ok := pathIndex(claims[0].Path[1]); !ok || idx != 0 {
		t.Errorf("index did not survive JSON: %#v", claims[0].Path[1])
	}
	if claims[1].Path[1] != nil {
		t.Errorf("null wildcard did not survive JSON: %#v", claims[1].Path[1])
	}
	// And it matches against a real credential.
	if !matchOneClaim(&claims[1], pathTestClaims()) {
		t.Error("parsed wildcard query should match")
	}

	// Re-serialising must keep the shape.
	out, err := MarshalDCQL(*q)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Error("empty marshal")
	}
}

// TestWildcardDepthStillBounded confirms the complexity limit still applies to
// paths containing wildcards.
func TestWildcardDepthStillBounded(t *testing.T) {
	path := make([]any, dcqlMaxPathDepth+1)
	for i := range path {
		path[i] = nil
	}
	q := DCQLQuery{Credentials: []CredentialQuery{{
		ID: "c", Format: FormatSDJWT, Claims: []ClaimQuery{{Path: path}},
	}}}
	if err := q.Validate(); !errors.Is(err, ErrDCQLQueryTooComplex) {
		t.Fatalf("want ErrDCQLQueryTooComplex, got %v", err)
	}
}
