package compliance

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// Axis 145: nested / recursive / array-element disclosure, issuance + presentation
//
// The verifier learned all three RFC 9901 disclosure shapes in Axis 139, but
// issuance only ever emitted flat top-level ones. These tests drive the new
// issuance and path-addressed presentation through that SAME independently
// written verifier, so a passing round trip is evidence the issuer produces the
// shapes the spec defines — not merely shapes this file agrees with.
// ============================================================================

func nestedIssuer(t *testing.T) *Issuer {
	t.Helper()
	iss, err := NewIssuer("did:web:issuer.example")
	if err != nil {
		t.Fatal(err)
	}
	return iss
}

// verifyAll is the "reveal everything" baseline: it hands the verifier every
// disclosure the credential carries.
func verifyAll(t *testing.T, iss *Issuer, sdjwt string) *VerifiedClaims {
	t.Helper()
	paths, err := DisclosablePaths(sdjwt)
	if err != nil {
		t.Fatalf("DisclosablePaths: %v", err)
	}
	presented, err := PresentPaths(sdjwt, paths)
	if err != nil {
		t.Fatalf("PresentPaths(all): %v", err)
	}
	vc, err := VerifySDJWT(presented, iss.PublicKey())
	if err != nil {
		t.Fatalf("verify all-disclosed: %v", err)
	}
	return vc
}

// TestNestedObjectDisclosure proves a holder can reveal one member of a nested
// object without revealing its siblings — the capability flat issuance lacked.
func TestNestedObjectDisclosure(t *testing.T) {
	iss := nestedIssuer(t)
	sdjwt, _, err := iss.IssueSDJWTVC("DigitalProductPassport", "battery-1", nil, map[string]any{
		"address": map[string]any{
			"country": SD("JP"),
			"city":    SD("Osaka"),
			"planet":  "Earth", // always visible
		},
	}, time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	presented, err := PresentPaths(sdjwt, [][]any{{"address", "country"}})
	if err != nil {
		t.Fatalf("present: %v", err)
	}
	vc, err := VerifySDJWT(presented, iss.PublicKey())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	addr, ok := vc.Claims["address"].(map[string]any)
	if !ok {
		t.Fatalf("address missing: %+v", vc.Claims)
	}
	if addr["country"] != "JP" {
		t.Errorf("country should be disclosed, got %v", addr["country"])
	}
	if _, leaked := addr["city"]; leaked {
		t.Error("city was NOT disclosed but appeared in the resolved claims")
	}
	if addr["planet"] != "Earth" {
		t.Errorf("always-visible member should survive, got %v", addr["planet"])
	}
	// The `_sd` machinery must not leak into the resolved claims.
	if _, leaked := addr["_sd"]; leaked {
		t.Error("_sd leaked into resolved claims")
	}
}

// TestArrayElementDisclosure proves array elements are individually disclosable
// and that undisclosed ones vanish rather than becoming placeholders.
func TestArrayElementDisclosureIssuance(t *testing.T) {
	iss := nestedIssuer(t)
	sdjwt, _, err := iss.IssueSDJWTVC("DigitalProductPassport", "b", nil, map[string]any{
		"markets": []any{SD("JP"), SD("DE"), "public"},
	}, time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	presented, err := PresentPaths(sdjwt, [][]any{{"markets", 1}})
	if err != nil {
		t.Fatalf("present: %v", err)
	}
	vc, err := VerifySDJWT(presented, iss.PublicKey())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	markets, ok := vc.Claims["markets"].([]any)
	if !ok {
		t.Fatalf("markets missing: %+v", vc.Claims)
	}
	// DE (index 1) disclosed, JP (index 0) not, "public" always visible.
	if !reflect.DeepEqual(markets, []any{"DE", "public"}) {
		t.Fatalf("markets = %v, want [DE public]", markets)
	}
	for _, el := range markets {
		if m, isObj := el.(map[string]any); isObj {
			if _, isPlaceholder := m["..."]; isPlaceholder {
				t.Error("an undisclosed element leaked as a visible placeholder")
			}
		}
	}
}

// TestRecursiveDisclosure is RFC 9901's recursive shape: revealing a parent
// exposes nested DIGESTS, not nested values, so the child stays hidden until it
// too is revealed.
func TestRecursiveDisclosureIssuance(t *testing.T) {
	iss := nestedIssuer(t)
	sdjwt, _, err := iss.IssueSDJWTVC("DigitalProductPassport", "b", map[string]any{
		"supplier": map[string]any{
			"name":   SD("ACME"),
			"taxID":  SD("JP-123"),
			"public": "listed",
		},
	}, nil, time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Reveal only the parent: the nested members must stay hidden.
	parentOnly, err := PresentPaths(sdjwt, [][]any{{"supplier"}})
	if err != nil {
		t.Fatalf("present parent: %v", err)
	}
	vc, err := VerifySDJWT(parentOnly, iss.PublicKey())
	if err != nil {
		t.Fatalf("verify parent-only: %v", err)
	}
	sup, ok := vc.Claims["supplier"].(map[string]any)
	if !ok {
		t.Fatalf("supplier missing: %+v", vc.Claims)
	}
	if sup["public"] != "listed" {
		t.Errorf("always-visible nested member missing: %v", sup)
	}
	if _, leaked := sup["name"]; leaked {
		t.Error("nested name leaked when only the parent was revealed")
	}
	if _, leaked := sup["taxID"]; leaked {
		t.Error("nested taxID leaked when only the parent was revealed")
	}

	// Now reveal the nested name too — PresentPaths must pull in the parent.
	withChild, err := PresentPaths(sdjwt, [][]any{{"supplier", "name"}})
	if err != nil {
		t.Fatalf("present child: %v", err)
	}
	vc2, err := VerifySDJWT(withChild, iss.PublicKey())
	if err != nil {
		t.Fatalf("verify child (ancestor should be auto-included): %v", err)
	}
	sup2 := vc2.Claims["supplier"].(map[string]any)
	if sup2["name"] != "ACME" {
		t.Errorf("nested name should be disclosed, got %v", sup2["name"])
	}
	if _, leaked := sup2["taxID"]; leaked {
		t.Error("sibling taxID leaked")
	}
}

// TestPresentPathsOmittingAncestorWouldFail documents WHY ancestors are pulled
// in automatically: a nested disclosure without its parent is unusable, and RFC
// 9901 requires the verifier to reject the whole presentation.
func TestPresentPathsOmittingAncestorWouldFail(t *testing.T) {
	iss := nestedIssuer(t)
	sdjwt, _, err := iss.IssueSDJWTVC("DigitalProductPassport", "b", map[string]any{
		"supplier": map[string]any{"name": SD("ACME")},
	}, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Hand-build a presentation with ONLY the child disclosure, bypassing
	// PresentPaths, to show the verifier rejects it.
	segs := strings.Split(strings.TrimSuffix(sdjwt, "~"), "~")
	var child string
	for _, s := range segs[1:] {
		if d, err := parseDisclosures([]string{s}); err == nil {
			for _, pd := range d {
				if pd.name == "name" {
					child = s
				}
			}
		}
	}
	if child == "" {
		t.Fatal("could not locate the nested disclosure")
	}
	orphan := segs[0] + "~" + child + "~"
	if _, err := VerifySDJWT(orphan, iss.PublicKey()); !errors.Is(err, ErrDisclosureUnused) {
		t.Fatalf("an orphaned nested disclosure must be rejected as unused, got %v", err)
	}
	// And PresentPaths never produces that: it includes the ancestor.
	ok, err := PresentPaths(sdjwt, [][]any{{"supplier", "name"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySDJWT(ok, iss.PublicKey()); err != nil {
		t.Fatalf("PresentPaths output must verify: %v", err)
	}
}

// TestDeepNestingRoundTrip exercises several levels plus an array of objects.
func TestDeepNestingRoundTrip(t *testing.T) {
	iss := nestedIssuer(t)
	sdjwt, _, err := iss.IssueSDJWTVC("DigitalProductPassport", "b", nil, map[string]any{
		"battery": map[string]any{
			"cells": []any{
				map[string]any{"id": "c1", "cobaltPct": SD(12.0)},
				SD(map[string]any{"id": "c2", "cobaltPct": SD(30.0)}),
			},
			"chemistry": SD("LFP"),
		},
	}, time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Reveal the cobalt figure of the first (always-present) cell only.
	presented, err := PresentPaths(sdjwt, [][]any{{"battery", "cells", 0, "cobaltPct"}})
	if err != nil {
		t.Fatalf("present: %v", err)
	}
	vc, err := VerifySDJWT(presented, iss.PublicKey())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	bat := vc.Claims["battery"].(map[string]any)
	cells := bat["cells"].([]any)
	if len(cells) != 1 {
		t.Fatalf("the SD-marked second cell should be absent, got %d cells", len(cells))
	}
	c0 := cells[0].(map[string]any)
	if c0["cobaltPct"] != 12.0 {
		t.Errorf("cobaltPct should be disclosed, got %v", c0["cobaltPct"])
	}
	if _, leaked := bat["chemistry"]; leaked {
		t.Error("chemistry was not requested but leaked")
	}

	// Revealing everything must also verify and expose the nested cell.
	all := verifyAll(t, iss, sdjwt)
	allCells := all.Claims["battery"].(map[string]any)["cells"].([]any)
	if len(allCells) != 2 {
		t.Fatalf("all-disclosed should show both cells, got %d", len(allCells))
	}
	if allCells[1].(map[string]any)["cobaltPct"] != 30.0 {
		t.Errorf("nested cell's recursive claim missing: %v", allCells[1])
	}
}

// TestFlatIssuanceUnchanged is the back-compat guard: a claim tree with no SD()
// marker must behave exactly as before, including name-based Present().
func TestFlatIssuanceUnchanged(t *testing.T) {
	iss := nestedIssuer(t)
	sdjwt, discs, err := iss.IssueSDJWTVC("DigitalProductPassport", "b", map[string]any{
		"carbonKgCO2ePerKWh": 42.0,
		"cellChemistry":      "LFP",
	}, map[string]any{"batteryCategory": "ev"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(discs) != 2 {
		t.Fatalf("want 2 flat disclosures, got %d", len(discs))
	}
	for _, d := range discs {
		if d.Name == "" {
			t.Error("a flat disclosure must be the named 3-element shape")
		}
	}
	presented, err := Present(sdjwt, []string{"carbonKgCO2ePerKWh"})
	if err != nil {
		t.Fatal(err)
	}
	vc, err := VerifySDJWT(presented, iss.PublicKey())
	if err != nil {
		t.Fatalf("name-based Present must still verify: %v", err)
	}
	if vc.Claims["carbonKgCO2ePerKWh"] != 42.0 {
		t.Errorf("disclosed claim missing: %v", vc.Claims)
	}
	if _, leaked := vc.Claims["cellChemistry"]; leaked {
		t.Error("undisclosed claim leaked")
	}
	if vc.Claims["batteryCategory"] != "ev" {
		t.Error("clear claim missing")
	}
}

// TestNoDisclosableMembersNoSD: an object with nothing disclosable must not gain
// an `_sd` member — an empty or decoy-only `_sd` everywhere would be a
// fingerprint and pure noise.
func TestNoDisclosableMembersNoSD(t *testing.T) {
	iss := nestedIssuer(t)
	sdjwt, _, err := iss.IssueSDJWTVC("DigitalProductPassport", "b", nil, map[string]any{
		"address": map[string]any{"country": "JP", "city": "Osaka"},
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	payload := decodePayloadForTest(t, sdjwt)
	addr := payload["address"].(map[string]any)
	if _, has := addr["_sd"]; has {
		t.Error("an object with no disclosable members must not carry _sd")
	}
}

// TestDisclosableNameValidation: issuance must refuse names the verifier would
// reject at any depth, rather than minting a credential that can never verify.
func TestDisclosableNameValidation(t *testing.T) {
	iss := nestedIssuer(t)
	cases := map[string]map[string]any{
		"reserved claim nested": {"a": map[string]any{"iss": SD("evil")}},
		"reserved claim status": {"a": map[string]any{"status": SD("x")}},
		"structural _sd":        {"a": map[string]any{"_sd": SD("x")}},
		"structural ...":        {"a": map[string]any{"...": SD("x")}},
	}
	for name, clear := range cases {
		if _, _, err := iss.IssueSDJWTVC("DigitalProductPassport", "b", nil, clear, time.Hour); !errors.Is(err, ErrDisclosableName) {
			t.Errorf("%s: want ErrDisclosableName, got %v", name, err)
		}
	}
	// A literal `_sd` supplied by the caller is also refused.
	if _, _, err := iss.IssueSDJWTVC("DigitalProductPassport", "b", nil,
		map[string]any{"a": map[string]any{"_sd": []any{"x"}, "b": SD(1)}}, time.Hour); !errors.Is(err, ErrDisclosableName) {
		t.Errorf("a caller-supplied literal _sd must be refused, got %v", err)
	}
}

// TestMisplacedMarkerRejected: SD() at a claim root, or nested directly inside
// another SD(), has no disclosure shape and must be refused.
func TestMisplacedMarkerRejected(t *testing.T) {
	iss := nestedIssuer(t)
	// SD() as an entire clear-claim value: there is no container to redact it in.
	if _, _, err := iss.IssueSDJWTVC("DigitalProductPassport", "b", nil,
		map[string]any{"a": SD("x")}, time.Hour); !errors.Is(err, ErrDisclosableMisplaced) {
		t.Errorf("SD() at a claim root must be refused, got %v", err)
	}
	// SD(SD(x)) would silently collapse a level.
	if _, _, err := iss.IssueSDJWTVC("DigitalProductPassport", "b", nil,
		map[string]any{"a": map[string]any{"b": SD(SD("x"))}}, time.Hour); !errors.Is(err, ErrDisclosableMisplaced) {
		t.Errorf("SD(SD(x)) must be refused, got %v", err)
	}
}

// TestUnencodableValueRejected: a value JSON cannot encode previously produced
// an empty disclosure whose digest matched nothing — a signed credential that
// could never verify. It must be an error at issuance.
func TestUnencodableValueRejected(t *testing.T) {
	iss := nestedIssuer(t)
	ch := make(chan int)
	if _, _, err := iss.IssueSDJWTVC("DigitalProductPassport", "b",
		map[string]any{"bad": ch}, nil, time.Hour); !errors.Is(err, ErrDisclosableValue) {
		t.Errorf("an unencodable sd claim must be refused, got %v", err)
	}
	if _, _, err := iss.IssueSDJWTVC("DigitalProductPassport", "b", nil,
		map[string]any{"bad": ch}, time.Hour); !errors.Is(err, ErrDisclosableValue) {
		t.Errorf("an unencodable clear claim must be refused, got %v", err)
	}
	if _, _, err := iss.IssueSDJWTVC("DigitalProductPassport", "b", nil,
		map[string]any{"a": map[string]any{"bad": SD(ch)}}, time.Hour); !errors.Is(err, ErrDisclosableValue) {
		t.Errorf("an unencodable nested disclosure must be refused, got %v", err)
	}
}

// TestPresentPathsUnknownPath fails closed on a mistyped path instead of quietly
// presenting fewer claims than asked for.
func TestPresentPathsUnknownPath(t *testing.T) {
	iss := nestedIssuer(t)
	sdjwt, _, err := iss.IssueSDJWTVC("DigitalProductPassport", "b", nil,
		map[string]any{"address": map[string]any{"country": SD("JP"), "planet": "Earth"}}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]any{
		{"address", "postcode"}, // no such disclosable claim
		{"address"},             // the object itself is not disclosable here
		{"address", "planet"},   // always-visible, never a disclosure
		{"markets", 0},          // no such array
	} {
		if _, err := PresentPaths(sdjwt, [][]any{bad}); !errors.Is(err, ErrPresentPathUnknown) {
			t.Errorf("path %v: want ErrPresentPathUnknown, got %v", bad, err)
		}
	}
}

// TestDisclosablePathsEnumeration lists exactly the disclosable positions.
func TestDisclosablePathsEnumeration(t *testing.T) {
	iss := nestedIssuer(t)
	sdjwt, _, err := iss.IssueSDJWTVC("DigitalProductPassport", "b", nil, map[string]any{
		"address": map[string]any{"country": SD("JP"), "city": SD("Osaka"), "planet": "Earth"},
		"markets": []any{SD("JP"), "public"},
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := DisclosablePaths(sdjwt)
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string]bool, len(paths))
	for _, p := range paths {
		b, _ := json.Marshal(p)
		got[string(b)] = true
	}
	for _, want := range []string{`["address","city"]`, `["address","country"]`, `["markets",0]`} {
		if !got[want] {
			t.Errorf("missing disclosable path %s (got %v)", want, got)
		}
	}
	if len(paths) != 3 {
		t.Errorf("want exactly 3 disclosable paths, got %d: %v", len(paths), paths)
	}
}

// TestNestedDecoysApplied: with DecoyDigests set, a nested object carrying real
// disclosures also carries decoys, so its true disclosable-member count is
// hidden — but an array's length is never padded, because length is semantic.
func TestNestedDecoysApplied(t *testing.T) {
	iss := nestedIssuer(t)
	iss.DecoyDigests = 3
	sdjwt, _, err := iss.IssueSDJWTVC("DigitalProductPassport", "b", nil, map[string]any{
		"address": map[string]any{"country": SD("JP")},
		"markets": []any{SD("JP"), "public"},
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	payload := decodePayloadForTest(t, sdjwt)
	addrSD := payload["address"].(map[string]any)["_sd"].([]any)
	if len(addrSD) != 1+3 {
		t.Errorf("nested _sd should hold 1 real + 3 decoy digests, got %d", len(addrSD))
	}
	markets := payload["markets"].([]any)
	if len(markets) != 2 {
		t.Errorf("array length must not be padded with decoys, got %d", len(markets))
	}
	// It must still round-trip.
	verifyAll(t, iss, sdjwt)
}

// TestNestedDisclosuresAreDistinctShapes checks the wire shapes: an object
// member disclosure has 3 elements, an array element 2.
func TestNestedDisclosuresAreDistinctShapes(t *testing.T) {
	iss := nestedIssuer(t)
	sdjwt, _, err := iss.IssueSDJWTVC("DigitalProductPassport", "b", nil, map[string]any{
		"address": map[string]any{"country": SD("JP")},
		"markets": []any{SD("DE")},
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var sawObject, sawArray bool
	for _, seg := range strings.Split(strings.TrimSuffix(sdjwt, "~"), "~")[1:] {
		raw, err := b64DecodeForTest(seg)
		if err != nil {
			t.Fatal(err)
		}
		var arr []any
		if err := json.Unmarshal(raw, &arr); err != nil {
			t.Fatal(err)
		}
		switch len(arr) {
		case 2:
			sawArray = true
			if arr[1] != "DE" {
				t.Errorf("array disclosure value = %v", arr[1])
			}
		case 3:
			sawObject = true
			if arr[1] != "country" {
				t.Errorf("object disclosure name = %v", arr[1])
			}
		default:
			t.Errorf("disclosure with %d elements", len(arr))
		}
		// Salt must carry >= 128 bits (RFC 9901 §5.2.1).
		salt, _ := arr[0].(string)
		saltRaw, err := b64DecodeForTest(salt)
		if err != nil || len(saltRaw) < 16 {
			t.Errorf("salt too short or unparseable: %d bytes", len(saltRaw))
		}
	}
	if !sawObject || !sawArray {
		t.Errorf("expected both shapes, object=%v array=%v", sawObject, sawArray)
	}
}

// --- test helpers ---

func decodePayloadForTest(t *testing.T, sdjwt string) map[string]any {
	t.Helper()
	p, err := decodeJWTPayload(strings.SplitN(sdjwt, "~", 2)[0])
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func b64DecodeForTest(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// TestNestedPathPresentationWithES256KeyBinding is the combination a real EUDI
// wallet needs: a nested credential bound to a P-256 device key, presented by
// path with an ES256 KB-JWT. Nested claims are only addressable by path, and
// OpenID4VP requires key binding, so without this pairing Axis 145's disclosure
// shapes would be unusable in a live presentation flow.
func TestNestedPathPresentationWithES256KeyBinding(t *testing.T) {
	iss, err := NewES256Issuer("did:web:eudi-issuer.europa.eu")
	if err != nil {
		t.Fatal(err)
	}
	holderPriv, holderPub := p256Holder(t)

	sdjwt, _, err := iss.IssueSDJWTVCBound("DigitalProductPassport", "battery-EU-1", nil, map[string]any{
		"address": map[string]any{"country": SD("JP"), "city": SD("Osaka")},
		"markets": []any{SD("JP"), SD("DE")},
	}, holderPub, time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	const nonce, aud = "verifier-nonce", "did:web:verifier.europa.eu"
	presented, err := PresentPathsWithKeyBindingES256(sdjwt,
		[][]any{{"address", "country"}, {"markets", 1}}, holderPriv, nonce, aud, nil, time.Now())
	if err != nil {
		t.Fatalf("present with ES256 KB: %v", err)
	}
	vc, err := VerifySDJWTWithBinding(presented, iss.PublicKey(), VerifyOptions{
		RequireKeyBinding: true, ExpectedNonce: nonce, ExpectedAudience: aud,
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !vc.KeyBound {
		t.Error("presentation should be key-bound")
	}
	addr := vc.Claims["address"].(map[string]any)
	if addr["country"] != "JP" {
		t.Errorf("country should be disclosed: %v", addr)
	}
	if _, leaked := addr["city"]; leaked {
		t.Error("city leaked")
	}
	if got := vc.Claims["markets"].([]any); !reflect.DeepEqual(got, []any{"DE"}) {
		t.Errorf("markets = %v, want [DE]", got)
	}

	// The Ed25519 path-based variant must reject a P-256-only holder key shape.
	if _, err := PresentPathsWithKeyBinding(sdjwt, [][]any{{"address", "country"}},
		nil, nonce, aud, nil, time.Now()); err != ErrHolderKeyRequired {
		t.Errorf("a nil Ed25519 holder key must be refused, got %v", err)
	}
}
