package openid4vp

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"blrcs/compliance"
)

// boundPresent issues a holder-bound SD-JWT and returns a KB-JWT presentation
// bound to the request's nonce + client_id (OpenID4VP anti-replay). Verifiers
// reject unbound presentations when a nonce/audience is expected, so e2e flows
// must use holder binding.
func boundPresent(t *testing.T, iss *compliance.Issuer, reqURL, subject string, sd, clear map[string]any, reveal []string) string {
	t.Helper()
	holderPub, holderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sdjwt, _, err := iss.IssueSDJWTBound(subject, sd, clear, holderPub, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(reqURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	presented, err := compliance.PresentWithKeyBinding(sdjwt, reveal, holderPriv, q.Get("nonce"), q.Get("client_id"), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	return presented
}

// ============================================================================
// Helper: end-to-end flow setup
// ============================================================================

func setupFlow(t *testing.T) (*Verifier, *compliance.Issuer) {
	t.Helper()
	iss, err := compliance.NewIssuer("did:web:factory.blrcs.example")
	if err != nil {
		t.Fatal(err)
	}
	ver := NewVerifier(
		"https://verify.blrcs.example",
		"https://verify.blrcs.example/openid4vp/callback",
		nil,
	)
	return ver, iss
}

// ============================================================================
// Authorization Request
// ============================================================================

func TestCreateRequestBasic(t *testing.T) {
	ver, iss := setupFlow(t)
	def := PresentationDefinition{
		ID:             "pd-battery-compliance",
		Purpose:        "Verify EU battery compliance",
		RequiredClaims: []string{"batteryCategory", "carbonKgCO2ePerKWh"},
		AcceptableIssuers: map[string][]byte{
			iss.ID: iss.PublicKey(),
		},
	}
	reqURL, state, err := ver.CreateRequest(def)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(reqURL, "openid4vp://authorize?") {
		t.Fatalf("bad URL prefix: %s", reqURL)
	}
	if state == "" {
		t.Fatal("state empty")
	}
	// Parse query to ensure structure
	u, err := url.Parse(reqURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("response_type") != "vp_token" {
		t.Errorf("response_type: %s", q.Get("response_type"))
	}
	if q.Get("client_id") != "https://verify.blrcs.example" {
		t.Errorf("client_id: %s", q.Get("client_id"))
	}
	if q.Get("state") != state {
		t.Errorf("state mismatch")
	}
	// presentation_definition JSON
	pdRaw := q.Get("presentation_definition")
	var pd PresentationDefinition
	if err := json.Unmarshal([]byte(pdRaw), &pd); err != nil {
		t.Fatalf("pd parse: %v", err)
	}
	if len(pd.RequiredClaims) != 2 {
		t.Errorf("required claims not preserved")
	}
}

func TestCreateRequestEmptyDefinition(t *testing.T) {
	ver, _ := setupFlow(t)
	_, _, err := ver.CreateRequest(PresentationDefinition{ID: "x"})
	if err != ErrDefinitionEmpty {
		t.Fatalf("want ErrDefinitionEmpty, got %v", err)
	}
}

// ============================================================================
// Process Response — E2E happy path
// ============================================================================

func TestE2EBatteryPassportFlow(t *testing.T) {
	ver, iss := setupFlow(t)

	// 1. Verifier creates request
	def := PresentationDefinition{
		ID:             "dpp-eu-battery",
		Purpose:        "EU Battery Passport Art.77 verification",
		RequiredClaims: []string{"batteryCategory", "chemistry", "capacityKWh", "carbonKgCO2ePerKWh"},
		AcceptableIssuers: map[string][]byte{
			iss.ID: iss.PublicKey(),
		},
	}
	reqURL, state, err := ver.CreateRequest(def)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Wallet side: issue a holder-bound SD-JWT containing ALL battery claims
	// (consumer chose to disclose these specific fields)
	sdClaims := map[string]any{
		"batteryCategory":    "ev",
		"chemistry":          "nmc",
		"capacityKWh":        75.0,
		"carbonKgCO2ePerKWh": 48.5,
		// Private fields NOT disclosed in this presentation:
		"supplierName":          "SecretCobaltCorp",
		"recycledContentCobalt": 16,
	}
	clearClaims := map[string]any{
		"productId": "EV-BAT-001",
	}
	// Holder discloses only the required ones, bound to the request nonce/client_id.
	presented := boundPresent(t, iss, reqURL, "battery-abc", sdClaims, clearClaims,
		[]string{"batteryCategory", "chemistry", "capacityKWh", "carbonKgCO2ePerKWh"})

	// 3. Verifier receives response
	resp := &AuthorizationResponse{
		VPToken: presented,
		State:   state,
	}
	vp, err := ver.ProcessResponse(resp)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if vp.Issuer != iss.ID {
		t.Errorf("issuer: %s", vp.Issuer)
	}
	if vp.Subject != "battery-abc" {
		t.Errorf("subject: %s", vp.Subject)
	}
	// Required claims must be disclosed
	for _, req := range []string{"batteryCategory", "chemistry", "capacityKWh", "carbonKgCO2ePerKWh"} {
		if _, ok := vp.Claims[req]; !ok {
			t.Errorf("required claim missing: %s", req)
		}
	}
	// Privacy-protected claims must NOT be disclosed
	if _, ok := vp.Claims["supplierName"]; ok {
		t.Error("supplierName leaked in presentation")
	}
	if _, ok := vp.Claims["recycledContentCobalt"]; ok {
		t.Error("recycled content leaked in presentation")
	}
	// Clear claims always present
	if vp.Claims["productId"] != "EV-BAT-001" {
		t.Errorf("productId: %v", vp.Claims["productId"])
	}
}

// ============================================================================
// Security: replay protection, missing claims, wrong issuer
// ============================================================================

func TestReplayRejected(t *testing.T) {
	ver, iss := setupFlow(t)
	def := PresentationDefinition{
		ID:             "x",
		RequiredClaims: []string{"foo"},
		AcceptableIssuers: map[string][]byte{
			iss.ID: iss.PublicKey(),
		},
	}
	reqURL, state, _ := ver.CreateRequest(def)
	presented := boundPresent(t, iss, reqURL, "s", map[string]any{"foo": "bar"}, nil, []string{"foo"})

	resp := &AuthorizationResponse{VPToken: presented, State: state}

	// First attempt succeeds
	if _, err := ver.ProcessResponse(resp); err != nil {
		t.Fatalf("first attempt: %v", err)
	}
	// Replay must fail (state consumed)
	if _, err := ver.ProcessResponse(resp); err != ErrStateNotFound {
		t.Fatalf("replay: want ErrStateNotFound, got %v", err)
	}
}

func TestMissingRequiredClaim(t *testing.T) {
	ver, iss := setupFlow(t)
	def := PresentationDefinition{
		ID:             "x",
		RequiredClaims: []string{"foo", "critical"},
		AcceptableIssuers: map[string][]byte{
			iss.ID: iss.PublicKey(),
		},
	}
	reqURL, state, _ := ver.CreateRequest(def)
	// Holder-bound SD-JWT discloses only "foo"; "critical" is not disclosed.
	presented := boundPresent(t, iss, reqURL, "s", map[string]any{"foo": "bar"}, nil, []string{"foo"})
	resp := &AuthorizationResponse{VPToken: presented, State: state}
	_, err := ver.ProcessResponse(resp)
	if !strings.Contains(err.Error(), "openid4vp: required claim not disclosed: critical") {
		t.Fatalf("want claim missing error, got %v", err)
	}
}

func TestUnknownIssuerRejected(t *testing.T) {
	ver, iss := setupFlow(t)
	evilIss, _ := compliance.NewIssuer("did:web:evil.example")
	def := PresentationDefinition{
		ID:             "x",
		RequiredClaims: []string{"foo"},
		AcceptableIssuers: map[string][]byte{
			iss.ID: iss.PublicKey(), // legitimate issuer only
		},
	}
	_, state, _ := ver.CreateRequest(def)
	// Evil issuer's SD-JWT
	sdjwt, _, _ := evilIss.IssueSDJWT("s", map[string]any{"foo": "bar"}, nil, time.Hour)
	resp := &AuthorizationResponse{VPToken: sdjwt, State: state}
	_, err := ver.ProcessResponse(resp)
	if err == nil {
		t.Fatal("evil issuer should be rejected")
	}
}

func TestUnknownState(t *testing.T) {
	ver, iss := setupFlow(t)
	sdjwt, _, _ := iss.IssueSDJWT("s", map[string]any{"foo": "bar"}, nil, time.Hour)
	resp := &AuthorizationResponse{VPToken: sdjwt, State: "never-issued"}
	if _, err := ver.ProcessResponse(resp); err != ErrStateNotFound {
		t.Fatalf("want ErrStateNotFound, got %v", err)
	}
}

func TestMissingVPToken(t *testing.T) {
	ver, _ := setupFlow(t)
	resp := &AuthorizationResponse{VPToken: "", State: "anything"}
	if _, err := ver.ProcessResponse(resp); err != ErrPresentationMissing {
		t.Fatalf("want ErrPresentationMissing, got %v", err)
	}
}

func TestSessionExpiry(t *testing.T) {
	ver, iss := setupFlow(t)
	ver.DefaultTTL = 50 * time.Millisecond
	def := PresentationDefinition{
		ID: "x", RequiredClaims: []string{"foo"},
		AcceptableIssuers: map[string][]byte{iss.ID: iss.PublicKey()},
	}
	_, state, _ := ver.CreateRequest(def)
	time.Sleep(100 * time.Millisecond)
	sdjwt, _, _ := iss.IssueSDJWT("s", map[string]any{"foo": "bar"}, nil, time.Hour)
	resp := &AuthorizationResponse{VPToken: sdjwt, State: state}
	if _, err := ver.ProcessResponse(resp); err != ErrStateNotFound {
		t.Fatalf("expired session should fail, got %v", err)
	}
}

// ============================================================================
// Form encoding / parsing (direct_post transport)
// ============================================================================

func TestResponseFormRoundTrip(t *testing.T) {
	r := &AuthorizationResponse{
		VPToken:                "some.sdjwt.token~d1~d2~",
		State:                  "state-abc-123",
		PresentationSubmission: []byte(`{"id":"x"}`),
	}
	form := BuildResponseForm(r)
	parsed, err := ParseResponseForm(form)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.VPToken != r.VPToken {
		t.Error("VPToken roundtrip")
	}
	if parsed.State != r.State {
		t.Error("State roundtrip")
	}
	if string(parsed.PresentationSubmission) != string(r.PresentationSubmission) {
		t.Error("PresentationSubmission roundtrip")
	}
}

func TestParseResponseFormMissingFields(t *testing.T) {
	if _, err := ParseResponseForm("foo=bar"); err == nil {
		t.Fatal("missing required fields should fail")
	}
	if _, err := ParseResponseForm("%%invalid%%"); err == nil {
		t.Fatal("malformed form should fail")
	}
}

func TestStripTrailingTilde(t *testing.T) {
	if got := StripTrailingTilde("jwt~disc1~disc2~"); got != "jwt~disc1~disc2" {
		t.Errorf("trailing tilde: %q", got)
	}
	if got := StripTrailingTilde("jwt~disc1~disc2"); got != "jwt~disc1~disc2" {
		t.Errorf("no trailing tilde: %q", got)
	}
	if got := StripTrailingTilde(""); got != "" {
		t.Errorf("empty string: %q", got)
	}
}
