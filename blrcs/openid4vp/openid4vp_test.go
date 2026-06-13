package openid4vp

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// ============================================================================
// Coverage uplift: peekIssuer, HTTP handlers (body-too-large, CreateRequest
// error), CreateRequestDCQL, BuildCredentialOfferURL, wallet Present edge cases
// ============================================================================

func TestPeekIssuerEdgeCases(t *testing.T) {
	// Too few parts (no dot separator)
	if _, ok := peekIssuer("notajwt"); ok {
		t.Error("single part should fail")
	}
	// Bad base64 payload
	if _, ok := peekIssuer("header.!!!bad-base64.sig"); ok {
		t.Error("bad base64 payload should fail")
	}
	// Valid base64, invalid JSON
	bad := base64.RawURLEncoding.EncodeToString([]byte("not-json"))
	if _, ok := peekIssuer("header." + bad + ".sig"); ok {
		t.Error("invalid JSON payload should fail")
	}
	// Valid base64, valid JSON, but iss missing
	noIss := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"x"}`))
	if _, ok := peekIssuer("header." + noIss + ".sig"); ok {
		t.Error("JSON without iss should fail")
	}
	// With SD-JWT disclosure suffix (~ separator should be stripped first)
	withIss := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"did:web:test"}`))
	token := "header." + withIss + ".sig~disc1~disc2~"
	if gotIss, ok := peekIssuer(token); !ok || gotIss != "did:web:test" {
		t.Errorf("peekIssuer with disclosures: ok=%v iss=%q", ok, gotIss)
	}
}

func TestAuthorizeHandlerCreateRequestError(t *testing.T) {
	ver, _ := setupFlow(t)
	h := ver.AuthorizeHandler()
	// Empty definition triggers ErrDefinitionEmpty
	body, _ := json.Marshal(PresentationDefinition{ID: "empty"})
	req := httptest.NewRequest(http.MethodPost, "/openid4vp/authorize", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rr.Code)
	}
}

func TestAuthorizeHandlerBodyTooLarge(t *testing.T) {
	ver, _ := setupFlow(t)
	h := ver.AuthorizeHandler()
	big := bytes.Repeat([]byte("x"), (1<<20)+1)
	req := httptest.NewRequest(http.MethodPost, "/openid4vp/authorize", bytes.NewReader(big))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rr.Code)
	}
}

func TestCreateRequestDCQLBadClientID(t *testing.T) {
	ver := NewVerifier(" bad-client-id", "https://example.com/cb", nil)
	q := DCQLQuery{Credentials: []CredentialQuery{{ID: "c1", Format: "sd-jwt"}}}
	_, _, err := ver.CreateRequestDCQL(q)
	if err != ErrClientIDInvalid {
		t.Fatalf("want ErrClientIDInvalid, got %v", err)
	}
}

func TestCreateRequestDCQLInvalidQuery(t *testing.T) {
	ver, _ := setupFlow(t)
	// Empty credentials → Validate fails
	q := DCQLQuery{}
	_, _, err := ver.CreateRequestDCQL(q)
	if err == nil {
		t.Fatal("empty DCQL query should fail")
	}
}

func TestCreateRequestDCQLHappyPath(t *testing.T) {
	ver, _ := setupFlow(t)
	q := DCQLQuery{Credentials: []CredentialQuery{{ID: "c1", Format: "sd-jwt"}}}
	reqURL, state, err := ver.CreateRequestDCQL(q)
	if err != nil {
		t.Fatal(err)
	}
	if state == "" {
		t.Error("state should not be empty")
	}
	if !strings.HasPrefix(reqURL, "openid4vp://authorize?") {
		t.Errorf("bad URL: %s", reqURL)
	}
	u, _ := url.Parse(reqURL)
	if u.Query().Get("dcql_query") == "" {
		t.Error("dcql_query missing from URL")
	}
}

func TestBuildCredentialOfferURLMissingConfigIDs(t *testing.T) {
	_, err := BuildCredentialOfferURL(CredentialOffer{
		CredentialIssuer: "did:web:factory.example",
	})
	if err == nil {
		t.Error("missing credential_configuration_ids should fail")
	}
}

func TestWalletPresentMissingPD(t *testing.T) {
	w := NewMockWallet("did:web:holder.example")
	// A DCQL request URL (no presentation_definition)
	ver, _ := setupFlow(t)
	q := DCQLQuery{Credentials: []CredentialQuery{{ID: "c1", Format: "sd-jwt"}}}
	reqURL, _, _ := ver.CreateRequestDCQL(q)
	_, err := w.Present(reqURL)
	if err == nil {
		t.Error("wallet Present with DCQL URL (no PD) should fail")
	}
}

// ============================================================================
// Store.Save failure propagation + AcceptableDIDs auto-generation
// ============================================================================

// failSaveStore is a SessionStore whose Save always fails, to exercise the
// error-propagation path in CreateRequest / CreateRequestDCQL.
type failSaveStore struct{}

func (failSaveStore) Save(string, *AuthorizationRequest, time.Duration) error {
	return errSaveFailed
}
func (failSaveStore) Load(string) (*AuthorizationRequest, error) { return nil, ErrStateNotFound }
func (failSaveStore) Consume(string) error                       { return nil }

var errSaveFailed = &saveErr{}

type saveErr struct{}

func (*saveErr) Error() string { return "save failed" }

func TestCreateRequestStoreSaveError(t *testing.T) {
	ver := NewVerifier("https://verify.example", "https://verify.example/cb", failSaveStore{})
	def := PresentationDefinition{RequiredClaims: []string{"x"}}
	if _, _, err := ver.CreateRequest(def); err != errSaveFailed {
		t.Fatalf("want errSaveFailed, got %v", err)
	}
}

func TestCreateRequestDCQLStoreSaveError(t *testing.T) {
	ver := NewVerifier("https://verify.example", "https://verify.example/cb", failSaveStore{})
	q := DCQLQuery{Credentials: []CredentialQuery{{ID: "c1", Format: "sd-jwt"}}}
	if _, _, err := ver.CreateRequestDCQL(q); err != errSaveFailed {
		t.Fatalf("want errSaveFailed, got %v", err)
	}
}

// TestCreateRequestAutoGenAcceptableDIDs verifies that AcceptableDIDs is
// derived from AcceptableIssuers when the former is empty (wire-format
// population for the wallet's issuer matching).
func TestCreateRequestAutoGenAcceptableDIDs(t *testing.T) {
	ver, iss := setupFlow(t)
	def := PresentationDefinition{
		RequiredClaims:    []string{"x"},
		AcceptableIssuers: map[string][]byte{iss.ID: iss.PublicKey()},
		// AcceptableDIDs intentionally left empty → auto-generated.
	}
	reqURL, _, err := ver.CreateRequest(def)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(reqURL)
	pdJSON := u.Query().Get("presentation_definition")
	if !strings.Contains(pdJSON, iss.ID) {
		t.Errorf("AcceptableDIDs not auto-generated into wire PD: %s", pdJSON)
	}
}

// TestMockWalletPresentNoHolderKey covers wallet.go line 157-159: the else
// branch of `if w.HolderKey != nil` that calls compliance.Present (no KB-JWT).
func TestMockWalletPresentNoHolderKey(t *testing.T) {
	ver, iss := setupFlow(t)
	sdjwt, _, err := iss.IssueSDJWT("sub", map[string]any{"name": "Alice"}, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	def := PresentationDefinition{
		ID:             "pd-test",
		RequiredClaims: []string{"name"},
		AcceptableIssuers: map[string][]byte{
			iss.ID: iss.PublicKey(),
		},
	}
	reqURL, _, err := ver.CreateRequest(def)
	if err != nil {
		t.Fatal(err)
	}
	w := NewMockWallet("did:web:holder.example")
	w.Store(StoredCredential{
		ID:        "cred-no-kb",
		IssuerDID: iss.ID,
		IssuerPub: iss.PublicKey(),
		SDJWT:     sdjwt,
	})
	// HolderKey is nil → Present calls compliance.Present (no KB-JWT).
	resp, err := w.Present(reqURL)
	if err != nil {
		t.Fatalf("Present without HolderKey: %v", err)
	}
	if resp.VPToken == "" {
		t.Error("expected non-empty VPToken")
	}
}

// TestMockWalletPresentCompliancePresentError covers wallet.go lines 160-162:
// when compliance.Present returns an error (empty SDJWT → ErrSDJWTEmpty), the
// wallet must propagate the error.
func TestMockWalletPresentCompliancePresentError(t *testing.T) {
	ver, iss := setupFlow(t)
	def := PresentationDefinition{
		ID:             "pd-test",
		RequiredClaims: []string{"name"},
		AcceptableIssuers: map[string][]byte{
			iss.ID: iss.PublicKey(),
		},
	}
	reqURL, _, err := ver.CreateRequest(def)
	if err != nil {
		t.Fatal(err)
	}
	w := NewMockWallet("did:web:holder.example")
	// Empty SDJWT → compliance.Present returns ErrSDJWTEmpty.
	w.Store(StoredCredential{
		ID:        "bad-cred",
		IssuerDID: iss.ID,
		SDJWT:     "",
	})
	_, err = w.Present(reqURL)
	if err == nil {
		t.Error("Present with empty SDJWT should return error")
	}
}
