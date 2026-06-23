package openid4vp

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
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

// TestConcurrentReplayRejected guards the TOCTOU between Load and Consume: Load
// does not delete the one-time state, so without an atomic, return-checked
// Consume two simultaneous submissions of the SAME valid vp_token+state could
// both pass verification and both be accepted (a presentation double-spend). The
// nonce binding does not help — a replay carries the same valid nonce. Exactly
// one of N concurrent identical requests must succeed; the rest must be rejected.
// Run with -race to surface any residual data race on the store.
func TestConcurrentReplayRejected(t *testing.T) {
	ver, iss := setupFlow(t)
	def := PresentationDefinition{
		ID:                "x",
		RequiredClaims:    []string{"foo"},
		AcceptableIssuers: map[string][]byte{iss.ID: iss.PublicKey()},
	}
	reqURL, state, _ := ver.CreateRequest(def)
	presented := boundPresent(t, iss, reqURL, "s", map[string]any{"foo": "bar"}, nil, []string{"foo"})

	const n = 16
	var (
		wg        sync.WaitGroup
		start     = make(chan struct{})
		successes atomic.Int32
	)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // line everyone up so they race on the same state
			resp := &AuthorizationResponse{VPToken: presented, State: state}
			if _, err := ver.ProcessResponse(resp); err == nil {
				successes.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := successes.Load(); got != 1 {
		t.Fatalf("exactly one concurrent submission must be accepted, got %d", got)
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

// TestStaleKBJWTRejected verifies that a KB-JWT whose iat predates the session TTL
// is rejected — enforcing SD-JWT freshness (Axis 6: temporal integrity).
//
// A wallet that pre-generates KB-JWTs and caches them cannot replay them beyond
// the verifier's DefaultTTL window, even if it obtains the matching state token.
func TestStaleKBJWTRejected(t *testing.T) {
	ver, iss := setupFlow(t)
	def := PresentationDefinition{
		ID:             "fresh-check",
		RequiredClaims: []string{"foo"},
		AcceptableIssuers: map[string][]byte{
			iss.ID: iss.PublicKey(),
		},
	}
	reqURL, state, err := ver.CreateRequest(def)
	if err != nil {
		t.Fatal(err)
	}

	// Issue a holder-bound SD-JWT and generate a KB-JWT with an iat far in the past
	// (simulating a wallet that pre-generated or cached the presentation).
	holderPub, holderPriv, _ := ed25519.GenerateKey(rand.Reader)
	sdjwt, _, err := iss.IssueSDJWTBound("s", map[string]any{"foo": "bar"}, nil, holderPub, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(reqURL)
	q := u.Query()
	// KB-JWT iat = 30 minutes ago — well past the default 10-minute MaxKBAge.
	staleNow := time.Now().Add(-30 * time.Minute)
	presented, err := compliance.PresentWithKeyBinding(sdjwt, []string{"foo"}, holderPriv,
		q.Get("nonce"), q.Get("client_id"), staleNow)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ver.ProcessResponse(&AuthorizationResponse{VPToken: presented, State: state})
	if err == nil {
		t.Fatal("stale KB-JWT should be rejected")
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

// TestProcessResponseNoAcceptableIssuers covers the guard at
// openid4vp.go:339 that rejects sessions configured with no acceptable issuers.
func TestProcessResponseNoAcceptableIssuers(t *testing.T) {
	store := NewMemoryStore()
	ver := NewVerifier("https://verify.example", "https://verify.example/cb", store)
	// Inject a session with an empty AcceptableIssuers map directly into the store
	// so we bypass CreateRequest validation (which doesn't require AcceptableIssuers).
	state := "test-state-noissuer"
	req := &AuthorizationRequest{
		ClientID:    ver.ClientID,
		ResponseURI: ver.ResponseURI,
		Nonce:       "testnonce",
		State:       state,
		PresentationDefinition: PresentationDefinition{
			RequiredClaims:    []string{"x"},
			AcceptableIssuers: nil, // deliberately empty
		},
	}
	if err := store.Save(state, req, time.Minute); err != nil {
		t.Fatal(err)
	}
	_, err := ver.ProcessResponse(&AuthorizationResponse{
		State:   state,
		VPToken: "header.payload.sig", // non-empty but irrelevant; check comes first
	})
	if err == nil || err.Error() == "" {
		t.Fatalf("ProcessResponse with no AcceptableIssuers should fail, got %v", err)
	}
}

// ============================================================================
// Credential revocation (status_list) — exposed on result + optional fail-closed
// in-flow check (draft-ietf-oauth-status-list)
// ============================================================================

func TestProcessResponseRevocation(t *testing.T) {
	iss, err := compliance.NewIssuer("did:web:issuer.example")
	if err != nil {
		t.Fatal(err)
	}
	status := &compliance.StatusRef{URI: "https://status.example/list", Index: 7}
	sdjwt, _, err := iss.IssueSDJWTStatus("subj", map[string]any{"foo": "bar"}, nil, status, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pres, err := compliance.Present(sdjwt, []string{"foo"})
	if err != nil {
		t.Fatal(err)
	}
	def := PresentationDefinition{
		ID:                "x",
		RequiredClaims:    []string{"foo"},
		AcceptableIssuers: map[string][]byte{iss.ID: iss.PublicKey()},
	}
	// newVer returns a bearer-accepting verifier with a fresh session for `pres`.
	newVer := func() (*Verifier, string) {
		v := NewVerifier("https://verify.example", "https://verify.example/cb", nil)
		v.RequireKeyBinding = false // status credential here is a bearer SD-JWT
		_, state, cerr := v.CreateRequest(def)
		if cerr != nil {
			t.Fatal(cerr)
		}
		return v, state
	}

	// 1. No checker configured: verification succeeds and Status is exposed so the
	//    relying party can check revocation itself.
	v1, st1 := newVer()
	vp, err := v1.ProcessResponse(&AuthorizationResponse{VPToken: pres, State: st1})
	if err != nil {
		t.Fatalf("no-checker verify: %v", err)
	}
	if vp.Status == nil || vp.Status.Index != 7 || vp.Status.URI != status.URI {
		t.Fatalf("Status not exposed on result: %+v", vp.Status)
	}

	// 2. Checker reports revoked → ErrCredentialRevoked (fail-closed).
	v2, st2 := newVer()
	v2.RevocationChecker = func(s *compliance.StatusRef) (bool, error) {
		if s.Index != 7 {
			t.Errorf("checker got wrong status index: %d", s.Index)
		}
		return true, nil
	}
	if _, err := v2.ProcessResponse(&AuthorizationResponse{VPToken: pres, State: st2}); !errors.Is(err, ErrCredentialRevoked) {
		t.Fatalf("want ErrCredentialRevoked, got %v", err)
	}

	// 3. Checker error is propagated (not swallowed as "not revoked").
	v3, st3 := newVer()
	sentinel := errors.New("status list fetch failed")
	v3.RevocationChecker = func(_ *compliance.StatusRef) (bool, error) { return false, sentinel }
	if _, err := v3.ProcessResponse(&AuthorizationResponse{VPToken: pres, State: st3}); !errors.Is(err, sentinel) {
		t.Fatalf("want wrapped sentinel, got %v", err)
	}

	// 4. Checker NOT invoked for a credential without a status reference.
	plain, _, err := iss.IssueSDJWT("subj", map[string]any{"foo": "bar"}, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	plainPres, err := compliance.Present(plain, []string{"foo"})
	if err != nil {
		t.Fatal(err)
	}
	v4, st4 := newVer()
	v4.RevocationChecker = func(_ *compliance.StatusRef) (bool, error) {
		t.Error("RevocationChecker must not run for a credential without a status")
		return true, nil
	}
	vp4, err := v4.ProcessResponse(&AuthorizationResponse{VPToken: plainPres, State: st4})
	if err != nil {
		t.Fatalf("no-status verify: %v", err)
	}
	if vp4.Status != nil {
		t.Errorf("Status should be nil for a credential without a status reference: %+v", vp4.Status)
	}
}

// ============================================================================
// memoryStore — bounded session store tests
// ============================================================================

// TestMemoryStoreBoundedCap verifies that the store never exceeds its cap and
// returns an error when full and no expired entries exist to sweep.
func TestMemoryStoreBoundedCap(t *testing.T) {
	const cap = 5
	store := NewMemoryStoreWithCap(cap)
	req := &AuthorizationRequest{State: "x", Nonce: "n"}
	for i := range cap {
		state := "s" + string(rune('a'+i))
		if err := store.Save(state, req, time.Hour); err != nil {
			t.Fatalf("save %d failed: %v", i, err)
		}
	}
	if len(store.data) != cap {
		t.Fatalf("expected %d entries, got %d", cap, len(store.data))
	}
	// One more save must fail — all entries are still live.
	if err := store.Save("overflow", req, time.Hour); err == nil {
		t.Fatal("save beyond cap should fail when no expired entries exist")
	}
	if len(store.data) != cap {
		t.Fatalf("store grew past cap: %d", len(store.data))
	}
}

// TestMemoryStoreExpiredEntriesSweptBeforeError verifies that an expired entry
// is evicted during Save to make room, so a new entry is accepted instead of
// returning an error.
func TestMemoryStoreExpiredEntriesSweptBeforeError(t *testing.T) {
	const cap = 3
	store := NewMemoryStoreWithCap(cap)
	req := &AuthorizationRequest{State: "x", Nonce: "n"}
	// Fill to cap with entries that expire immediately.
	for i := range cap {
		state := "s" + string(rune('a'+i))
		if err := store.Save(state, req, -time.Second); err != nil {
			t.Fatalf("save %d failed: %v", i, err)
		}
	}
	// Force expiry.
	store.mu.Lock()
	now := time.Now()
	for _, e := range store.data {
		e.expires = now.Add(-2 * time.Second)
	}
	store.mu.Unlock()

	// A new save should succeed by sweeping one expired entry.
	if err := store.Save("new-live", req, time.Hour); err != nil {
		t.Fatalf("save should succeed after sweeping expired entry: %v", err)
	}
}

// TestNewMemoryStoreWithCapNonPositive verifies that cap ≤ 0 falls back to defaultMemStoreMax.
func TestNewMemoryStoreWithCapNonPositive(t *testing.T) {
	s := NewMemoryStoreWithCap(0)
	if s.maxSize != defaultMemStoreMax {
		t.Errorf("cap 0 should default to %d, got %d", defaultMemStoreMax, s.maxSize)
	}
	s2 := NewMemoryStoreWithCap(-1)
	if s2.maxSize != defaultMemStoreMax {
		t.Errorf("cap -1 should default to %d, got %d", defaultMemStoreMax, s2.maxSize)
	}
}

// ============================================================================
// MemoryStore.Close — goroutine lifecycle
// ============================================================================

// TestMemoryStoreCloseIdempotent verifies that calling Close twice does not panic.
// Before the fix, the gcLoop goroutine had no stop mechanism; the stop channel
// was introduced so Close terminates the background ticker goroutine exactly once.
func TestMemoryStoreCloseIdempotent(t *testing.T) {
	s := NewMemoryStore()
	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestMemoryStoreCloseStopsGC verifies that the stop channel is closed by
// Close(), making the select case in gcLoop unblock and return.
// We confirm by checking that the stop channel is closed after Close().
func TestMemoryStoreCloseStopsGC(t *testing.T) {
	s := NewMemoryStore()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// A closed channel returns the zero value immediately.
	select {
	case _, ok := <-s.stop:
		if ok {
			t.Error("stop channel should be closed (not readable)")
		}
	default:
		t.Error("stop channel should be closed; default branch means it's still open")
	}
}

// TestVerifierCloseStopsStore verifies that Verifier.Close forwards to the
// underlying MemoryStore's Close, stopping the GC goroutine.
func TestVerifierCloseStopsStore(t *testing.T) {
	ver := NewVerifier("https://v.example", "https://v.example/cb", nil)
	if err := ver.Close(); err != nil {
		t.Fatalf("Verifier.Close: %v", err)
	}
	// Calling again must not panic (idempotent).
	if err := ver.Close(); err != nil {
		t.Fatalf("second Verifier.Close: %v", err)
	}
}

// TestVerifierCloseWithExternalStore verifies that Verifier.Close is a no-op
// when the session store does not implement io.Closer (e.g. a custom KV store).
func TestVerifierCloseWithExternalStore(t *testing.T) {
	// stubStore satisfies SessionStore but not io.Closer.
	stub := &stubSessionStore{}
	ver := NewVerifier("https://v.example", "https://v.example/cb", stub)
	if err := ver.Close(); err != nil {
		t.Fatalf("Close with non-Closer store should return nil: %v", err)
	}
}

// TestMemoryStoreGCEvictsExpired verifies that GC() sweeps all expired entries
// in a single pass. This exercises the full-sweep path in gcLoop (which fires
// the ticker every 5 minutes — too long to wait in tests) directly via GC().
func TestMemoryStoreGCEvictsExpired(t *testing.T) {
	ms := NewMemoryStoreWithCap(100)
	defer ms.Close()

	req := &AuthorizationRequest{ClientID: "https://v.example", Nonce: "n1"}
	if err := ms.Save("live", req, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := ms.Save("expired", req, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	// Let the "expired" entry's TTL elapse.
	time.Sleep(5 * time.Millisecond)

	ms.GC()

	// Expired entry must be gone.
	if _, err := ms.Load("expired"); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("expired entry should be gone after GC, got: %v", err)
	}
	// Live entry must survive.
	if _, err := ms.Load("live"); err != nil {
		t.Fatalf("live entry should survive GC: %v", err)
	}
}

// TestMemoryStoreGCIdempotent verifies calling GC() when the store is empty
// or already clean does not panic or error.
func TestMemoryStoreGCIdempotent(t *testing.T) {
	ms := NewMemoryStoreWithCap(10)
	defer ms.Close()
	ms.GC() // empty store — must not panic
	req := &AuthorizationRequest{ClientID: "x"}
	if err := ms.Save("s", req, time.Hour); err != nil {
		t.Fatal(err)
	}
	ms.GC() // no expired entries — must not delete live entry
	if _, err := ms.Load("s"); err != nil {
		t.Fatalf("live entry removed by GC with no expiry: %v", err)
	}
}

type stubSessionStore struct{}

func (s *stubSessionStore) Save(_ string, _ *AuthorizationRequest, _ time.Duration) error {
	return nil
}
func (s *stubSessionStore) Load(_ string) (*AuthorizationRequest, error) { return nil, nil }
func (s *stubSessionStore) Consume(_ string) error                       { return nil }
