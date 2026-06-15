package openid4vp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"blrcs/compliance"
)

func TestAuthorizeHandler(t *testing.T) {
	ver, iss := setupFlow(t)
	ts := httptest.NewServer(ver.AuthorizeHandler())
	defer ts.Close()

	def := PresentationDefinition{
		ID:             "pd-1",
		Purpose:        "EU DPP compliance check",
		RequiredClaims: []string{"category"},
		AcceptableIssuers: map[string][]byte{
			iss.ID: iss.PublicKey(),
		},
	}
	body, _ := json.Marshal(def)
	resp, err := http.Post(ts.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	var out map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out["requestURL"], "openid4vp://authorize?") {
		t.Errorf("bad URL: %s", out["requestURL"])
	}
	if out["state"] == "" {
		t.Error("state missing")
	}
}

func TestAuthorizeHandlerMethodReject(t *testing.T) {
	ver, _ := setupFlow(t)
	ts := httptest.NewServer(ver.AuthorizeHandler())
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 405 {
		t.Fatalf("want 405, got %d", resp.StatusCode)
	}
}

func TestAuthorizeHandlerBadJSON(t *testing.T) {
	ver, _ := setupFlow(t)
	ts := httptest.NewServer(ver.AuthorizeHandler())
	defer ts.Close()

	resp, err := http.Post(ts.URL, "application/json", strings.NewReader("{bad json"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("want 400, got %d", resp.StatusCode)
	}
}

// ============================================================================
// Callback handler — full E2E including form-encoded wallet POST
// ============================================================================

func TestCallbackHandlerFormPost(t *testing.T) {
	ver, iss := setupFlow(t)
	var triggered atomic.Int32
	ts := httptest.NewServer(ver.CallbackHandler(func(vp *VerifiedPresentation) {
		triggered.Add(1)
	}))
	defer ts.Close()

	// Create a valid session by calling CreateRequest directly
	def := PresentationDefinition{
		ID:             "cb-1",
		RequiredClaims: []string{"category", "carbonKgCO2e"},
		AcceptableIssuers: map[string][]byte{
			iss.ID: iss.PublicKey(),
		},
	}
	reqURL, state, _ := ver.CreateRequest(def)

	// Issue a holder-bound SD-JWT and present it bound to the request.
	presented := boundPresent(t, iss, reqURL, "dpp-battery-1", map[string]any{
		"category":     "battery/ev",
		"carbonKgCO2e": 3.2,
	}, nil, []string{"category", "carbonKgCO2e"})

	// Wallet POSTs form-encoded
	form := BuildResponseForm(&AuthorizationResponse{
		VPToken: presented,
		State:   state,
	})
	resp, err := http.Post(ts.URL, "application/x-www-form-urlencoded", strings.NewReader(form))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out["status"] != "success" {
		t.Fatalf("status: %v", out["status"])
	}
	if out["issuer"] != iss.ID {
		t.Errorf("issuer: %v", out["issuer"])
	}
	if triggered.Load() != 1 {
		t.Error("onSuccess not triggered")
	}
}

func TestCallbackHandlerJSONFallback(t *testing.T) {
	ver, iss := setupFlow(t)
	ts := httptest.NewServer(ver.CallbackHandler(nil))
	defer ts.Close()

	def := PresentationDefinition{
		ID: "cb-json", RequiredClaims: []string{"x"},
		AcceptableIssuers: map[string][]byte{iss.ID: iss.PublicKey()},
	}
	reqURL, state, _ := ver.CreateRequest(def)
	presented := boundPresent(t, iss, reqURL, "s", map[string]any{"x": 1}, nil, []string{"x"})

	payload, _ := json.Marshal(&AuthorizationResponse{VPToken: presented, State: state})
	resp, err := http.Post(ts.URL, "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("json fallback: %d", resp.StatusCode)
	}
}

func TestCallbackHandlerInvalidClaim(t *testing.T) {
	ver, iss := setupFlow(t)
	// The detailed error must reach the server-side hook, never the client.
	var serverErr error
	ver.OnVerifyError = func(e error) { serverErr = e }
	ts := httptest.NewServer(ver.CallbackHandler(nil))
	defer ts.Close()

	def := PresentationDefinition{
		ID: "cb-bad", RequiredClaims: []string{"missing"},
		AcceptableIssuers: map[string][]byte{iss.ID: iss.PublicKey()},
	}
	reqURL, state, _ := ver.CreateRequest(def)
	// Bound SD-JWT that does NOT contain the required "missing" claim.
	presented := boundPresent(t, iss, reqURL, "s", map[string]any{"other": 1}, nil, []string{"other"})

	form := BuildResponseForm(&AuthorizationResponse{VPToken: presented, State: state})
	resp, err := http.Post(ts.URL, "application/x-www-form-urlencoded", strings.NewReader(form))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("want 400, got %d", resp.StatusCode)
	}
	var out map[string]string
	json.NewDecoder(resp.Body).Decode(&out)
	if out["status"] != "failure" {
		t.Errorf("status: %s", out["status"])
	}
	// CWE-209: the client response must NOT reveal which check failed (no claim name).
	if strings.Contains(out["error"], "missing") || strings.Contains(out["error"], "claim") {
		t.Errorf("client error leaks internal detail: %s", out["error"])
	}
	if out["error"] != "presentation verification failed" {
		t.Errorf("expected generic client error, got: %s", out["error"])
	}
	// The detail is preserved server-side for logging/audit.
	if serverErr == nil || !strings.Contains(serverErr.Error(), "missing") {
		t.Errorf("OnVerifyError should receive the detailed error, got: %v", serverErr)
	}
}

func TestCallbackHandlerMethodReject(t *testing.T) {
	ver, _ := setupFlow(t)
	ts := httptest.NewServer(ver.CallbackHandler(nil))
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 405 {
		t.Fatalf("GET: want 405, got %d", resp.StatusCode)
	}
}

func TestCallbackHandlerBodyTooLarge(t *testing.T) {
	ver, _ := setupFlow(t)
	ts := httptest.NewServer(ver.CallbackHandler(nil))
	defer ts.Close()

	// Body just over 4 MiB — triggers http.MaxBytesReader in CallbackHandler.
	bigBody := strings.Repeat("A", (4<<20)+1)
	resp, err := http.Post(ts.URL, "application/x-www-form-urlencoded", strings.NewReader(bigBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("body too large: want 400, got %d", resp.StatusCode)
	}
}

// TestCallbackHandlerMalformedJSON exercises the parse-error branch when the
// body is invalid JSON under a JSON content-type.
func TestCallbackHandlerMalformedJSON(t *testing.T) {
	ver, _ := setupFlow(t)
	ts := httptest.NewServer(ver.CallbackHandler(nil))
	defer ts.Close()

	resp, err := http.Post(ts.URL, "application/json", strings.NewReader("{not valid json"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed JSON: want 400, got %d", resp.StatusCode)
	}
	var out map[string]string
	json.NewDecoder(resp.Body).Decode(&out)
	if !strings.Contains(out["error"], "parse") {
		t.Errorf("expected parse error hint, got: %s", out["error"])
	}
}

// ============================================================================
// Public-key helper (base64) — for caller convenience
// ============================================================================

func TestEncodePublicKey(t *testing.T) {
	iss, _ := compliance.NewIssuer("did:web:test")
	b64 := base64.RawURLEncoding.EncodeToString(iss.PublicKey())
	if len(b64) < 40 {
		t.Error("public key encoding too short")
	}
}
