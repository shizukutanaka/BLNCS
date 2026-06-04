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
	"time"

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
	_, state, _ := ver.CreateRequest(def)

	// Issue SD-JWT with required claims
	sdjwt, _, _ := iss.IssueSDJWT("dpp-battery-1", map[string]any{
		"category":     "battery/ev",
		"carbonKgCO2e": 3.2,
	}, nil, time.Hour)

	// Wallet POSTs form-encoded
	form := BuildResponseForm(&AuthorizationResponse{
		VPToken: sdjwt,
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
	_, state, _ := ver.CreateRequest(def)
	sdjwt, _, _ := iss.IssueSDJWT("s", map[string]any{"x": 1}, nil, time.Hour)

	payload, _ := json.Marshal(&AuthorizationResponse{VPToken: sdjwt, State: state})
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
	ts := httptest.NewServer(ver.CallbackHandler(nil))
	defer ts.Close()

	def := PresentationDefinition{
		ID: "cb-bad", RequiredClaims: []string{"missing"},
		AcceptableIssuers: map[string][]byte{iss.ID: iss.PublicKey()},
	}
	_, state, _ := ver.CreateRequest(def)
	sdjwt, _, _ := iss.IssueSDJWT("s", map[string]any{"other": 1}, nil, time.Hour)

	form := BuildResponseForm(&AuthorizationResponse{VPToken: sdjwt, State: state})
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
	if !strings.Contains(out["error"], "missing") {
		t.Errorf("error hint: %s", out["error"])
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
