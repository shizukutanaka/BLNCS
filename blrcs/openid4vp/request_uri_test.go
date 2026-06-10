package openid4vp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ============================================================================
// buildRequestByRefURL
// ============================================================================

func TestBuildRequestByRefURL(t *testing.T) {
	got := buildRequestByRefURL("did:web:verify.example", "https://verify.example/vp/request/abc")
	want := "openid4vp://authorize?client_id=did:web:verify.example&request_uri=https://verify.example/vp/request/abc"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// ============================================================================
// extractLastPathSegment
// ============================================================================

func TestExtractLastPathSegment(t *testing.T) {
	cases := []struct{ path, want string }{
		{"/a/b/c", "c"},
		{"/a/b/c/", "c"},
		{"state", "state"},
		{"/state", "state"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := extractLastPathSegment(tc.path); got != tc.want {
			t.Errorf("extractLastPathSegment(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// ============================================================================
// CreateRequestByRef
// ============================================================================

func TestCreateRequestByRef(t *testing.T) {
	ver, _ := setupFlow(t)
	def := PresentationDefinition{
		ID:             "pd-test",
		RequiredClaims: []string{"productId"},
	}
	reqURL, state, err := ver.CreateRequestByRef(def, "https://verify.example/vp/request")
	if err != nil {
		t.Fatal(err)
	}
	if state == "" {
		t.Error("state should not be empty")
	}
	if !strings.HasPrefix(reqURL, "openid4vp://authorize?") {
		t.Errorf("unexpected URL prefix: %q", reqURL)
	}
	if !strings.Contains(reqURL, "request_uri=") {
		t.Error("URL should contain request_uri parameter")
	}
	if !strings.Contains(reqURL, "client_id=") {
		t.Error("URL should contain client_id parameter")
	}
	// request_uri must end with the state token
	if !strings.HasSuffix(reqURL, "/"+state) {
		t.Errorf("request_uri should end with state %q: %q", state, reqURL)
	}
}

func TestCreateRequestByRefBaseURITrailingSlash(t *testing.T) {
	ver, _ := setupFlow(t)
	def := PresentationDefinition{ID: "pd-trail", RequiredClaims: []string{"productId"}}
	// base URI with trailing slash — should not produce double slash
	reqURL, state, err := ver.CreateRequestByRef(def, "https://verify.example/vp/request/")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(reqURL, "//"+state) {
		t.Errorf("double slash in request_uri: %q", reqURL)
	}
	if !strings.HasSuffix(reqURL, "/"+state) {
		t.Errorf("request_uri should end with /%s: %q", state, reqURL)
	}
}

// ============================================================================
// CreateRequestDCQLByRef
// ============================================================================

func TestCreateRequestDCQLByRef(t *testing.T) {
	ver, _ := setupFlow(t)
	query := DCQLQuery{
		Credentials: []CredentialQuery{{
			ID:     "cred0",
			Format: "vc+sd-jwt",
		}},
	}
	reqURL, state, err := ver.CreateRequestDCQLByRef(query, "https://verify.example/vp/req")
	if err != nil {
		t.Fatal(err)
	}
	if state == "" {
		t.Error("state should not be empty")
	}
	if !strings.Contains(reqURL, "request_uri=") {
		t.Error("URL should contain request_uri")
	}
	if !strings.HasSuffix(reqURL, "/"+state) {
		t.Errorf("request_uri should end with state %q: %q", state, reqURL)
	}
}

// ============================================================================
// RequestHandler — happy path
// ============================================================================

func TestRequestHandlerServesRequest(t *testing.T) {
	ver, _ := setupFlow(t)
	def := PresentationDefinition{
		ID:             "pd-handler",
		RequiredClaims: []string{"productId"},
	}
	_, state, err := ver.CreateRequestByRef(def, "https://verify.example/vp/request")
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(ver.RequestHandler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/vp/request/" + state)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("want 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "application/oauth-authz-req+jwt" {
		t.Errorf("unexpected Content-Type: %q", ct)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Error("want Cache-Control: no-store")
	}

	var req AuthorizationRequest
	if err := json.NewDecoder(resp.Body).Decode(&req); err != nil {
		t.Fatalf("body is not valid AuthorizationRequest JSON: %v", err)
	}
	if req.State != state {
		t.Errorf("state mismatch: got %q, want %q", req.State, state)
	}
}

// ============================================================================
// RequestHandler — not found (unknown state)
// ============================================================================

func TestRequestHandlerNotFound(t *testing.T) {
	ver, _ := setupFlow(t)
	ts := httptest.NewServer(ver.RequestHandler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/vp/request/no-such-state")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("want 404, got %d", resp.StatusCode)
	}
}

// ============================================================================
// RequestHandler — missing state (bare path)
// ============================================================================

func TestRequestHandlerMissingState(t *testing.T) {
	ver, _ := setupFlow(t)
	ts := httptest.NewServer(ver.RequestHandler())
	defer ts.Close()

	// Path ends with "/" so extractLastPathSegment returns ""
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("want 400, got %d", resp.StatusCode)
	}
}

// ============================================================================
// RequestHandler — method not allowed
// ============================================================================

func TestRequestHandlerMethodNotAllowed(t *testing.T) {
	ver, _ := setupFlow(t)
	ts := httptest.NewServer(ver.RequestHandler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/vp/request/state123", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("want 405, got %d", resp.StatusCode)
	}
}

// ============================================================================
// RequestHandler — request is re-fetchable (not consumed on GET)
// ============================================================================

func TestRequestHandlerIdempotent(t *testing.T) {
	ver, _ := setupFlow(t)
	def := PresentationDefinition{ID: "pd-idem", RequiredClaims: []string{"productId"}}
	_, state, err := ver.CreateRequestByRef(def, "https://verify.example/vp/request")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(ver.RequestHandler())
	defer ts.Close()

	path := ts.URL + "/vp/request/" + state
	for i := 0; i < 3; i++ {
		resp, err := http.Get(path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("fetch %d: want 200, got %d", i+1, resp.StatusCode)
		}
	}
}
