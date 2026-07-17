package openapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ============================================================================
// Builder API
// ============================================================================

func TestNewSpec(t *testing.T) {
	s := New("MyAPI", "1.0", "Test API")
	if s.OpenAPI != "3.0.3" {
		t.Errorf("openapi version: %s", s.OpenAPI)
	}
	if s.Info.Title != "MyAPI" {
		t.Errorf("title: %s", s.Info.Title)
	}
	if s.Info.Version != "1.0" {
		t.Errorf("version: %s", s.Info.Version)
	}
}

func TestAddPathStoresOperation(t *testing.T) {
	s := New("X", "1", "")
	s.AddPath("/test", "GET", &Operation{
		Summary: "Test endpoint",
		Responses: map[string]*Response{
			"200": {Description: "OK"},
		},
	})
	if op, ok := s.Paths["/test"]["get"]; !ok {
		t.Fatal("path not stored")
	} else if op.Summary != "Test endpoint" {
		t.Errorf("summary: %s", op.Summary)
	}
}

func TestAddPathLowercasesMethod(t *testing.T) {
	s := New("X", "1", "")
	s.AddPath("/test", "POST", &Operation{
		Responses: map[string]*Response{"200": {Description: "OK"}},
	})
	if _, ok := s.Paths["/test"]["post"]; !ok {
		t.Error("POST should be lowered to 'post'")
	}
	// Original-case absent
	if _, ok := s.Paths["/test"]["POST"]; ok {
		t.Error("uppercase 'POST' should not be stored")
	}
}

func TestAddSchemaStored(t *testing.T) {
	s := New("X", "1", "")
	s.AddSchema("MySchema", &Schema{
		Type: "object",
		Properties: map[string]*Schema{
			"name": {Type: "string"},
		},
	})
	if _, ok := s.Components.Schemas["MySchema"]; !ok {
		t.Error("schema not stored")
	}
}

func TestAddBearerAuth(t *testing.T) {
	s := New("X", "1", "")
	s.AddBearerAuth("authA")
	scheme, ok := s.Components.SecuritySchemes["authA"]
	if !ok {
		t.Fatal("auth scheme missing")
	}
	if scheme.Type != "http" || scheme.Scheme != "bearer" {
		t.Errorf("scheme: %+v", scheme)
	}
}

func TestSetServer(t *testing.T) {
	s := New("X", "1", "")
	s.SetServer("https://api.example", "Prod")
	s.SetServer("https://staging.example", "Staging")
	if len(s.Servers) != 2 {
		t.Errorf("server count: %d", len(s.Servers))
	}
}

func TestSetContactAndLicense(t *testing.T) {
	s := New("X", "1", "")
	s.SetContact("Team", "https://example", "team@example")
	s.SetLicense("MIT", "https://opensource.org/licenses/MIT")

	if s.Info.Contact == nil || s.Info.Contact.Email != "team@example" {
		t.Error("contact not stored")
	}
	if s.Info.License == nil || s.Info.License.Name != "MIT" {
		t.Error("license not stored")
	}
}

// ============================================================================
// JSON output
// ============================================================================

func TestJSONOutput(t *testing.T) {
	s := New("MyAPI", "2.0", "Description here")
	s.AddPath("/items", "GET", &Operation{
		Summary: "List items",
		Responses: map[string]*Response{
			"200": {Description: "Items list"},
		},
	})
	body, err := s.JSON()
	if err != nil {
		t.Fatal(err)
	}
	out := string(body)
	expected := []string{
		`"openapi": "3.0.3"`,
		`"title": "MyAPI"`,
		`"version": "2.0"`,
		`"/items"`,
		`"summary": "List items"`,
	}
	for _, want := range expected {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in: %s", want, out)
		}
	}
}

func TestJSONIsValidParseable(t *testing.T) {
	s := New("X", "1", "")
	s.AddPath("/x", "GET", &Operation{
		Responses: map[string]*Response{"200": {Description: "OK"}},
	})
	body, _ := s.JSON()
	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if parsed["openapi"] != "3.0.3" {
		t.Errorf("parsed openapi: %v", parsed["openapi"])
	}
}

// ============================================================================
// HTTP Handler
// ============================================================================

func TestJSONHandlerServesSpec(t *testing.T) {
	s := New("API", "1", "")
	s.AddPath("/x", "GET", &Operation{
		Responses: map[string]*Response{"200": {Description: "OK"}},
	})
	ts := httptest.NewServer(s.JSONHandler())
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status: %d", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
		t.Errorf("content-type: %s", resp.Header.Get("Content-Type"))
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"openapi"`) {
		t.Errorf("body: %s", body)
	}
}

func TestJSONHandlerMethodRestriction(t *testing.T) {
	s := New("X", "1", "")
	ts := httptest.NewServer(s.JSONHandler())
	defer ts.Close()

	resp, err := http.Post(ts.URL, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status: %d", resp.StatusCode)
	}
}

// ============================================================================
// BLRCSDefault
// ============================================================================

func TestBLRCSDefaultIncludesAllExpectedEndpoints(t *testing.T) {
	s := BLRCSDefault("1.0.0")
	expected := []string{
		"/openid4vp/authorize",
		"/openid4vp/callback",
		"/.well-known/openid-credential-issuer",
		"/token",
		"/credential",
		"/healthz",
		"/readyz",
		"/metrics",
		"/.well-known/blrcs-capabilities.json",
		"/.well-known/privacy.json",
	}
	paths := s.SortedPaths()
	pathSet := make(map[string]bool, len(paths))
	for _, p := range paths {
		pathSet[p] = true
	}
	for _, want := range expected {
		if !pathSet[want] {
			t.Errorf("missing endpoint: %s", want)
		}
	}
}

func TestBLRCSDefaultHasReusableSchemas(t *testing.T) {
	s := BLRCSDefault("1.0.0")
	wantSchemas := []string{"Error", "PassportClaim", "PresentationDefinition"}
	for _, name := range wantSchemas {
		if _, ok := s.Components.Schemas[name]; !ok {
			t.Errorf("missing schema: %s", name)
		}
	}
}

func TestBLRCSDefaultHasBearerAuth(t *testing.T) {
	s := BLRCSDefault("1.0.0")
	if _, ok := s.Components.SecuritySchemes["bearerAuth"]; !ok {
		t.Error("missing bearerAuth scheme")
	}
}

func TestBLRCSDefaultCredentialEndpointRequiresAuth(t *testing.T) {
	s := BLRCSDefault("1.0.0")
	op, ok := s.Paths["/credential"]["post"]
	if !ok {
		t.Fatal("credential endpoint missing")
	}
	if len(op.Security) == 0 {
		t.Error("credential endpoint should require auth")
	}
}

func TestBLRCSDefaultJSONIsValid(t *testing.T) {
	s := BLRCSDefault("1.0.0")
	body, err := s.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatal(err)
	}
	// OpenAPI 3.0 必須トップレベルフィールド
	for _, key := range []string{"openapi", "info", "paths", "components"} {
		if _, ok := parsed[key]; !ok {
			t.Errorf("missing top-level field: %s", key)
		}
	}
}

// ============================================================================
// Concurrent access
// ============================================================================

func TestConcurrentAddPath(t *testing.T) {
	s := New("X", "1", "")
	done := make(chan struct{}, 100)
	for i := 0; i < 100; i++ {
		go func() {
			s.AddPath("/path"+string(rune('a'+i%26)), "GET", &Operation{
				Responses: map[string]*Response{"200": {Description: "OK"}},
			})
			done <- struct{}{}
		}()
	}
	for i := 0; i < 100; i++ {
		<-done
	}
	// JSON output should not race / panic
	body, err := s.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if len(body) == 0 {
		t.Error("empty JSON")
	}
}

// ============================================================================
// toLower edge cases
// ============================================================================

func TestToLower(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"GET", "get"},
		{"POST", "post"},
		{"DELETE", "delete"},
		{"PaTcH", "patch"},
		{"already-lower", "already-lower"},
		{"", ""},
	}
	for _, c := range cases {
		if got := toLower(c.in); got != c.want {
			t.Errorf("toLower(%q): got %q want %q", c.in, got, c.want)
		}
	}
}
