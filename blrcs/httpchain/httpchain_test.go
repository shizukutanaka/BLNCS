package httpchain

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"blrcs/telemetry"
)

// ============================================================================
// Empty chain
// ============================================================================

func TestEmptyChainPassesThrough(t *testing.T) {
	chain := New(telemetry.New(telemetry.NopRecorder{}))
	h := chain.Then(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	ts := httptest.NewServer(h)
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status: %d", resp.StatusCode)
	}
}

// ============================================================================
// Recovery middleware
// ============================================================================

func TestRecoveryCatchesPanic(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})
	chain := New(tel).WithRecovery()
	h := chain.Then(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	}))
	ts := httptest.NewServer(h)
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 500 {
		t.Errorf("status: %d", resp.StatusCode)
	}
	if tel.Counter("panic.recovered.total").Value() != 1 {
		t.Errorf("recovery counter not incremented")
	}
}

// ============================================================================
// W3C Trace Context
// ============================================================================

func TestTraceContextGeneratedWhenAbsent(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})
	var capturedTrace *TraceContextValues
	h := New(tel).WithTraceContext().Then(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedTrace = TraceFromContext(r.Context())
	}))
	ts := httptest.NewServer(h)
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if capturedTrace == nil {
		t.Fatal("trace context missing")
	}
	if len(capturedTrace.TraceID) != 32 {
		t.Errorf("traceID length: %d", len(capturedTrace.TraceID))
	}
	if len(capturedTrace.SpanID) != 16 {
		t.Errorf("spanID length: %d", len(capturedTrace.SpanID))
	}
	// Response header echoed
	tp := resp.Header.Get("traceparent")
	if !strings.HasPrefix(tp, "00-"+capturedTrace.TraceID) {
		t.Errorf("response traceparent: %s", tp)
	}
}

func TestTraceContextHonoredFromIncoming(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})
	var captured *TraceContextValues
	h := New(tel).WithTraceContext().Then(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = TraceFromContext(r.Context())
	}))
	ts := httptest.NewServer(h)
	defer ts.Close()

	const incomingTraceID = "0123456789abcdef0123456789abcdef"
	const incomingSpanID = "fedcba0987654321"
	req, _ := http.NewRequest("GET", ts.URL, nil)
	req.Header.Set("traceparent", "00-"+incomingTraceID+"-"+incomingSpanID+"-01")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if captured.TraceID != incomingTraceID {
		t.Errorf("traceID: %s want %s", captured.TraceID, incomingTraceID)
	}
	if captured.ParentSpanID != incomingSpanID {
		t.Errorf("parent spanID: %s want %s", captured.ParentSpanID, incomingSpanID)
	}
	// Server generates own spanID
	if captured.SpanID == incomingSpanID {
		t.Error("server should generate own spanID (not echo parent)")
	}
}

func TestTraceContextMalformedHeader(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})
	var captured *TraceContextValues
	h := New(tel).WithTraceContext().Then(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = TraceFromContext(r.Context())
	}))
	ts := httptest.NewServer(h)
	defer ts.Close()

	cases := []string{
		"",
		"bad",
		"99-aaaa-bbbb-01",         // unknown version
		"00-tooshort-tooshort-01", // bad lengths
	}
	for _, hdr := range cases {
		req, _ := http.NewRequest("GET", ts.URL, nil)
		if hdr != "" {
			req.Header.Set("traceparent", hdr)
		}
		resp, _ := http.DefaultClient.Do(req)
		resp.Body.Close()
		if captured == nil || len(captured.TraceID) != 32 {
			t.Errorf("malformed %q produced bad trace: %+v", hdr, captured)
		}
	}
}

// ============================================================================
// Request logging
// ============================================================================

func TestRequestLoggingCounters(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})
	chain := New(tel).WithRequestLogging()
	mux := http.NewServeMux()
	mux.Handle("/ok", chain.Then(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("hi"))
	})))
	mux.Handle("/error", chain.Then(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	})))
	mux.Handle("/notfound", chain.Then(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	})))
	ts := httptest.NewServer(mux)
	defer ts.Close()

	for _, path := range []string{"/ok", "/error", "/notfound"} {
		resp, _ := http.Get(ts.URL + path)
		resp.Body.Close()
	}

	if tel.Counter("http.status.2xx").Value() != 1 {
		t.Errorf("2xx: %d", tel.Counter("http.status.2xx").Value())
	}
	if tel.Counter("http.status.5xx").Value() != 1 {
		t.Errorf("5xx: %d", tel.Counter("http.status.5xx").Value())
	}
	if tel.Counter("http.status.4xx").Value() != 1 {
		t.Errorf("4xx: %d", tel.Counter("http.status.4xx").Value())
	}
	hist := tel.Histogram("http.request.duration_ms").Snapshot()
	if hist.Count != 3 {
		t.Errorf("duration histogram count: %d", hist.Count)
	}
}

// ============================================================================
// Auth middleware
// ============================================================================

func TestBearerAuthSuccess(t *testing.T) {
	tokens := map[string]string{"secret-token": "alice"}
	chain := New(telemetry.New(telemetry.NopRecorder{})).WithAuth(BearerAuth(tokens))
	var capturedPrincipal string
	h := chain.Then(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPrincipal = PrincipalFromContext(r.Context())
		w.WriteHeader(200)
	}))
	ts := httptest.NewServer(h)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL, nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status: %d", resp.StatusCode)
	}
	if capturedPrincipal != "alice" {
		t.Errorf("principal: %s", capturedPrincipal)
	}
}

func TestBearerAuthMissing(t *testing.T) {
	chain := New(telemetry.New(telemetry.NopRecorder{})).WithAuth(BearerAuth(map[string]string{}))
	h := chain.Then(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("inner handler should not run")
	}))
	ts := httptest.NewServer(h)
	defer ts.Close()
	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("status: %d", resp.StatusCode)
	}
}

func TestBearerAuthInvalidToken(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})
	chain := New(tel).WithAuth(BearerAuth(map[string]string{"good": "alice"}))
	h := chain.Then(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ts := httptest.NewServer(h)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL, nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("status: %d", resp.StatusCode)
	}
	if tel.Counter("http.auth.fail").Value() != 1 {
		t.Error("auth.fail counter not incremented")
	}
}

// ============================================================================
// CORS preflight
// ============================================================================

func TestCORSPreflight(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})
	chain := New(tel).WithCORS(CORSConfig{
		AllowedOrigins: []string{"https://app.example"},
		AllowedMethods: []string{"GET", "POST"},
		AllowedHeaders: []string{"X-Custom"},
	})
	h := chain.Then(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("preflight should not reach handler")
	}))
	ts := httptest.NewServer(h)
	defer ts.Close()

	req, _ := http.NewRequest("OPTIONS", ts.URL, nil)
	req.Header.Set("Origin", "https://app.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Errorf("preflight status: %d", resp.StatusCode)
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "https://app.example" {
		t.Errorf("origin header: %s", resp.Header.Get("Access-Control-Allow-Origin"))
	}
	if !strings.Contains(resp.Header.Get("Access-Control-Allow-Methods"), "POST") {
		t.Errorf("methods: %s", resp.Header.Get("Access-Control-Allow-Methods"))
	}
	if resp.Header.Get("Access-Control-Allow-Headers") != "X-Custom" {
		t.Errorf("headers: %s", resp.Header.Get("Access-Control-Allow-Headers"))
	}
}

func TestCORSDisallowedOrigin(t *testing.T) {
	chain := New(telemetry.New(telemetry.NopRecorder{})).WithCORS(CORSConfig{
		AllowedOrigins: []string{"https://allowed.example"},
	})
	called := atomic.Bool{}
	h := chain.Then(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
		w.WriteHeader(200)
	}))
	ts := httptest.NewServer(h)
	defer ts.Close()

	// Cross-origin GET (not preflight) — should pass to handler but no Allow header
	req, _ := http.NewRequest("GET", ts.URL, nil)
	req.Header.Set("Origin", "https://evil.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if !called.Load() {
		t.Error("non-preflight should reach handler")
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Error("disallowed origin should not get Allow header")
	}
}

// ============================================================================
// Composition order
// ============================================================================

func TestCompositionOrder(t *testing.T) {
	var order []string
	tel := telemetry.New(telemetry.NopRecorder{})
	chain := New(tel)
	chain.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "outer")
			next.ServeHTTP(w, r)
		})
	})
	chain.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "inner")
			next.ServeHTTP(w, r)
		})
	})
	h := chain.Then(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "handler")
	}))
	ts := httptest.NewServer(h)
	defer ts.Close()

	resp, _ := http.Get(ts.URL)
	resp.Body.Close()

	// First-added should be outer-most (executed first on entry, last on exit)
	expected := []string{"outer", "inner", "handler"}
	if len(order) != 3 {
		t.Fatalf("expected 3 calls, got %v", order)
	}
	for i := range expected {
		if order[i] != expected[i] {
			t.Errorf("at %d: got %s want %s", i, order[i], expected[i])
		}
	}
}

// ============================================================================
// Full chain integration
// ============================================================================

func TestFullChainIntegration(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})
	tokens := map[string]string{"abc": "alice"}

	var seenTraceID string
	var seenPrincipal string
	chain := New(tel).
		WithRecovery().
		WithTraceContext().
		WithRequestLogging().
		WithAuth(BearerAuth(tokens))

	h := chain.Then(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tc := TraceFromContext(r.Context())
		seenTraceID = tc.TraceID
		seenPrincipal = PrincipalFromContext(r.Context())
		w.WriteHeader(200)
	}))
	ts := httptest.NewServer(h)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL, nil)
	req.Header.Set("Authorization", "Bearer abc")
	req.Header.Set("traceparent", "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != 200 {
		t.Errorf("status: %d", resp.StatusCode)
	}
	if seenPrincipal != "alice" {
		t.Errorf("principal: %s", seenPrincipal)
	}
	if seenTraceID != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Errorf("traceID: %s", seenTraceID)
	}
}
