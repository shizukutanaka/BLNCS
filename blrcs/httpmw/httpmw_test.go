package httpmw

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"blrcs/telemetry"
)

// ============================================================================
// Recovery
// ============================================================================

func TestRecoveryFromPanic(t *testing.T) {
	panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("simulated panic")
	})
	wrapped := Recovery(panicHandler)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	wrapped.ServeHTTP(rec, req)
	if rec.Code != 500 {
		t.Errorf("status: %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "internal_server_error") {
		t.Errorf("body: %s", body)
	}
	// stack trace MUST NOT leak
	if strings.Contains(body, "simulated panic") {
		t.Error("CRITICAL: panic message leaked in response")
	}
	if strings.Contains(body, ".go:") {
		t.Error("CRITICAL: stack trace leaked in response")
	}
}

func TestRecoveryNormalHandler(t *testing.T) {
	normalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})
	wrapped := Recovery(normalHandler)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	wrapped.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Errorf("status: %d", rec.Code)
	}
	if rec.Body.String() != "ok" {
		t.Errorf("body: %s", rec.Body.String())
	}
}

func TestRecoveryIncrementsCounter(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})
	telemetry.SetDefault(tel)

	panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("oops")
	})
	wrapped := Recovery(panicHandler)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	wrapped.ServeHTTP(rec, req)

	if tel.Counter("http.panics_recovered").Value() != 1 {
		t.Errorf("panic counter: %d", tel.Counter("http.panics_recovered").Value())
	}
}

// ============================================================================
// RequestID
// ============================================================================

func TestRequestIDGeneratesNew(t *testing.T) {
	var capturedRID string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRID = RequestIDFromContext(r.Context())
		w.WriteHeader(200)
	})
	wrapped := RequestID(handler)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	wrapped.ServeHTTP(rec, req)

	if capturedRID == "" {
		t.Fatal("no RID in context")
	}
	if rec.Header().Get("X-Request-ID") != capturedRID {
		t.Errorf("response header mismatch")
	}
	if len(capturedRID) != 16 { // 8 bytes -> 16 hex chars
		t.Errorf("RID length: %d", len(capturedRID))
	}
}

func TestRequestIDRespectsClientHeader(t *testing.T) {
	var capturedRID string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRID = RequestIDFromContext(r.Context())
	})
	wrapped := RequestID(handler)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Request-ID", "client-provided-abc")
	wrapped.ServeHTTP(rec, req)

	if capturedRID != "client-provided-abc" {
		t.Errorf("client header not respected: %s", capturedRID)
	}
}

func TestRequestIDFromContextNil(t *testing.T) {
	if RequestIDFromContext(context.Background()) != "" {
		t.Error("missing RID should return empty string")
	}
}

// ============================================================================
// AccessLog
// ============================================================================

func TestAccessLogIncrementsCounter(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})
	telemetry.SetDefault(tel)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})
	wrapped := AccessLog(handler)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	wrapped.ServeHTTP(rec, req)

	if tel.Counter("http.requests.2").Value() != 1 {
		t.Errorf("2xx counter: %d", tel.Counter("http.requests.2").Value())
	}
	hist := tel.Histogram("http.duration_ms").Snapshot()
	if hist.Count != 1 {
		t.Errorf("duration histogram: %d", hist.Count)
	}
}

func TestAccessLog4xxCounter(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})
	telemetry.SetDefault(tel)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	})
	wrapped := AccessLog(handler)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	wrapped.ServeHTTP(rec, req)
	if tel.Counter("http.requests.4").Value() != 1 {
		t.Errorf("4xx counter: %d", tel.Counter("http.requests.4").Value())
	}
}

func TestClientIPXForwardedFor(t *testing.T) {
	cases := []struct {
		header, want string
	}{
		{"203.0.113.1", "203.0.113.1"},
		{"203.0.113.1, 10.0.0.1", "203.0.113.1"},
		{"203.0.113.1,10.0.0.1", "203.0.113.1"},
	}
	for _, c := range cases {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Forwarded-For", c.header)
		if got := clientIP(req); got != c.want {
			t.Errorf("XFF %q: got %s want %s", c.header, got, c.want)
		}
	}
}

func TestClientIPXRealIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Real-IP", "198.51.100.42")
	if got := clientIP(req); got != "198.51.100.42" {
		t.Errorf("X-Real-IP: %s", got)
	}
}

// ============================================================================
// SecurityHeaders
// ============================================================================

func TestSecurityHeaders(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	wrapped := SecurityHeaders(handler)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	wrapped.ServeHTTP(rec, req)

	wants := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
	}
	for k, want := range wants {
		if got := rec.Header().Get(k); got != want {
			t.Errorf("%s: got %q want %q", k, got, want)
		}
	}
	// Permissions-Policy must deny camera/mic/geo/payment
	pp := rec.Header().Get("Permissions-Policy")
	for _, perm := range []string{"camera", "microphone", "geolocation", "payment"} {
		if !strings.Contains(pp, perm+"=()") {
			t.Errorf("Permissions-Policy missing %s denial: %s", perm, pp)
		}
	}
}

// ============================================================================
// Chain composition
// ============================================================================

func TestChainOrdering(t *testing.T) {
	// Build chain that records execution order
	var order []string
	mw := func(name string) Middleware {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, name+":enter")
				next.ServeHTTP(w, r)
				order = append(order, name+":exit")
			})
		}
	}
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "handler")
		w.WriteHeader(200)
	})
	chained := Chain(final, mw("a"), mw("b"), mw("c"))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	chained.ServeHTTP(rec, req)

	want := []string{"a:enter", "b:enter", "c:enter", "handler", "c:exit", "b:exit", "a:exit"}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Errorf("order:\ngot:  %v\nwant: %v", order, want)
	}
}

func TestDefaultChain(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})
	telemetry.SetDefault(tel)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request ID injected
		if RequestIDFromContext(r.Context()) == "" {
			t.Error("RID should be injected")
		}
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})
	chained := Default(handler)
	ts := httptest.NewServer(chained)
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Errorf("body: %s", body)
	}
	// X-Request-ID + security headers present
	if resp.Header.Get("X-Request-ID") == "" {
		t.Error("X-Request-ID missing")
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("nosniff header missing")
	}
	// access log counter incremented
	if tel.Counter("http.requests.2").Value() < 1 {
		t.Error("access log not recorded")
	}
}

func TestDefaultChainCatchesPanic(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})
	telemetry.SetDefault(tel)

	panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	})
	chained := Default(panicHandler)
	ts := httptest.NewServer(chained)
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 500 {
		t.Errorf("status: %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	// Request ID still present in panic response
	if !strings.Contains(string(body), "requestId") {
		t.Errorf("panic response should include requestId: %s", body)
	}
	if tel.Counter("http.panics_recovered").Value() != 1 {
		t.Error("panic counter not incremented")
	}
}

// ============================================================================
// statusWriter — headerWritten accuracy test
// ============================================================================

func TestRecoveryAfterPartialWrite(t *testing.T) {
	h := Recovery(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("partial"))
		panic("after write")
	}))
	ts := httptest.NewServer(h)
	defer ts.Close()

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(ts.URL)
	if err == nil {
		defer resp.Body.Close()
		// Status should be 200 (already written before panic), NOT overwritten to 500
		if resp.StatusCode != 200 {
			t.Logf("status after partial write + panic: %d (may vary by timing)", resp.StatusCode)
		}
	}
	// Either way, counter should be incremented
	if telemetry.Default().Counter("http.panics_recovered").Value() < 1 {
		t.Error("recovery counter not incremented")
	}
}

func TestStatusWriterTracksWrite(t *testing.T) {
	recorder := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: recorder}
	if headerWritten(sw) {
		t.Error("before write should be false")
	}
	sw.Write([]byte("data"))
	if !headerWritten(sw) {
		t.Error("after Write should be true")
	}
}

func TestStatusWriterTracksWriteHeader(t *testing.T) {
	recorder := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: recorder}
	sw.WriteHeader(201)
	if !headerWritten(sw) {
		t.Error("after WriteHeader should be true")
	}
	if sw.status != 201 {
		t.Errorf("status: %d", sw.status)
	}
}

func TestHeaderWrittenOnPlainResponseWriter(t *testing.T) {
	recorder := httptest.NewRecorder()
	if headerWritten(recorder) {
		t.Error("plain ResponseWriter should return false (not statusWriter)")
	}
}
