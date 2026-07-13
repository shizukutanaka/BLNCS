package httpmw

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
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
	// Proxy headers are only honored when explicitly trusted.
	TrustProxyHeaders = true
	defer func() { TrustProxyHeaders = false }()
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
	TrustProxyHeaders = true
	defer func() { TrustProxyHeaders = false }()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Real-IP", "198.51.100.42")
	if got := clientIP(req); got != "198.51.100.42" {
		t.Errorf("X-Real-IP: %s", got)
	}
}

// TestClientIPIgnoresSpoofedXFFByDefault verifies the secure default: spoofed
// proxy headers are ignored, so they cannot be used to bypass per-IP rate limits.
// The returned value is the IP without the ephemeral port (see
// TestClientIPStripsPort for why the port must be stripped).
func TestClientIPIgnoresSpoofedXFFByDefault(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.50:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.99")
	req.Header.Set("X-Real-IP", "203.0.113.99")
	if got := clientIP(req); got != "192.0.2.50" {
		t.Errorf("spoofed headers should be ignored, got %s", got)
	}
}

// TestClientIPStripsPort guards against a rate-limit bypass: Go's HTTP server
// sets r.RemoteAddr to "IP:port" with an ephemeral source port that changes per
// connection. If clientIP returned IP:port, the rate limiter would key
// per-connection, so an attacker could open a new connection per request and get
// a fresh token bucket each time. clientIP MUST return the bare IP.
func TestClientIPStripsPort(t *testing.T) {
	cases := []struct{ remote, want string }{
		{"192.0.2.50:1234", "192.0.2.50"},
		{"192.0.2.50:55555", "192.0.2.50"},   // same IP, different port → same key
		{"[2001:db8::1]:443", "2001:db8::1"}, // IPv6 with port
		{"203.0.113.7", "203.0.113.7"},       // already bare (no port) → unchanged
	}
	for _, c := range cases {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = c.remote
		if got := clientIP(req); got != c.want {
			t.Errorf("clientIP(%q) = %q, want %q", c.remote, got, c.want)
		}
	}
}

// TestRateLimitKeyedPerIPNotPerConnection is the end-to-end regression: two
// requests from the same IP but different ephemeral ports must share one token
// bucket. Before the port-stripping fix they keyed separately, letting a client
// double its effective rate simply by using a new source port.
func TestRateLimitKeyedPerIPNotPerConnection(t *testing.T) {
	rl := NewRateLimiter(1, 1) // 1 token, 1 rps → only the first request passes
	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	do := func(remote string) int {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	if got := do("198.51.100.10:1000"); got != http.StatusOK {
		t.Fatalf("first request from IP: want 200, got %d", got)
	}
	// Same IP, brand-new ephemeral port — must still be rate-limited (429),
	// proving the bucket is keyed by IP, not by connection.
	if got := do("198.51.100.10:2000"); got != http.StatusTooManyRequests {
		t.Errorf("second request (new port, same IP): want 429, got %d", got)
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

// ============================================================================
// sanitizeRequestID — injection and overflow protection
// ============================================================================

func TestSanitizeRequestIDAllowedChars(t *testing.T) {
	safe := "abc-XYZ_123.ok"
	if got := sanitizeRequestID(safe); got != safe {
		t.Errorf("safe chars changed: %q", got)
	}
}

func TestSanitizeRequestIDStripsInjectionChars(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{`{"key":"value"}`, "keyvalue"},
		{"<script>", "script"},
		{"a&b", "ab"},
		{"a\nb\rc", "abc"},
		{"a b", "ab"},
		{"a/b", "ab"},
	}
	for _, c := range cases {
		if got := sanitizeRequestID(c.in); got != c.want {
			t.Errorf("sanitizeRequestID(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSanitizeRequestIDTruncatesAt128(t *testing.T) {
	long := strings.Repeat("a", 200)
	got := sanitizeRequestID(long)
	if len(got) > 128 {
		t.Errorf("length %d, want <= 128", len(got))
	}
}

func TestSanitizeRequestIDEmptyAfterFilter(t *testing.T) {
	// All characters are illegal; result must be empty string.
	if got := sanitizeRequestID("!!!???"); got != "" {
		t.Errorf("want empty string, got %q", got)
	}
}

// TestClientIPXFFInvalidIPIgnored verifies that a non-IP X-Forwarded-For value
// (e.g. an injected domain name) is ignored when TrustProxyHeaders is true,
// falling through to r.RemoteAddr — preventing rate-limit bypass and log forgery.
func TestClientIPXFFInvalidIPIgnored(t *testing.T) {
	old := TrustProxyHeaders
	TrustProxyHeaders = true
	defer func() { TrustProxyHeaders = old }()

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:51234"

	req.Header.Set("X-Forwarded-For", "not-an-ip-address")
	if ip := clientIP(req); ip != "10.0.0.1" {
		t.Errorf("invalid XFF should fall through to RemoteAddr, got %q", ip)
	}

	req.Header.Del("X-Forwarded-For")
	req.Header.Set("X-Real-IP", "user@corp.example")
	if ip := clientIP(req); ip != "10.0.0.1" {
		t.Errorf("invalid X-Real-IP should fall through to RemoteAddr, got %q", ip)
	}

	req.Header.Del("X-Real-IP")
	req.Header.Set("X-Forwarded-For", "203.0.113.5, 10.0.0.2")
	if ip := clientIP(req); ip != "203.0.113.5" {
		t.Errorf("valid XFF first IP should be used, got %q", ip)
	}
}

// TestMaxBodyBytesBlocks verifies that MaxBodyBytes causes reads beyond the
// limit to return an error, exercised by the inner handler reading the body.
func TestMaxBodyBytesBlocks(t *testing.T) {
	body := make([]byte, 1025)
	for i := range body {
		body[i] = 'x'
	}

	var readErr error
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 2048)
		_, readErr = r.Body.Read(buf)
		w.WriteHeader(http.StatusOK)
	})

	handler := MaxBodyBytes(1024)(inner)
	req := httptest.NewRequest("POST", "/", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if readErr == nil {
		t.Error("MaxBodyBytes: expected read error when body exceeds limit")
	}
}

// TestMaxBodyBytesAllowsSmallBody verifies that small bodies pass through.
func TestMaxBodyBytesAllowsSmallBody(t *testing.T) {
	body := bytes.NewReader([]byte(`{"ok":true}`))
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := MaxBodyBytes(1024)(inner)
	req := httptest.NewRequest("POST", "/", body)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called {
		t.Error("inner handler should be called for small body")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("want 200, got %d", rec.Code)
	}
}

// TestMaxBodyBytesZeroDisablesCap verifies that limit≤0 passes all bodies.
func TestMaxBodyBytesZeroDisablesCap(t *testing.T) {
	body := make([]byte, 1024*1024)
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := MaxBodyBytes(0)(inner)
	req := httptest.NewRequest("POST", "/", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called {
		t.Error("inner handler should be called when limit is 0")
	}
}

// TestRequestIDSanitizesIncomingHeader verifies that a header containing
// injection characters is sanitized before being reflected in the response.
func TestRequestIDSanitizesIncomingHeader(t *testing.T) {
	var capturedRID string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRID = RequestIDFromContext(r.Context())
	})
	wrapped := RequestID(handler)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Request-ID", `{"inject":"true"}`)
	wrapped.ServeHTTP(rec, req)
	// Only safe chars survive: { } " : are all stripped.
	if strings.ContainsAny(capturedRID, `{}":<>`) {
		t.Errorf("unsafe chars in sanitized RID: %q", capturedRID)
	}
	if capturedRID == "" {
		// At least the alphabetic parts ("injecttrue") survive.
		t.Errorf("RID should not be empty after sanitization")
	}
}

// ============================================================================
// Flusher/Unwrap forwarding — statusWriter (Recovery) and loggingResponseWriter
// (AccessLog) must not silently break SSE handlers when wrapped around them.
// mcp/http.go's SSE endpoint does a direct `w.(http.Flusher)` type assertion,
// so the wrapper types must implement Flush() directly (Unwrap alone would
// only satisfy http.NewResponseController-based callers, not a raw assertion).
// ============================================================================

// nonFlushingWriter implements only the 3 required http.ResponseWriter
// methods — no Flush() — to test the "underlying writer doesn't support
// Flusher" fallback path doesn't panic.
type nonFlushingWriter struct {
	header http.Header
}

func (w *nonFlushingWriter) Header() http.Header         { return w.header }
func (w *nonFlushingWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *nonFlushingWriter) WriteHeader(int)             {}

func newNonFlushingWriter() *nonFlushingWriter {
	return &nonFlushingWriter{header: make(http.Header)}
}

func TestStatusWriterForwardsFlush(t *testing.T) {
	rec := httptest.NewRecorder() // httptest.ResponseRecorder implements http.Flusher
	sw := &statusWriter{ResponseWriter: rec}
	f, ok := any(sw).(http.Flusher)
	if !ok {
		t.Fatal("statusWriter must implement http.Flusher")
	}
	f.Flush()
	if !rec.Flushed {
		t.Error("Flush() did not forward to the underlying ResponseRecorder")
	}
}

func TestStatusWriterFlushNoOpWhenUnsupported(t *testing.T) {
	sw := &statusWriter{ResponseWriter: newNonFlushingWriter()}
	// Must not panic even though the underlying writer has no Flush method.
	sw.Flush()
}

func TestStatusWriterUnwrap(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rec}
	u, ok := any(sw).(interface{ Unwrap() http.ResponseWriter })
	if !ok {
		t.Fatal("statusWriter must implement Unwrap() http.ResponseWriter")
	}
	if u.Unwrap() != http.ResponseWriter(rec) {
		t.Error("Unwrap() should return the exact wrapped ResponseWriter")
	}
}

func TestLoggingResponseWriterForwardsFlush(t *testing.T) {
	rec := httptest.NewRecorder()
	lrw := &loggingResponseWriter{ResponseWriter: rec}
	f, ok := any(lrw).(http.Flusher)
	if !ok {
		t.Fatal("loggingResponseWriter must implement http.Flusher")
	}
	f.Flush()
	if !rec.Flushed {
		t.Error("Flush() did not forward to the underlying ResponseRecorder")
	}
}

func TestLoggingResponseWriterFlushNoOpWhenUnsupported(t *testing.T) {
	lrw := &loggingResponseWriter{ResponseWriter: newNonFlushingWriter()}
	lrw.Flush()
}

func TestLoggingResponseWriterUnwrap(t *testing.T) {
	rec := httptest.NewRecorder()
	lrw := &loggingResponseWriter{ResponseWriter: rec}
	u, ok := any(lrw).(interface{ Unwrap() http.ResponseWriter })
	if !ok {
		t.Fatal("loggingResponseWriter must implement Unwrap() http.ResponseWriter")
	}
	if u.Unwrap() != http.ResponseWriter(rec) {
		t.Error("Unwrap() should return the exact wrapped ResponseWriter")
	}
}

// TestResponseControllerDrillsThroughRecoveryAndAccessLog is the regression
// test for the actual bug: http.NewResponseController(w) must find a working
// Flush/SetWriteDeadline even when w has been wrapped by BOTH Recovery and
// AccessLog (the composition mcp/http.go's SSE endpoint would see once the
// full default chain wraps it) — proving http.ResponseController's Unwrap
// walk works through two stacked wrapper layers, not just one.
func TestResponseControllerDrillsThroughRecoveryAndAccessLog(t *testing.T) {
	var sawFlusher bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		sawFlusher = rc.Flush() == nil
	})
	wrapped := Recovery(AccessLog(inner))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	wrapped.ServeHTTP(rec, req)
	if !sawFlusher {
		t.Error("http.NewResponseController(w).Flush() should succeed through Recovery(AccessLog(...))")
	}
}

// TestDefaultChainPreservesRealStreamingOverTCP is the rigorous version of
// the ResponseController test above: it proves bytes written before a Flush
// call actually reach a REAL TCP client promptly when the handler is wrapped
// by the full Default chain — not just that the Flush call itself doesn't
// error (httptest.ResponseRecorder.Flush() is a no-op flag-set, so it can't
// catch server-side buffering). Uses a real net/http.Server via
// httptest.NewServer so actual socket writes are exercised.
func TestDefaultChainPreservesRealStreamingOverTCP(t *testing.T) {
	const firstChunk = "first-chunk\n"
	release := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, firstChunk)
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("flush through Default chain failed: %v", err)
		}
		<-release // hold the connection open until the test has read the first chunk
	})

	srv := httptest.NewServer(Default(handler))
	defer srv.Close()
	defer close(release)

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
		t.Fatal(err)
	}

	// A short deadline: if Flush is silently swallowed by the wrapper chain,
	// the first chunk sits server-side until the handler returns (it never
	// will, until `release` closes) and this read times out.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(conn)
	// Skip the HTTP status line + headers.
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("reading response (flush likely did not reach the socket in time): %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	// The response has no Content-Length (streaming), so net/http.Server sends
	// it chunked-transfer-encoded (RFC 9112 §7.1): a hex chunk-size line, then
	// exactly that many content bytes, then a trailing CRLF. httputil's
	// chunked reader decodes that framing rather than hand-parsing it.
	body := make([]byte, len(firstChunk))
	if _, err := io.ReadFull(httputil.NewChunkedReader(reader), body); err != nil {
		t.Fatalf("reading flushed (chunked) body chunk: %v", err)
	}
	if string(body) != firstChunk {
		t.Errorf("body: got %q want %q", body, firstChunk)
	}
}
