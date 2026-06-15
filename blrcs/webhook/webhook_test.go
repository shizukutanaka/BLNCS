package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"blrcs/telemetry"
)

// ============================================================================
// Subscription mechanics
// ============================================================================

func TestSubscribeAndCount(t *testing.T) {
	b := NewBus(telemetry.New(telemetry.NopRecorder{}))
	b.AllowPrivateTargets = true
	b.Subscribe("dpp.issued", Subscriber{URL: "http://test/1"})
	b.Subscribe("dpp.issued", Subscriber{URL: "http://test/2"})
	b.Subscribe("dpp.verified", Subscriber{URL: "http://test/3"})

	if got := len(b.Subscribers("dpp.issued")); got != 2 {
		t.Errorf("issued: %d", got)
	}
	if got := len(b.Subscribers("dpp.verified")); got != 1 {
		t.Errorf("verified: %d", got)
	}
	if got := len(b.Subscribers("none")); got != 0 {
		t.Errorf("none: %d", got)
	}
}

// ============================================================================
// Delivery happy path
// ============================================================================

func TestPublishHappyPath(t *testing.T) {
	var received atomic.Int32
	var capturedSig, capturedTimestamp, capturedEvent string
	var capturedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		capturedBody = body
		capturedSig = r.Header.Get("X-BLRCS-Signature")
		capturedTimestamp = r.Header.Get("X-BLRCS-Timestamp")
		capturedEvent = r.Header.Get("X-BLRCS-Event")
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	bus := NewBus(telemetry.New(telemetry.NopRecorder{}))
	bus.AllowPrivateTargets = true
	bus.Subscribe("test.event", Subscriber{
		URL:    server.URL,
		Secret: []byte("shared-secret"),
	})

	succ, total, err := bus.Publish(context.Background(), "test.event", map[string]any{
		"foo": "bar",
	})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || succ != 1 {
		t.Errorf("delivery: %d/%d", succ, total)
	}
	if received.Load() != 1 {
		t.Errorf("server received: %d", received.Load())
	}
	if capturedEvent != "test.event" {
		t.Errorf("event header: %s", capturedEvent)
	}
	if capturedSig == "" {
		t.Error("signature missing")
	}
	if capturedTimestamp == "" {
		t.Error("timestamp missing")
	}
	// Verify body parses as Event
	var ev Event
	if err := json.Unmarshal(capturedBody, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Type != "test.event" {
		t.Errorf("event type: %s", ev.Type)
	}
}

// ============================================================================
// Multiple subscribers in parallel
// ============================================================================

func TestPublishMultipleSubscribers(t *testing.T) {
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	bus := NewBus(telemetry.New(telemetry.NopRecorder{}))
	bus.AllowPrivateTargets = true
	for i := 0; i < 10; i++ {
		bus.Subscribe("burst", Subscriber{URL: server.URL, Secret: []byte("s")})
	}

	succ, total, _ := bus.Publish(context.Background(), "burst", "data")
	if succ != 10 || total != 10 {
		t.Errorf("delivery: %d/%d", succ, total)
	}
	if received.Load() != 10 {
		t.Errorf("server received: %d", received.Load())
	}
}

// ============================================================================
// Retry on transient failure
// ============================================================================

func TestRetryOnFailure(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n < 3 {
			http.Error(w, "transient", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	bus := NewBus(telemetry.New(telemetry.NopRecorder{}))
	bus.AllowPrivateTargets = true
	// Speed up retries for test
	bus.Subscribe("flaky", Subscriber{
		URL:     server.URL,
		Secret:  []byte("s"),
		Retries: 5,
	})
	// Patch: short Now for fast first delay (we can't change the 1s base easily,
	// but with retries=5 first delay is 1s — still fits)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	succ, total, _ := bus.Publish(ctx, "flaky", "x")
	if succ != 1 || total != 1 {
		t.Errorf("eventual delivery: %d/%d, attempts=%d", succ, total, attempts.Load())
	}
	if attempts.Load() != 3 {
		t.Errorf("attempts: %d (want 3)", attempts.Load())
	}
}

func TestExhaustedRetriesGiveUp(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "permanent", http.StatusInternalServerError)
	}))
	defer server.Close()

	bus := NewBus(telemetry.New(telemetry.NopRecorder{}))
	bus.AllowPrivateTargets = true
	bus.Subscribe("doomed", Subscriber{
		URL:     server.URL,
		Secret:  []byte("s"),
		Retries: 1, // 2回試行後に断念 (1s後)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	succ, total, _ := bus.Publish(ctx, "doomed", "x")
	if succ != 0 || total != 1 {
		t.Errorf("should fail: %d/%d", succ, total)
	}
}

// ============================================================================
// HMAC signature verification (receiver side)
// ============================================================================

func TestVerifyRequestRoundTrip(t *testing.T) {
	secret := []byte("super-secret-key")
	body := []byte(`{"event":"test"}`)
	now := time.Now()
	ts := strconv.FormatInt(now.Unix(), 10)
	sig := signPayload(secret, ts, body)

	headers := map[string]string{
		"X-BLRCS-Timestamp": ts,
		"X-BLRCS-Signature": "v1=" + sig,
	}
	if err := VerifyRequest(secret, headers, body, 5*time.Minute, now); err != nil {
		t.Fatalf("valid signature failed: %v", err)
	}
}

func TestVerifyRejectsTamperedBody(t *testing.T) {
	secret := []byte("k")
	original := []byte("{}")
	tampered := []byte(`{"evil":true}`)
	now := time.Now()
	ts := strconv.FormatInt(now.Unix(), 10)
	sig := signPayload(secret, ts, original)

	headers := map[string]string{
		"X-BLRCS-Timestamp": ts,
		"X-BLRCS-Signature": "v1=" + sig,
	}
	if err := VerifyRequest(secret, headers, tampered, 5*time.Minute, now); err == nil {
		t.Fatal("tampered body should fail verification")
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	secret := []byte("k")
	body := []byte("{}")
	now := time.Now()
	ts := strconv.FormatInt(now.Unix(), 10)
	headers := map[string]string{
		"X-BLRCS-Timestamp": ts,
		"X-BLRCS-Signature": "v1=ffff" + signPayload(secret, ts, body)[4:],
	}
	if err := VerifyRequest(secret, headers, body, 5*time.Minute, now); err == nil {
		t.Fatal("tampered sig should fail")
	}
}

func TestVerifyRejectsWrongSecret(t *testing.T) {
	body := []byte("{}")
	now := time.Now()
	ts := strconv.FormatInt(now.Unix(), 10)
	sig := signPayload([]byte("real-secret"), ts, body)
	headers := map[string]string{
		"X-BLRCS-Timestamp": ts,
		"X-BLRCS-Signature": "v1=" + sig,
	}
	if err := VerifyRequest([]byte("wrong-secret"), headers, body, 5*time.Minute, now); err == nil {
		t.Fatal("wrong secret should fail")
	}
}

func TestVerifyRejectsExpiredTimestamp(t *testing.T) {
	secret := []byte("k")
	body := []byte("{}")
	now := time.Now()
	oldTime := now.Add(-1 * time.Hour)
	ts := strconv.FormatInt(oldTime.Unix(), 10)
	sig := signPayload(secret, ts, body)
	headers := map[string]string{
		"X-BLRCS-Timestamp": ts,
		"X-BLRCS-Signature": "v1=" + sig,
	}
	// 5min window
	if err := VerifyRequest(secret, headers, body, 5*time.Minute, now); err == nil {
		t.Fatal("expired timestamp should fail")
	}
}

func TestVerifyMissingHeaders(t *testing.T) {
	body := []byte("{}")
	now := time.Now()
	cases := []map[string]string{
		{},                              // both missing
		{"X-BLRCS-Timestamp": "1"},      // sig missing
		{"X-BLRCS-Signature": "v1=abc"}, // ts missing
		{"X-BLRCS-Timestamp": "1", "X-BLRCS-Signature": "abc"}, // bad prefix
	}
	for _, h := range cases {
		if err := VerifyRequest([]byte("k"), h, body, time.Hour, now); err == nil {
			t.Errorf("should reject %+v", h)
		}
	}
}

// ============================================================================
// Empty subscribers
// ============================================================================

func TestPublishWithNoSubscribers(t *testing.T) {
	bus := NewBus(telemetry.New(telemetry.NopRecorder{}))
	bus.AllowPrivateTargets = true
	succ, total, err := bus.Publish(context.Background(), "no-listeners", nil)
	if err != nil {
		t.Fatal(err)
	}
	if succ != 0 || total != 0 {
		t.Errorf("no subscribers: %d/%d", succ, total)
	}
}

// ============================================================================
// Custom headers
// ============================================================================

func TestCustomHeaders(t *testing.T) {
	var capturedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	bus := NewBus(telemetry.New(telemetry.NopRecorder{}))
	bus.AllowPrivateTargets = true
	bus.Subscribe("auth.test", Subscriber{
		URL:     server.URL,
		Secret:  []byte("k"),
		Headers: map[string]string{"Authorization": "Bearer custom-token"},
	})
	bus.Publish(context.Background(), "auth.test", "x")
	if capturedAuth != "Bearer custom-token" {
		t.Errorf("custom auth not set: %s", capturedAuth)
	}
}

func TestSSRFGuardBlocksLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	// Secure-by-default bus (AllowPrivateTargets=false) must refuse loopback.
	bus := NewBus(telemetry.New(telemetry.NopRecorder{}))
	bus.Subscribe("evt", Subscriber{URL: srv.URL, Retries: 1, Timeout: time.Second})
	_, _, _ = bus.Publish(context.Background(), "evt", map[string]any{"x": 1})

	// Direct check: delivery to the loopback URL is blocked.
	if err := bus.deliverOnce(context.Background(), Subscriber{URL: srv.URL}, "evt", []byte("{}")); !errors.Is(err, ErrBlockedTarget) {
		t.Fatalf("want ErrBlockedTarget, got %v", err)
	}
	// Non-http scheme is blocked too.
	if err := bus.deliverOnce(context.Background(), Subscriber{URL: "file:///etc/passwd"}, "evt", []byte("{}")); !errors.Is(err, ErrBlockedTarget) {
		t.Fatalf("file:// want ErrBlockedTarget, got %v", err)
	}
}

// TestIsBlockedIP pins the non-public ranges the SSRF guard must reject,
// including the RFC 6598 CGNAT range that net.IP.IsPrivate misses.
func TestIsBlockedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1",        // loopback
		"10.1.2.3",         // RFC 1918
		"192.168.0.1",      // RFC 1918
		"172.16.5.5",       // RFC 1918
		"169.254.169.254",  // link-local (cloud metadata)
		"0.0.0.0",          // unspecified
		"100.64.0.1",       // RFC 6598 CGNAT (NOT caught by IsPrivate)
		"100.127.255.254",  // RFC 6598 upper edge
		"::1",              // IPv6 loopback
		"fc00::1",          // IPv6 unique-local
		"::ffff:127.0.0.1", // IPv4-mapped loopback
	}
	for _, s := range blocked {
		if !isBlockedIP(net.ParseIP(s)) {
			t.Errorf("%s should be blocked", s)
		}
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "203.0.113.10", "2606:4700:4700::1111"}
	for _, s := range allowed {
		if isBlockedIP(net.ParseIP(s)) {
			t.Errorf("%s should be allowed (public)", s)
		}
	}
}

// TestSafeDialContextBlocksPrivateLiteral verifies the dial-time guard rejects a
// connection to a private/loopback address — the enforcement point that defeats
// DNS rebinding (the URL check and the dial now agree on the same IP).
func TestSafeDialContextBlocksPrivateLiteral(t *testing.T) {
	bus := NewBus(telemetry.New(telemetry.NopRecorder{}))
	if _, err := bus.safeDialContext(context.Background(), "tcp", "127.0.0.1:9"); !errors.Is(err, ErrBlockedTarget) {
		t.Fatalf("dial to loopback: want ErrBlockedTarget, got %v", err)
	}
	if _, err := bus.safeDialContext(context.Background(), "tcp", "169.254.169.254:80"); !errors.Is(err, ErrBlockedTarget) {
		t.Fatalf("dial to metadata IP: want ErrBlockedTarget, got %v", err)
	}
	// With private targets allowed, the guard steps aside (will fail to connect,
	// but NOT with ErrBlockedTarget).
	bus.AllowPrivateTargets = true
	if _, err := bus.safeDialContext(context.Background(), "tcp", "127.0.0.1:9"); errors.Is(err, ErrBlockedTarget) {
		t.Fatal("AllowPrivateTargets=true must not block the dial")
	}
}

func TestRandomEventID(t *testing.T) {
	id := randomEventID()
	// UUID v4 format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
	if len(id) != 36 {
		t.Errorf("randomEventID length: %d", len(id))
	}
	if id[14] != '4' {
		t.Errorf("version nibble: %c", id[14])
	}
	// Multiple IDs should be different
	id2 := randomEventID()
	if id == id2 {
		t.Error("randomEventID should produce different values")
	}
}

func TestNewBusNilTelemetry(t *testing.T) {
	bus := NewBus(nil)
	if bus == nil {
		t.Fatal("nil bus")
	}
}

func TestVerifyRequestEmptySecret(t *testing.T) {
	now := time.Now()
	ts := strconv.FormatInt(now.Unix(), 10)
	headers := map[string]string{
		"X-BLRCS-Timestamp": ts,
		"X-BLRCS-Signature": "v1=abc",
	}
	if err := VerifyRequest([]byte{}, headers, []byte("{}"), 5*time.Minute, now); err == nil {
		t.Error("empty secret should fail")
	}
}

func TestVerifyRequestBadTimestamp(t *testing.T) {
	now := time.Now()
	headers := map[string]string{
		"X-BLRCS-Timestamp": "not-a-number",
		"X-BLRCS-Signature": "v1=abc",
	}
	if err := VerifyRequest([]byte("secret"), headers, []byte("{}"), 5*time.Minute, now); err == nil {
		t.Error("bad timestamp should fail")
	}
}

func TestVerifyRequestCaseInsensitiveHeaders(t *testing.T) {
	secret := []byte("secret")
	body := []byte("{}")
	now := time.Now()
	ts := strconv.FormatInt(now.Unix(), 10)
	sig := signPayload(secret, ts, body)
	// Use lowercase header variants
	headers := map[string]string{
		"X-Blrcs-Timestamp": ts,
		"X-Blrcs-Signature": "v1=" + sig,
	}
	if err := VerifyRequest(secret, headers, body, 5*time.Minute, now); err != nil {
		t.Fatalf("lowercase headers should still verify: %v", err)
	}
}

func TestValidateOutboundURLEmptyHost(t *testing.T) {
	bus := NewBus(telemetry.New(telemetry.NopRecorder{}))
	// http:// with no host → blocked
	u, _ := url.Parse("http://")
	if err := bus.validateOutboundURL(u); err == nil {
		t.Error("empty host should be blocked")
	}
}

func TestValidateOutboundURLUnresolvable(t *testing.T) {
	bus := NewBus(telemetry.New(telemetry.NopRecorder{}))
	// Hostname that can't be resolved (no such domain)
	u, _ := url.Parse("https://this-host-does-not-exist-blrcs-test.invalid")
	err := bus.validateOutboundURL(u)
	if err == nil {
		t.Error("unresolvable host should be blocked")
	}
}

// ============================================================================
// Coverage uplift: missing-signature path, context-cancelled retry, redirect guard
// ============================================================================

func TestVerifyRequestMissingSignatureWithValidTimestamp(t *testing.T) {
	secret := []byte("k")
	body := []byte("{}")
	now := time.Now()
	ts := strconv.FormatInt(now.Unix(), 10)
	// Valid timestamp, but NO signature header at all.
	headers := map[string]string{
		"X-BLRCS-Timestamp": ts,
	}
	if err := VerifyRequest(secret, headers, body, 5*time.Minute, now); err == nil {
		t.Error("missing signature should fail even with valid timestamp")
	}
}

func TestDeliverWithRetryContextCancelledDuringWait(t *testing.T) {
	// Server always fails — forces a retry delay, during which we cancel ctx.
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		http.Error(w, "fail", http.StatusInternalServerError)
	}))
	defer server.Close()

	bus := NewBus(telemetry.New(telemetry.NopRecorder{}))
	bus.AllowPrivateTargets = true

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel after first delivery attempt completes so the retry wait is interrupted.
	go func() {
		for attempts.Load() < 1 {
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
	}()

	err := bus.deliverWithRetry(ctx, Subscriber{URL: server.URL, Retries: 5, Timeout: time.Second}, "evt", []byte("{}"))
	if err == nil {
		t.Error("cancelled context during retry should return error")
	}
}

func TestDeliverOnceBadURL(t *testing.T) {
	bus := NewBus(telemetry.New(telemetry.NopRecorder{}))
	bus.AllowPrivateTargets = true
	// "\x00" makes http.NewRequestWithContext return an error (invalid URL byte).
	err := bus.deliverOnce(context.Background(), Subscriber{URL: "http://host\x00bad"}, "evt", []byte("{}"))
	if err == nil {
		t.Error("invalid URL byte should cause deliverOnce to return error")
	}
}

func TestNewBusCheckRedirectBlocksSSRF(t *testing.T) {
	// Set up a server that redirects to itself (loopback) — CheckRedirect should fire and block.
	var redirectTarget string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if redirectTarget != "" {
			http.Redirect(w, r, redirectTarget, http.StatusFound)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()
	redirectTarget = server.URL + "/redirected"

	// Secure bus (AllowPrivateTargets=false): redirect to loopback must be blocked.
	bus := NewBus(telemetry.New(telemetry.NopRecorder{}))
	// The initial URL is not subject to CheckRedirect (it goes through validateOutboundURL
	// in deliverOnce). The CheckRedirect is exercised only when the HTTP client follows
	// a 30x. Since the initial URL is loopback, deliverOnce will block it before the
	// request even goes out — so directly call the redirect checker:
	parsedURL, _ := url.Parse(server.URL + "/loop")
	err := bus.HTTP.CheckRedirect(&http.Request{URL: parsedURL}, nil)
	if err == nil {
		t.Error("CheckRedirect to loopback should return ErrBlockedTarget")
	}
	if !errors.Is(err, ErrBlockedTarget) {
		t.Errorf("want ErrBlockedTarget, got: %v", err)
	}
}

// TestPublishMarshalError covers the json.Marshal error branch in Publish when
// data contains an un-marshallable value (channel).
func TestPublishMarshalError(t *testing.T) {
	bus := NewBus(telemetry.New(telemetry.NopRecorder{}))
	bus.AllowPrivateTargets = true
	bus.Subscribe("test.evt", Subscriber{URL: "http://localhost:19999/ignored"})
	_, _, err := bus.Publish(context.Background(), "test.evt", make(chan int))
	if err == nil {
		t.Error("un-marshallable event data should cause Publish to return an error")
	}
}

// TestDeliverOnceZeroTimeout covers the s.Timeout == 0 branch in deliverOnce
// where no context.WithTimeout is created (timeoutCtx stays as ctx).
// TestValidateOutboundURLPublicIP covers the return nil path at the end of the
// validateOutboundURL loop (line 136) when all resolved IPs are public.
// Uses a numeric IP literal so net.LookupIP returns it directly (no DNS query).
func TestValidateOutboundURLPublicIP(t *testing.T) {
	bus := NewBus(telemetry.New(telemetry.NopRecorder{}))
	// 8.8.8.8 is a public unicast IP — not loopback, not private, not link-local.
	u, _ := url.Parse("https://8.8.8.8/path")
	if err := bus.validateOutboundURL(u); err != nil {
		t.Errorf("public IP 8.8.8.8 should not be blocked: %v", err)
	}
}

// TestPublishGoroutinePanicRecovery covers lines 190-192 (the recover block
// inside Publish's goroutine). Setting b.HTTP = nil causes a nil-pointer panic
// in deliverOnce when it calls b.HTTP.Do(req); the goroutine's deferred
// recover() catches it and increments the panic counter.
func TestPublishGoroutinePanicRecovery(t *testing.T) {
	bus := NewBus(telemetry.New(telemetry.NopRecorder{}))
	bus.AllowPrivateTargets = true
	bus.Subscribe("panic.evt", Subscriber{URL: "http://127.0.0.1:9", Retries: 0, Timeout: time.Second})
	bus.HTTP = nil // nil client → panic inside goroutine
	succ, total, err := bus.Publish(context.Background(), "panic.evt", "x")
	if err != nil {
		t.Fatal(err)
	}
	if succ != 0 || total != 1 {
		t.Errorf("panicking goroutine: succ=%d total=%d", succ, total)
	}
}

// TestDeliverWithRetryPreCancelledContext covers lines 217-219: the ctx.Err()
// check at the top of the deliverWithRetry loop. When ctx is already cancelled
// before the first attempt, the check fires immediately and returns the error
// without calling deliverOnce.
func TestDeliverWithRetryPreCancelledContext(t *testing.T) {
	bus := NewBus(telemetry.New(telemetry.NopRecorder{}))
	bus.AllowPrivateTargets = true
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := bus.deliverWithRetry(ctx, Subscriber{URL: "http://127.0.0.1:9", Retries: 3, Timeout: time.Second}, "evt", []byte("{}"))
	if err == nil {
		t.Error("pre-cancelled context should return error immediately")
	}
}

// TestDeliverOnceConnectionImmediatelyClosed covers lines 273-275: the error
// return from b.HTTP.Do(req) when the server closes the connection before
// sending any response.
func TestDeliverOnceConnectionImmediatelyClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	defer ln.Close()

	bus := NewBus(telemetry.New(telemetry.NopRecorder{}))
	bus.AllowPrivateTargets = true
	err = bus.deliverOnce(context.Background(), Subscriber{
		URL:     "http://" + ln.Addr().String(),
		Timeout: time.Second,
	}, "evt", []byte("{}"))
	if err == nil {
		t.Error("connection immediately closed should return error from http.Do")
	}
}

// TestVerifyRequestSigWrongLongPrefix covers lines 333-335: the sig header has
// length > len("v1=") but doesn't start with "v1=". The first condition of the
// OR (len <= len) is false so only the second branch (prefix mismatch) fires.
func TestVerifyRequestSigWrongLongPrefix(t *testing.T) {
	secret := []byte("k")
	body := []byte("{}")
	now := time.Now()
	ts := strconv.FormatInt(now.Unix(), 10)
	headers := map[string]string{
		"X-BLRCS-Timestamp": ts,
		"X-BLRCS-Signature": "v2=somehashvalue", // length > 3 but prefix is "v2="
	}
	err := VerifyRequest(secret, headers, body, 5*time.Minute, now)
	if err == nil {
		t.Error("signature with wrong prefix 'v2=' should fail")
	}
}

func TestDeliverOnceZeroTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	bus := NewBus(telemetry.New(telemetry.NopRecorder{}))
	bus.AllowPrivateTargets = true
	// Timeout=0 → no context.WithTimeout; deliverOnce should still succeed.
	err := bus.deliverOnce(context.Background(), Subscriber{URL: server.URL, Timeout: 0}, "evt", []byte("{}"))
	if err != nil {
		t.Errorf("zero timeout deliverOnce should succeed: %v", err)
	}
}
