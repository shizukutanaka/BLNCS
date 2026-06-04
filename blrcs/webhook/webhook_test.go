package webhook

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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
