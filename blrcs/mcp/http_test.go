package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"blrcs/compliance"
)

// TestHTTPHandlerCloseStopsGCGoroutine verifies that Close stops the background
// session-GC goroutine, so creating handlers does not leak a goroutine + ticker
// each. Before the fix, gcLoop ran `for range t.C` with no stop channel and could
// never exit.
func TestHTTPHandlerCloseStopsGCGoroutine(t *testing.T) {
	srv, err := NewServer("ts-gc", "did:web:gc.test")
	if err != nil {
		t.Fatal(err)
	}
	// Let the runtime settle, then take a baseline.
	time.Sleep(20 * time.Millisecond)
	before := runtime.NumGoroutine()

	const n = 50
	handlers := make([]*HTTPHandler, n)
	for i := range handlers {
		handlers[i] = NewHTTPHandler(srv, nil, nil) // each starts a gcLoop goroutine
	}
	for _, h := range handlers {
		if err := h.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}

	// Poll until the gcLoop goroutines have drained back toward the baseline.
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before+5 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > before+5 {
		t.Errorf("gcLoop goroutines did not drain after Close: before=%d after=%d (started %d handlers)", before, got, n)
	}

	// Close must be idempotent (no double-close panic).
	if err := handlers[0].Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func newTestHTTP(t *testing.T, auth AuthVerifier, lim RateLimiter) (*httptest.Server, *compliance.Issuer) {
	t.Helper()
	srv, err := NewServer("did:web:ts.http", "did:web:server.http")
	if err != nil {
		t.Fatal(err)
	}
	iss, _ := compliance.NewIssuer("did:web:factory.http")
	srv.RegisterIssuer(iss)
	att, _ := compliance.NewSensorAttester("did:device:sensor.http")
	srv.RegisterAttester(att)
	h := NewHTTPHandler(srv, auth, lim)
	ts := httptest.NewServer(h)
	t.Cleanup(func() { ts.Close() })
	return ts, iss
}

func doJSON(t *testing.T, ts *httptest.Server, method, path, body, sid, token string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if sid != "" {
		req.Header.Set(sessionHeader, sid)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func TestHTTP_InitializeGrantsSession(t *testing.T) {
	ts, _ := newTestHTTP(t, nil, nil)
	resp, body := doJSON(t, ts, "POST", "/mcp", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, "", "")
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d body=%s", resp.StatusCode, body)
	}
	sid := resp.Header.Get(sessionHeader)
	if sid == "" {
		t.Fatal("no session header on initialize response")
	}
	if !strings.Contains(string(body), `"protocolVersion":"`+protocolVersion+`"`) {
		t.Fatalf("bad body: %s", body)
	}
}

func TestHTTP_ToolCallRoundTrip(t *testing.T) {
	ts, iss := newTestHTTP(t, nil, nil)
	// initialize
	resp, _ := doJSON(t, ts, "POST", "/mcp", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, "", "")
	sid := resp.Header.Get(sessionHeader)

	// issue
	issueReq := fmt.Sprintf(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"issue_passport","arguments":{"issuerId":"%s","productId":"01234567890128","carbonKgCO2e":1.5}}}`, iss.ID)
	resp, body := doJSON(t, ts, "POST", "/mcp", issueReq, sid, "")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	var envelope struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Result.IsError {
		t.Fatalf("tool error: %s", envelope.Result.Content[0].Text)
	}
	credJson := envelope.Result.Content[0].Text

	// verify
	verifyReq := map[string]any{
		"jsonrpc": "2.0", "id": 3, "method": "tools/call",
		"params": map[string]any{
			"name": "verify_passport",
			"arguments": map[string]any{
				"credentialJson":     credJson,
				"issuerPublicKeyB64": base64.StdEncoding.EncodeToString(iss.PublicKey()),
			},
		},
	}
	vb, _ := json.Marshal(verifyReq)
	resp, body = doJSON(t, ts, "POST", "/mcp", string(vb), sid, "")
	if resp.StatusCode != 200 {
		t.Fatalf("verify status: %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), `\"valid\":true`) {
		t.Fatalf("passport not verified: %s", body)
	}
}

func TestHTTP_MissingSessionOnNonInitialize(t *testing.T) {
	ts, _ := newTestHTTP(t, nil, nil)
	resp, _ := doJSON(t, ts, "POST", "/mcp", `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`, "", "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 (missing sid), got %d", resp.StatusCode)
	}
}

func TestHTTP_UnknownSessionRejected(t *testing.T) {
	ts, _ := newTestHTTP(t, nil, nil)
	resp, _ := doJSON(t, ts, "POST", "/mcp", `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`, "deadbeef", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404, got %d", resp.StatusCode)
	}
}

func TestHTTP_BearerAuth(t *testing.T) {
	auth := &BearerTokenAuth{Tokens: map[string]string{"secret-abc": "agent-1"}}
	ts, _ := newTestHTTP(t, auth, nil)

	// no token
	resp, _ := doJSON(t, ts, "POST", "/mcp", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, "", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}

	// wrong token
	resp, _ = doJSON(t, ts, "POST", "/mcp", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, "", "wrong")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}

	// correct token
	resp, _ = doJSON(t, ts, "POST", "/mcp", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, "", "secret-abc")
	if resp.StatusCode != 200 {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
}

func TestHTTP_SessionBoundToPrincipal(t *testing.T) {
	auth := &BearerTokenAuth{Tokens: map[string]string{
		"tok-a": "principal-a",
		"tok-b": "principal-b",
	}}
	ts, _ := newTestHTTP(t, auth, nil)

	// A initializes
	resp, _ := doJSON(t, ts, "POST", "/mcp", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, "", "tok-a")
	sidA := resp.Header.Get(sessionHeader)
	if sidA == "" {
		t.Fatal("no sid for A")
	}

	// B tries to use A's session
	resp, body := doJSON(t, ts, "POST", "/mcp", `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, sidA, "tok-b")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("session hijack should 404, got %d: %s", resp.StatusCode, body)
	}
}

func TestHTTP_RateLimiting(t *testing.T) {
	lim := NewTokenBucketLimiter(1, 2) // 1 req/sec, burst 2
	ts, _ := newTestHTTP(t, nil, lim)

	// 2 requests ok (burst)
	for i := 0; i < 2; i++ {
		resp, _ := doJSON(t, ts, "POST", "/mcp", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, "", "")
		if resp.StatusCode != 200 {
			t.Fatalf("req %d: got %d", i, resp.StatusCode)
		}
	}
	// 3rd should be rejected
	resp, _ := doJSON(t, ts, "POST", "/mcp", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, "", "")
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d", resp.StatusCode)
	}
}

func TestHTTP_DeleteSession(t *testing.T) {
	ts, _ := newTestHTTP(t, nil, nil)
	resp, _ := doJSON(t, ts, "POST", "/mcp", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, "", "")
	sid := resp.Header.Get(sessionHeader)

	// delete
	resp, _ = doJSON(t, ts, "DELETE", "/mcp", "", sid, "")
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: %d", resp.StatusCode)
	}

	// subsequent POST should fail
	resp, _ = doJSON(t, ts, "POST", "/mcp", `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, sid, "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("post-delete: %d", resp.StatusCode)
	}
}

func TestHTTP_MethodNotAllowed(t *testing.T) {
	ts, _ := newTestHTTP(t, nil, nil)
	req, _ := http.NewRequest("PUT", ts.URL+"/mcp", bytes.NewReader(nil))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", resp.StatusCode)
	}
}

func TestHTTP_SSEHeartbeat(t *testing.T) {
	ts, _ := newTestHTTP(t, nil, nil)
	// initialize session
	resp, _ := doJSON(t, ts, "POST", "/mcp", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, "", "")
	sid := resp.Header.Get(sessionHeader)

	// GET SSE with short context (to test connection establishment)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", ts.URL+"/mcp", nil)
	req.Header.Set(sessionHeader, sid)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("SSE status: %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content-type: %s", ct)
	}
	// Read first line
	rd := bufio.NewReader(resp.Body)
	line, _ := rd.ReadString('\n')
	if !strings.Contains(line, "connected") {
		t.Fatalf("expected connected line, got: %q", line)
	}
}

func TestHTTP_MaxBodyEnforced(t *testing.T) {
	srv, _ := NewServer("ts", "server")
	h := NewHTTPHandler(srv, nil, nil)
	h.SetMaxBody(100)
	ts := httptest.NewServer(h)
	defer ts.Close()

	big := strings.Repeat("x", 500)
	req, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader(big))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversize body: want 400, got %d", resp.StatusCode)
	}
}

func TestHTTP_EmptyBodyRejected(t *testing.T) {
	ts, _ := newTestHTTP(t, nil, nil)
	resp, _ := doJSON(t, ts, "POST", "/mcp", "", "", "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", resp.StatusCode)
	}
}

// TestSessionStoreBoundedLRU asserts the session map never exceeds its cap and
// that, at capacity, the least-recently-seen session is the one evicted (LRU) —
// closing the unbounded-growth DoS where repeated `initialize` calls accumulate
// sessions faster than the 30m idle expiry / 5m GC can reclaim them.
func TestSessionStoreBoundedLRU(t *testing.T) {
	s := &sessionStore{data: make(map[string]*sessionEntry), maxSessions: 3}

	// Create 3 sessions with strictly increasing lastSeen so ordering is defined.
	base := time.Now()
	for i, id := range []string{"a", "b", "c"} {
		s.create(id, "p")
		s.mu.Lock()
		s.data[id].lastSeen = base.Add(time.Duration(i) * time.Second)
		s.mu.Unlock()
	}
	if got := len(s.data); got != 3 {
		t.Fatalf("len after 3 creates: %d, want 3", got)
	}

	// "a" is the oldest. Creating a 4th must evict exactly "a" and stay at cap.
	s.create("d", "p")
	if got := len(s.data); got != 3 {
		t.Fatalf("len after 4th create: %d, want 3 (cap enforced)", got)
	}
	s.mu.Lock()
	_, aLives := s.data["a"]
	_, dLives := s.data["d"]
	s.mu.Unlock()
	if aLives {
		t.Error("oldest session 'a' should have been evicted (LRU)")
	}
	if !dLives {
		t.Error("newest session 'd' should be present")
	}
}

// TestSessionStoreCapPrefersIdleEviction asserts that when the map is at
// capacity but contains idle-expired entries, those are reclaimed first (so a
// live, recently-seen session is not needlessly evicted).
func TestSessionStoreCapPrefersIdleEviction(t *testing.T) {
	s := &sessionStore{data: make(map[string]*sessionEntry), maxSessions: 2}
	s.create("live", "p")
	s.create("stale", "p")
	// Make "stale" idle-expired.
	s.mu.Lock()
	s.data["stale"].lastSeen = time.Now().Add(-2 * sessionIdleTimeout)
	s.mu.Unlock()

	// At capacity (2). Creating a 3rd should reclaim "stale" (idle) and keep "live".
	s.create("new", "p")
	s.mu.Lock()
	_, liveLives := s.data["live"]
	_, staleLives := s.data["stale"]
	n := len(s.data)
	s.mu.Unlock()
	if staleLives {
		t.Error("idle-expired 'stale' should be reclaimed before LRU eviction")
	}
	if !liveLives {
		t.Error("live session should survive when an idle entry was available to reclaim")
	}
	if n != 2 {
		t.Fatalf("len: %d, want 2", n)
	}
}

// TestSetMaxSessionsIgnoresNonPositive asserts the cap cannot be disabled (a
// non-positive value is ignored), preserving the DoS guard.
func TestSetMaxSessionsIgnoresNonPositive(t *testing.T) {
	srv, _ := NewServer("ts", "server")
	h := NewHTTPHandler(srv, nil, nil)
	h.SetMaxSessions(0)
	h.sessions.mu.Lock()
	got := h.sessions.maxSessions
	h.sessions.mu.Unlock()
	if got != defaultMaxSessions {
		t.Fatalf("SetMaxSessions(0) changed cap to %d, want default %d", got, defaultMaxSessions)
	}
	h.SetMaxSessions(5)
	h.sessions.mu.Lock()
	got = h.sessions.maxSessions
	h.sessions.mu.Unlock()
	if got != 5 {
		t.Fatalf("SetMaxSessions(5): cap=%d, want 5", got)
	}
}

func TestHTTP_NotificationReturns202(t *testing.T) {
	ts, _ := newTestHTTP(t, nil, nil)
	// first initialize
	resp, _ := doJSON(t, ts, "POST", "/mcp", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, "", "")
	sid := resp.Header.Get(sessionHeader)
	// send notification (no id)
	resp, _ = doJSON(t, ts, "POST", "/mcp", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, sid, "")
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("notification want 202, got %d", resp.StatusCode)
	}
}
