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
	"strings"
	"testing"
	"time"

	"blrcs/compliance"
)

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
