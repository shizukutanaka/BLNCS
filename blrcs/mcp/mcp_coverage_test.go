package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"blrcs/storage"
)

// ============================================================================
// helpers (prefixed to avoid collision with mcp_test.go)
// ============================================================================

func mcpCall(t *testing.T, srv *Server, method string, params any) string {
	t.Helper()
	p, _ := json.Marshal(params)
	req := map[string]any{
		"jsonrpc": "2.0",
		"id":      99,
		"method":  method,
		"params":  json.RawMessage(p),
	}
	raw, _ := json.Marshal(req)
	return string(srv.HandleRaw(raw))
}

func mcpToolCall(t *testing.T, srv *Server, tool string, args map[string]any) string {
	t.Helper()
	return mcpCall(t, srv, "tools/call", map[string]any{
		"name":      tool,
		"arguments": args,
	})
}

// ============================================================================
// Protocol — ping
// ============================================================================

func TestPingMethod(t *testing.T) {
	srv, _, _ := setupServer(t)
	resp := mcpCall(t, srv, "ping", nil)
	if !strings.Contains(resp, `"result"`) {
		t.Errorf("ping result: %s", resp)
	}
}

// ============================================================================
// Tool — ledger_checkpoint
// ============================================================================

func TestCheckpointEmpty(t *testing.T) {
	srv, _, _ := setupServer(t)
	resp := mcpToolCall(t, srv, "ledger_checkpoint", map[string]any{})
	if !strings.Contains(resp, "size") {
		t.Errorf("checkpoint: %s", resp)
	}
}

func TestCheckpointAfterRegister(t *testing.T) {
	srv, iss, _ := setupServer(t)
	mcpToolCall(t, srv, "register_scitt", map[string]any{
		"issuerDID": iss.ID, "subject": "s", "contentType": "c", "payload": "p",
	})
	resp := mcpToolCall(t, srv, "ledger_checkpoint", map[string]any{})
	if !strings.Contains(resp, "size") {
		t.Errorf("after register: %s", resp)
	}
}

// ============================================================================
// Tool — get_scitt_receipt
// ============================================================================

func TestGetReceiptValid(t *testing.T) {
	srv, iss, _ := setupServer(t)
	mcpToolCall(t, srv, "register_scitt", map[string]any{
		"issuerDID": iss.ID, "subject": "r", "contentType": "c", "payload": "p",
	})
	resp := mcpToolCall(t, srv, "get_scitt_receipt", map[string]any{"leafIndex": 0})
	if strings.Contains(resp, `"error"`) {
		t.Errorf("receipt error: %s", resp)
	}
}

func TestGetReceiptInvalidIndex(t *testing.T) {
	srv, _, _ := setupServer(t)
	resp := mcpToolCall(t, srv, "get_scitt_receipt", map[string]any{"leafIndex": 999})
	if !strings.Contains(resp, "isError") && !strings.Contains(resp, "error") {
		t.Errorf("invalid index: %s", resp)
	}
}

// ============================================================================
// Tool error paths
// ============================================================================

func TestIssuePassportNoProductId(t *testing.T) {
	srv, _, _ := setupServer(t)
	resp := mcpToolCall(t, srv, "issue_passport", map[string]any{})
	if !strings.Contains(resp, "isError") && !strings.Contains(resp, "error") {
		t.Errorf("missing productId: %s", resp)
	}
}

func TestVerifyBadCredential(t *testing.T) {
	srv, _, _ := setupServer(t)
	resp := mcpToolCall(t, srv, "verify_passport", map[string]any{"credential": "bad"})
	if !strings.Contains(resp, "isError") && !strings.Contains(resp, "error") {
		t.Errorf("bad cred: %s", resp)
	}
}

func TestAttestMissingArgs(t *testing.T) {
	srv, _, _ := setupServer(t)
	resp := mcpToolCall(t, srv, "attest_range", map[string]any{})
	if !strings.Contains(resp, "isError") && !strings.Contains(resp, "error") {
		t.Errorf("missing attest args: %s", resp)
	}
}

func TestVerifyRangeBadInput(t *testing.T) {
	srv, _, _ := setupServer(t)
	resp := mcpToolCall(t, srv, "verify_range", map[string]any{"proof": "bad"})
	if !strings.Contains(resp, "isError") && !strings.Contains(resp, "error") {
		t.Errorf("bad proof: %s", resp)
	}
}

func TestRegisterSCITTMissing(t *testing.T) {
	srv, _, _ := setupServer(t)
	resp := mcpToolCall(t, srv, "register_scitt", map[string]any{})
	if !strings.Contains(resp, "isError") && !strings.Contains(resp, "error") {
		t.Errorf("missing fields: %s", resp)
	}
}

func TestUnknownToolDispatch(t *testing.T) {
	srv, _, _ := setupServer(t)
	resp := mcpToolCall(t, srv, "no_such_tool", map[string]any{})
	if !strings.Contains(resp, "unknown") {
		t.Errorf("unknown tool: %s", resp)
	}
}

func TestToolCallNoName(t *testing.T) {
	srv, _, _ := setupServer(t)
	resp := mcpCall(t, srv, "tools/call", map[string]any{"arguments": map[string]any{}})
	if !strings.Contains(resp, "isError") && !strings.Contains(resp, "error") {
		t.Errorf("no name: %s", resp)
	}
}

// ============================================================================
// HTTP — POST / auth / rate limit
// ============================================================================

func initHTTP(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{"protocolVersion": "2024-11-05",
			"clientInfo":   map[string]any{"name": "t", "version": "1"},
			"capabilities": map[string]any{}},
	})
	resp, err := http.Post(ts.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.Header.Get("Mcp-Session-Id")
}

func TestHTTPPostInit(t *testing.T) {
	srv, _, _ := setupServer(t)
	h := NewHTTPHandler(srv, nil, nil)
	ts := httptest.NewServer(h)
	defer ts.Close()
	sid := initHTTP(t, ts)
	if sid == "" {
		t.Error("no session ID")
	}
}

func TestHTTPPostToolsListWithSession(t *testing.T) {
	srv, _, _ := setupServer(t)
	h := NewHTTPHandler(srv, nil, nil)
	ts := httptest.NewServer(h)
	defer ts.Close()
	sid := initHTTP(t, ts)

	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": map[string]any{},
	})
	req, _ := http.NewRequest("POST", ts.URL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Mcp-Session-Id", sid)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("tools/list: %d", resp.StatusCode)
	}
}

func TestHTTPPostBadJSON(t *testing.T) {
	srv, _, _ := setupServer(t)
	h := NewHTTPHandler(srv, nil, nil)
	ts := httptest.NewServer(h)
	defer ts.Close()
	resp, err := http.Post(ts.URL, "application/json", strings.NewReader("{bad"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("bad JSON: %d", resp.StatusCode)
	}
}

func TestHTTPGetNoSession(t *testing.T) {
	srv, _, _ := setupServer(t)
	h := NewHTTPHandler(srv, nil, nil)
	ts := httptest.NewServer(h)
	defer ts.Close()
	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		t.Error("GET without session should not be 200")
	}
}

func TestHTTPDeleteSession(t *testing.T) {
	srv, _, _ := setupServer(t)
	h := NewHTTPHandler(srv, nil, nil)
	ts := httptest.NewServer(h)
	defer ts.Close()
	sid := initHTTP(t, ts)
	if sid == "" {
		t.Skip("no session")
	}
	req, _ := http.NewRequest("DELETE", ts.URL, nil)
	req.Header.Set("Mcp-Session-Id", sid)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		t.Errorf("DELETE: %d", resp.StatusCode)
	}
}

func TestHTTPAuthReject(t *testing.T) {
	srv, _, _ := setupServer(t)
	auth := &BearerTokenAuth{Tokens: map[string]string{"good": "a"}}
	h := NewHTTPHandler(srv, auth, nil)
	ts := httptest.NewServer(h)
	defer ts.Close()
	// No auth
	resp, err := http.Post(ts.URL, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("no auth: %d", resp.StatusCode)
	}
}

func TestHTTPAuthAccept(t *testing.T) {
	srv, _, _ := setupServer(t)
	auth := &BearerTokenAuth{Tokens: map[string]string{"tok": "agent"}}
	h := NewHTTPHandler(srv, auth, nil)
	ts := httptest.NewServer(h)
	defer ts.Close()
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{"protocolVersion": "2024-11-05",
			"clientInfo":   map[string]any{"name": "t", "version": "1"},
			"capabilities": map[string]any{}},
	})
	req, _ := http.NewRequest("POST", ts.URL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Errorf("auth accept: %d %s", resp.StatusCode, b)
	}
}

func TestHTTPMethodNotAllowed(t *testing.T) {
	srv, _, _ := setupServer(t)
	h := NewHTTPHandler(srv, nil, nil)
	ts := httptest.NewServer(h)
	defer ts.Close()
	req, _ := http.NewRequest("PUT", ts.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 405 {
		t.Errorf("PUT: %d", resp.StatusCode)
	}
}

func TestSetMaxBody(t *testing.T) {
	srv, _, _ := setupServer(t)
	h := NewHTTPHandler(srv, nil, nil)
	h.SetMaxBody(50)
	ts := httptest.NewServer(h)
	defer ts.Close()
	big := bytes.Repeat([]byte("x"), 200)
	resp, err := http.Post(ts.URL, "application/json", bytes.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		t.Error("oversized should not succeed")
	}
}

// ============================================================================
// NewServerWithStorage
// ============================================================================

func TestNewServerWithStorageCustom(t *testing.T) {
	store := storage.NewMemoryStorage()
	defer store.Close()
	srv, err := NewServerWithStorage("did:web:ts", "did:web:srv", store)
	if err != nil {
		t.Fatal(err)
	}
	if srv.Ledger() == nil {
		t.Error("ledger nil")
	}
}

// ============================================================================
// HandleRaw edge cases
// ============================================================================

func TestHandleRawEmpty(t *testing.T) {
	srv, _, _ := setupServer(t)
	resp := srv.HandleRaw([]byte{})
	if len(resp) == 0 {
		t.Error("empty body should return error")
	}
}

func TestHandleRawNotification(t *testing.T) {
	srv, _, _ := setupServer(t)
	raw := []byte(`{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`)
	_ = srv.HandleRaw(raw)
	// no crash — notifications return nil/empty
}

// ============================================================================
// Stdio smoke
// ============================================================================

func TestStdioPingRoundTrip(t *testing.T) {
	srv, _, _ := setupServer(t)
	input := `{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}` + "\n"
	var out bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- srv.Serve(strings.NewReader(input), &out) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
	}
	if !strings.Contains(out.String(), `"result"`) {
		t.Errorf("ping response: %s", out.String())
	}
}

// ============================================================================
// Rate limiter construction
// ============================================================================

func TestNewTokenBucketLimiter(t *testing.T) {
	lim := NewTokenBucketLimiter(10, 20)
	if lim == nil {
		t.Fatal("nil limiter")
	}
}
