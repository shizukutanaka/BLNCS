package mcp

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"blrcs/storage"
)

// ============================================================================
// handleDelete — missing session header → 400
// ============================================================================

func TestHTTPDeleteNoSessionHeader(t *testing.T) {
	srv, _, _ := setupServer(t)
	h := NewHTTPHandler(srv, nil, nil)
	ts := httptest.NewServer(h)
	defer ts.Close()
	req, _ := http.NewRequest("DELETE", ts.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("DELETE without sid: want 400, got %d", resp.StatusCode)
	}
}

// ============================================================================
// handleGet — unknown session → 404
// ============================================================================

func TestHTTPGetUnknownSession(t *testing.T) {
	srv, _, _ := setupServer(t)
	h := NewHTTPHandler(srv, nil, nil)
	ts := httptest.NewServer(h)
	defer ts.Close()
	req, _ := http.NewRequest("GET", ts.URL, nil)
	req.Header.Set(sessionHeader, "no-such-session")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET unknown session: want 404, got %d", resp.StatusCode)
	}
}

// ============================================================================
// touch — session aged past sessionIdleTimeout in touch() itself
// ============================================================================

func TestTouchAgedSession(t *testing.T) {
	s := &sessionStore{data: make(map[string]*sessionEntry)}
	s.create("aged", "user1")
	s.mu.Lock()
	s.data["aged"].lastSeen = time.Now().Add(-2 * sessionIdleTimeout)
	s.mu.Unlock()
	if s.touch("aged", "user1") {
		t.Error("aged session should return false from touch")
	}
	s.mu.Lock()
	_, exists := s.data["aged"]
	s.mu.Unlock()
	if exists {
		t.Error("touch should delete expired session")
	}
}

// ============================================================================
// NewServerWithStorage — failure when tsID is invalid
// ============================================================================

func TestNewServerWithStorageInvalidTSID(t *testing.T) {
	store := storage.NewMemoryStorage()
	defer store.Close()
	_, err := NewServerWithStorage("", "did:web:srv", store)
	if err == nil {
		t.Fatal("empty tsID should fail")
	}
}

// ============================================================================
// Serve — empty line is skipped without error
// ============================================================================

func TestServeSkipsEmptyLines(t *testing.T) {
	srv, _, _ := setupServer(t)
	input := "\n\n" + `{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}` + "\n"
	var out bytes.Buffer
	if err := srv.Serve(strings.NewReader(input), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"result"`) {
		t.Errorf("ping after empty lines: %s", out.String())
	}
}

// ============================================================================
// handleToolCall — params is a JSON string, not object → bad params error
// ============================================================================

func TestHandleToolCallBadParamsType(t *testing.T) {
	srv, _, _ := setupServer(t)
	// "params" is a JSON string → json.Unmarshal into toolCallParams fails
	raw := srv.HandleRaw([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":"not-object"}`))
	if !strings.Contains(string(raw), `"error"`) {
		t.Errorf("bad params type should return error: %s", raw)
	}
}

// ============================================================================
// toolIssuePassport error paths
// ============================================================================

func TestToolIssuePassportBadJSONArgs(t *testing.T) {
	srv, _, _ := setupServer(t)
	// "arguments" is a JSON string → json.Unmarshal into struct fails inside tool
	raw := srv.HandleRaw([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"issue_passport","arguments":"bad"}}`))
	if !strings.Contains(string(raw), "isError") {
		t.Errorf("bad args: %s", raw)
	}
}

func TestToolIssuePassportNegativeCarbon(t *testing.T) {
	srv, iss, _ := setupServer(t)
	resp := mcpToolCall(t, srv, "issue_passport", map[string]any{
		"issuerId":     iss.ID,
		"productId":    "TEST-001",
		"carbonKgCO2e": -5.0,
	})
	if !strings.Contains(resp, "isError") {
		t.Errorf("negative carbon: %s", resp)
	}
}

func TestToolIssuePassportBadRecyclability(t *testing.T) {
	srv, iss, _ := setupServer(t)
	resp := mcpToolCall(t, srv, "issue_passport", map[string]any{
		"issuerId":      iss.ID,
		"productId":     "TEST-002",
		"recyclability": 200.0,
	})
	if !strings.Contains(resp, "isError") {
		t.Errorf("recyclability out of range: %s", resp)
	}
}

// TestToolIssuePassportRecyclabilityFractionRange asserts the validator enforces
// the canonical [0,1] fraction range (matching compliance.PassportClaim and the
// advertised inputSchema), rejecting values > 1 that the old 0..100 bound wrongly
// admitted — which would otherwise sign nonsensical "8500%" recyclability into a
// permanent credential. A valid fraction (0.85) must still pass.
func TestToolIssuePassportRecyclabilityFractionRange(t *testing.T) {
	srv, iss, _ := setupServer(t)

	// 85 (a percentage, not a fraction) must now be rejected.
	resp := mcpToolCall(t, srv, "issue_passport", map[string]any{
		"issuerId":      iss.ID,
		"productId":     "TEST-FRAC-1",
		"recyclability": 85.0,
	})
	if !strings.Contains(resp, "isError") {
		t.Errorf("recyclability=85 (out of [0,1]) should be rejected: %s", resp)
	}

	// A genuine fraction must still succeed.
	resp = mcpToolCall(t, srv, "issue_passport", map[string]any{
		"issuerId":      iss.ID,
		"productId":     "TEST-FRAC-2",
		"recyclability": 0.85,
	})
	if strings.Contains(resp, `"isError":true`) {
		t.Errorf("recyclability=0.85 (valid fraction) should be accepted: %s", resp)
	}
}

func TestToolIssuePassportEmptyProductID(t *testing.T) {
	srv, iss, _ := setupServer(t)
	// Known issuer but empty productId → Issue() returns ErrEmptyProductID
	resp := mcpToolCall(t, srv, "issue_passport", map[string]any{
		"issuerId":  iss.ID,
		"productId": "",
	})
	if !strings.Contains(resp, "isError") {
		t.Errorf("empty productId: %s", resp)
	}
}

// ============================================================================
// toolVerifyPassport error paths
// ============================================================================

func TestToolVerifyPassportBadJSONArgs(t *testing.T) {
	srv, _, _ := setupServer(t)
	raw := srv.HandleRaw([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"verify_passport","arguments":"bad"}}`))
	if !strings.Contains(string(raw), "isError") {
		t.Errorf("bad args: %s", raw)
	}
}

func TestToolVerifyPassportBadPublicKey(t *testing.T) {
	srv, _, _ := setupServer(t)
	// Valid credential JSON (empty object) but wrong-size key → "bad public key"
	resp := mcpToolCall(t, srv, "verify_passport", map[string]any{
		"credentialJson":     "{}",
		"issuerPublicKeyB64": base64.StdEncoding.EncodeToString([]byte("too-short")),
	})
	if !strings.Contains(resp, "isError") {
		t.Errorf("bad key: %s", resp)
	}
}

// ============================================================================
// toolAttestRange error paths
// ============================================================================

func TestToolAttestRangeBadJSONArgs(t *testing.T) {
	srv, _, _ := setupServer(t)
	raw := srv.HandleRaw([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"attest_range","arguments":"bad"}}`))
	if !strings.Contains(string(raw), "isError") {
		t.Errorf("bad args: %s", raw)
	}
}

func TestToolAttestRangeMinGtMax(t *testing.T) {
	srv, _, att := setupServer(t)
	resp := mcpToolCall(t, srv, "attest_range", map[string]any{
		"attesterId": att.ID,
		"value":      5.0,
		"min":        10.0,
		"max":        1.0,
		"name":       "temp",
	})
	if !strings.Contains(resp, "isError") {
		t.Errorf("min > max: %s", resp)
	}
}

// ============================================================================
// toolVerifyRange error paths
// ============================================================================

func TestToolVerifyRangeBadJSONArgs(t *testing.T) {
	srv, _, _ := setupServer(t)
	raw := srv.HandleRaw([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"verify_range","arguments":"bad"}}`))
	if !strings.Contains(string(raw), "isError") {
		t.Errorf("bad args: %s", raw)
	}
}

func TestToolVerifyRangeBadAttesterKey(t *testing.T) {
	srv, _, _ := setupServer(t)
	resp := mcpToolCall(t, srv, "verify_range", map[string]any{
		"proofJson":            "{}",
		"attesterPublicKeyB64": base64.StdEncoding.EncodeToString([]byte("short")),
	})
	if !strings.Contains(resp, "isError") {
		t.Errorf("bad attester key: %s", resp)
	}
}

// ============================================================================
// toolRegisterSCITT error paths
// ============================================================================

func TestToolRegisterSCITTBadJSONArgs(t *testing.T) {
	srv, _, _ := setupServer(t)
	raw := srv.HandleRaw([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"register_scitt","arguments":"bad"}}`))
	if !strings.Contains(string(raw), "isError") {
		t.Errorf("bad args: %s", raw)
	}
}

func TestToolRegisterSCITTDefaultContentType(t *testing.T) {
	srv, iss, _ := setupServer(t)
	// No contentType field → defaults to "application/octet-stream"
	resp := mcpToolCall(t, srv, "register_scitt", map[string]any{
		"issuerId": iss.ID,
		"subject":  "test-subj",
		"payload":  "hello",
	})
	if strings.Contains(resp, `"isError":true`) {
		t.Errorf("default content type failed: %s", resp)
	}
}

// ============================================================================
// toolGetSCITTReceipt — bad JSON args
// ============================================================================

func TestToolGetSCITTReceiptBadJSONArgs(t *testing.T) {
	srv, _, _ := setupServer(t)
	raw := srv.HandleRaw([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_scitt_receipt","arguments":"bad"}}`))
	if !strings.Contains(string(raw), "isError") {
		t.Errorf("bad args: %s", raw)
	}
}

// ============================================================================
// TokenBucketLimiter — token cap at burst (b.tokens > l.burst → capped)
// ============================================================================

func TestTokenBucketCapAtBurst(t *testing.T) {
	lim := NewTokenBucketLimiter(1000, 3) // high rate, burst=3
	// Consume 1 token (first Allow on a new principal)
	lim.Allow("tester")
	// Artificially backdate the last-seen time so many tokens accumulate
	lim.mu.Lock()
	lim.buckets["tester"].last = time.Now().Add(-100 * time.Second)
	lim.mu.Unlock()
	// Next Allow should add 100*1000=100000 tokens but cap at burst=3
	if !lim.Allow("tester") {
		t.Error("should be allowed")
	}
	lim.mu.Lock()
	tokens := lim.buckets["tester"].tokens
	lim.mu.Unlock()
	if tokens > lim.burst {
		t.Errorf("tokens %v exceeds burst %v after cap", tokens, lim.burst)
	}
}

// ============================================================================
// toolVerifyPassport — bad credential JSON (valid key, bad cred)
// (exercises json.Unmarshal([]byte(in.CredentialJson), &cred) failure path)
// ============================================================================

func TestToolVerifyPassportBadCredJSON(t *testing.T) {
	srv, _, _ := setupServer(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	resp := mcpToolCall(t, srv, "verify_passport", map[string]any{
		"credentialJson":     "{bad json",
		"issuerPublicKeyB64": base64.StdEncoding.EncodeToString([]byte(pub)),
	})
	if !strings.Contains(resp, "isError") {
		t.Errorf("bad cred json: %s", resp)
	}
}
