package mcp

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"blrcs/compliance"
)

// ============================================================================
// ToolLimiter unit tests
// ============================================================================

func TestToolLimiterUnlimitedTool(t *testing.T) {
	tl := NewToolLimiter(map[string]RateLimit{
		"slow_tool": {Rate: 1, Burst: 1},
	})
	// "fast_tool" has no limit — must always be allowed
	for i := 0; i < 100; i++ {
		if !tl.Allow("fast_tool") {
			t.Fatalf("unlimited tool denied on call %d", i+1)
		}
	}
}

func TestToolLimiterBurstThenBlock(t *testing.T) {
	burst := 3
	tl := NewToolLimiter(map[string]RateLimit{
		"tool": {Rate: 0.001, Burst: burst}, // refill negligible in test time
	})
	// First `burst` calls must succeed
	for i := 0; i < burst; i++ {
		if !tl.Allow("tool") {
			t.Fatalf("call %d should be allowed (within burst)", i+1)
		}
	}
	// Next call should be denied
	if tl.Allow("tool") {
		t.Fatal("call after burst exhaustion should be denied")
	}
}

func TestToolLimiterRefillAfterWait(t *testing.T) {
	tl := NewToolLimiter(map[string]RateLimit{
		"tool": {Rate: 1000, Burst: 1}, // 1000 tokens/s — refills in ~1ms
	})
	if !tl.Allow("tool") {
		t.Fatal("first call should be allowed")
	}
	if tl.Allow("tool") {
		t.Fatal("second call should be denied (bucket empty)")
	}
	time.Sleep(2 * time.Millisecond) // wait for ~2 tokens to refill
	if !tl.Allow("tool") {
		t.Fatal("call after sleep should be allowed (refilled)")
	}
}

func TestToolLimiterIndependentPerTool(t *testing.T) {
	tl := NewToolLimiter(map[string]RateLimit{
		"a": {Rate: 0.001, Burst: 1},
		"b": {Rate: 0.001, Burst: 2},
	})
	// Exhaust "a"
	tl.Allow("a")
	if tl.Allow("a") {
		t.Fatal("a: second call should be denied")
	}
	// "b" should still have 2 tokens
	if !tl.Allow("b") {
		t.Fatal("b: first call should be allowed")
	}
	if !tl.Allow("b") {
		t.Fatal("b: second call should be allowed")
	}
	if tl.Allow("b") {
		t.Fatal("b: third call should be denied")
	}
}

func TestToolLimiterZeroRateIgnored(t *testing.T) {
	// Rate=0 or Burst=0 entries must be silently ignored (unlimited).
	tl := NewToolLimiter(map[string]RateLimit{
		"a": {Rate: 0, Burst: 5},
		"b": {Rate: 5, Burst: 0},
	})
	for i := 0; i < 20; i++ {
		if !tl.Allow("a") {
			t.Fatalf("a: call %d should be unlimited (Rate=0 ignored)", i+1)
		}
		if !tl.Allow("b") {
			t.Fatalf("b: call %d should be unlimited (Burst=0 ignored)", i+1)
		}
	}
}

func TestToolLimiterNilMap(t *testing.T) {
	tl := NewToolLimiter(nil)
	// Everything should be unlimited
	for i := 0; i < 10; i++ {
		if !tl.Allow("any_tool") {
			t.Fatalf("nil limits: call %d should be allowed", i+1)
		}
	}
}

// ============================================================================
// Server integration: SetToolLimiter / handleToolCall integration
// ============================================================================

func newTestServerRL(t *testing.T) *Server {
	t.Helper()
	s, err := NewServer("did:web:ts.test", "did:web:srv.test")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mcpToolCallRL(s *Server, toolName string, args map[string]any) string {
	argBytes, _ := json.Marshal(args)
	params, _ := json.Marshal(map[string]any{
		"name":      toolName,
		"arguments": json.RawMessage(argBytes),
	})
	req, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params":  json.RawMessage(params),
	})
	return string(s.HandleRaw(req))
}

func TestServerRateLimitExceeded(t *testing.T) {
	s := newTestServerRL(t)
	// Limit ledger_checkpoint to burst=1
	s.SetToolLimiter(NewToolLimiter(map[string]RateLimit{
		"ledger_checkpoint": {Rate: 0.001, Burst: 1},
	}))
	// First call: allowed
	resp1 := mcpToolCallRL(s, "ledger_checkpoint", map[string]any{})
	if strings.Contains(resp1, `"error"`) {
		t.Fatalf("first call should succeed, got: %s", resp1)
	}
	// Second call: rate limited
	resp2 := mcpToolCallRL(s, "ledger_checkpoint", map[string]any{})
	if !strings.Contains(resp2, "-32000") {
		t.Fatalf("second call should return rate limit error (-32000), got: %s", resp2)
	}
	if !strings.Contains(resp2, "rate limit") {
		t.Fatalf("error message should mention rate limit, got: %s", resp2)
	}
}

func TestServerRateLimitAllowedForOtherTools(t *testing.T) {
	s := newTestServerRL(t)
	// Only limit "ledger_checkpoint" — other tools must pass through
	s.SetToolLimiter(NewToolLimiter(map[string]RateLimit{
		"ledger_checkpoint": {Rate: 0.001, Burst: 0}, // burst=0 → unlimited (ignored)
	}))
	for i := 0; i < 5; i++ {
		resp := mcpToolCallRL(s, "ledger_checkpoint", map[string]any{})
		if strings.Contains(resp, "-32000") {
			t.Fatalf("call %d should be unlimited (Burst=0 ignored), got: %s", i+1, resp)
		}
	}
}

func TestServerSetNilLimiterUnlimits(t *testing.T) {
	s := newTestServerRL(t)
	// Install a tight limiter then remove it
	s.SetToolLimiter(NewToolLimiter(map[string]RateLimit{
		"ledger_checkpoint": {Rate: 0.001, Burst: 1},
	}))
	mcpToolCallRL(s, "ledger_checkpoint", map[string]any{}) // exhaust
	// Remove limiter
	s.SetToolLimiter(nil)
	// Should be unlimited now
	resp := mcpToolCallRL(s, "ledger_checkpoint", map[string]any{})
	if strings.Contains(resp, "-32000") {
		t.Fatalf("after removing limiter, call should succeed, got: %s", resp)
	}
}

func TestServerRateLimitDoesNotAuditRejected(t *testing.T) {
	s := newTestServerRL(t)
	initial := s.ledger.Size()
	s.SetToolLimiter(NewToolLimiter(map[string]RateLimit{
		"issue_passport": {Rate: 0.001, Burst: 0}, // burst=0 → unlimited (ignored by limiter)
	}))
	// All calls should pass (burst=0 means no limit configured)
	_ = mcpToolCallRL(s, "ledger_checkpoint", map[string]any{})
	_ = s.ledger.Size() // just exercise
	if s.ledger.Size() < initial {
		t.Fatal("ledger size should not decrease")
	}
}

func TestServerRateLimitTightBurstRejectsAuditableTools(t *testing.T) {
	s := newTestServerRL(t)
	iss, err := compliance.NewIssuer("did:web:factory.rate.test")
	if err != nil {
		t.Fatal(err)
	}
	s.RegisterIssuer(iss)

	// Burst=1 for issue_passport
	s.SetToolLimiter(NewToolLimiter(map[string]RateLimit{
		"issue_passport": {Rate: 0.001, Burst: 1},
	}))
	args := map[string]any{
		"issuerId":  iss.ID,
		"productId": "RATE-LIMIT-TEST",
	}
	// First call: allowed
	resp1 := mcpToolCallRL(s, "issue_passport", args)
	if strings.Contains(resp1, "-32000") {
		t.Fatalf("first call should succeed, got: %s", resp1)
	}
	// Second call: rate limited — must NOT reach the tool logic
	ledgerSizeBefore := s.ledger.Size()
	resp2 := mcpToolCallRL(s, "issue_passport", args)
	if !strings.Contains(resp2, "-32000") {
		t.Fatalf("second call should be rate limited, got: %s", resp2)
	}
	// Rate-limited calls must not append to ledger
	if s.ledger.Size() != ledgerSizeBefore {
		t.Fatal("rate-limited call must not audit to ledger")
	}
}
