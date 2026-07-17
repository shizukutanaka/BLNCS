// Per-tool token-bucket rate limiter for the MCP server.
//
// Each tool can be individually limited; tools without a configured limit are
// always allowed. Callers receive a JSON-RPC error (-32000) when the bucket is
// empty, letting the client back off and retry rather than silently dropping.
package mcp

import (
	"sync"
	"time"
)

// RateLimit configures a token-bucket for a single tool.
// Rate is refill speed in tokens per second; Burst is the maximum capacity and
// also the initial fill level.
type RateLimit struct {
	Rate  float64 // tokens refilled per second (e.g. 10.0 → 10 calls/s steady state)
	Burst int     // maximum burst capacity (e.g. 20 → up to 20 back-to-back calls)
}

// ToolLimiter holds per-tool token buckets. The zero value is valid but useless;
// create with NewToolLimiter.
type ToolLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
}

type tokenBucket struct {
	rate     float64 // tokens/s
	burst    float64 // max tokens
	tokens   float64 // current token count
	lastFill time.Time
}

// NewToolLimiter creates a ToolLimiter from a per-tool RateLimit map.
// Entries with Rate ≤ 0 or Burst ≤ 0 are silently ignored (unlimited).
func NewToolLimiter(limits map[string]RateLimit) *ToolLimiter {
	tl := &ToolLimiter{buckets: make(map[string]*tokenBucket, len(limits))}
	now := time.Now()
	for name, rl := range limits {
		if rl.Rate <= 0 || rl.Burst <= 0 {
			continue
		}
		tl.buckets[name] = &tokenBucket{
			rate:     rl.Rate,
			burst:    float64(rl.Burst),
			tokens:   float64(rl.Burst), // start full
			lastFill: now,
		}
	}
	return tl
}

// Allow reports whether the named tool call is permitted, consuming one token
// if so. Tools without a configured bucket are always allowed. This method is
// safe for concurrent use.
func (tl *ToolLimiter) Allow(tool string) bool {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	b, ok := tl.buckets[tool]
	if !ok {
		return true
	}
	now := time.Now()
	elapsed := now.Sub(b.lastFill).Seconds()
	b.tokens += elapsed * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.lastFill = now
	if b.tokens < 1.0 {
		return false
	}
	b.tokens--
	return true
}

// SetToolLimiter installs a rate limiter on the server. Pass nil to remove the
// current limiter (all tools become unlimited). Safe to call at any time.
func (s *Server) SetToolLimiter(tl *ToolLimiter) {
	s.mu.Lock()
	s.limiter = tl
	s.mu.Unlock()
}
