package httpmw

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiterBurstThenBlock(t *testing.T) {
	rl := NewRateLimiter(10, 3) // 10 rps, burst 3
	frozen := time.Now()
	rl.now = func() time.Time { return frozen } // freeze time → no refill

	for i := 0; i < 3; i++ {
		if !rl.Allow("1.2.3.4") {
			t.Fatalf("request %d within burst should be allowed", i)
		}
	}
	if rl.Allow("1.2.3.4") {
		t.Fatal("4th request beyond burst should be blocked")
	}
	// A different client has its own bucket.
	if !rl.Allow("5.6.7.8") {
		t.Fatal("different client should be allowed")
	}
}

func TestRateLimiterRefill(t *testing.T) {
	rl := NewRateLimiter(10, 1) // 10 rps, burst 1
	cur := time.Now()
	rl.now = func() time.Time { return cur }

	if !rl.Allow("ip") {
		t.Fatal("first allowed")
	}
	if rl.Allow("ip") {
		t.Fatal("second immediately should block (burst 1)")
	}
	cur = cur.Add(200 * time.Millisecond) // 0.2s * 10rps = 2 tokens
	if !rl.Allow("ip") {
		t.Fatal("after refill should be allowed")
	}
}

func TestRateLimiterDisabled(t *testing.T) {
	rl := NewRateLimiter(0, 0) // disabled
	for i := 0; i < 1000; i++ {
		if !rl.Allow("ip") {
			t.Fatal("disabled limiter must allow everything")
		}
	}
}

func TestRateLimiterMiddleware429(t *testing.T) {
	rl := NewRateLimiter(1, 1)
	frozen := time.Now()
	rl.now = func() time.Time { return frozen }
	h := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec1 := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "9.9.9.9:1234"
	h.ServeHTTP(rec1, req)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first request: %d", rec1.Code)
	}
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: want 429, got %d", rec2.Code)
	}
	if rec2.Header().Get("Retry-After") == "" {
		t.Error("429 should set Retry-After")
	}
}

func TestRateLimiterGC(t *testing.T) {
	rl := NewRateLimiter(10, 3)
	base := time.Now()
	rl.now = func() time.Time { return base }
	rl.Allow("stale")
	// Advance the clock and GC anything idle > 1m.
	rl.now = func() time.Time { return base.Add(2 * time.Minute) }
	rl.GC(time.Minute)
	rl.mu.Lock()
	_, exists := rl.buckets["stale"]
	rl.mu.Unlock()
	if exists {
		t.Error("stale bucket should have been GC'd")
	}
}

func TestStartGC(t *testing.T) {
	rl := NewRateLimiter(100, 200)
	stop := rl.StartGC(50*time.Millisecond, 10*time.Millisecond)
	if stop == nil {
		t.Fatal("StartGC returned nil stop func")
	}
	// Let the GC goroutine fire at least once.
	time.Sleep(100 * time.Millisecond)
	stop() // must not deadlock or panic
}

func TestStartGCDisabled(t *testing.T) {
	// Zero interval → returns no-op immediately
	rl := NewRateLimiter(100, 200)
	stop := rl.StartGC(0, time.Minute)
	if stop == nil {
		t.Fatal("StartGC(0) returned nil")
	}
	stop() // must not panic
}
