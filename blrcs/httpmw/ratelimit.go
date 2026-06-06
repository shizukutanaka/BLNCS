// Rate limiting — per-client token-bucket middleware (zero-dependency).
//
// config.RateLimitRPS を実際に強制するためのミドルウェア。クライアント IP ごとに
// トークンバケットを持ち、超過時は 429 + Retry-After を返す。
package httpmw

import (
	"net/http"
	"strconv"
	"sync"
	"time"
)

// RateLimiter — クライアント IP 単位のトークンバケット。スレッドセーフ。
//
// rps<=0 は「無効 (全許可)」を意味する (config.RateLimitRPS=0 と整合)。
type RateLimiter struct {
	rps      float64
	burst    float64
	disabled bool

	mu      sync.Mutex
	buckets map[string]*tokenBucket
	now     func() time.Time // テスト差し替え用
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

// NewRateLimiter — rps トークン/秒で補充、burst を上限とするリミッタを構築。
// burst<=0 の場合は rps を burst として使う。rps<=0 は無効化。
func NewRateLimiter(rps, burst int) *RateLimiter {
	if burst <= 0 {
		burst = rps
	}
	return &RateLimiter{
		rps:      float64(rps),
		burst:    float64(burst),
		disabled: rps <= 0,
		buckets:  make(map[string]*tokenBucket),
		now:      time.Now,
	}
}

// Allow — key (通常クライアント IP) からの 1 リクエストを許可するか判定し、
// 許可時はトークンを 1 消費する。
func (rl *RateLimiter) Allow(key string) bool {
	if rl.disabled {
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := rl.now()
	b, ok := rl.buckets[key]
	if !ok {
		// 初回は burst 満タンから 1 消費。
		rl.buckets[key] = &tokenBucket{tokens: rl.burst - 1, last: now}
		return true
	}
	// 経過時間ぶん補充 (burst で頭打ち)。
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * rl.rps
		if b.tokens > rl.burst {
			b.tokens = rl.burst
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Middleware — クライアント IP ごとにレート制限を強制する HTTP ミドルウェア。
// httpchain.Chain.Use や httpmw.Chain にそのまま渡せる。
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.Allow(clientIP(r)) {
			retry := 1
			if rl.rps > 0 && rl.rps < 1 {
				retry = int(1/rl.rps) + 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(retry))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate_limited"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// GC — last アクセスが ttl より古いバケットを削除する。長期稼働サーバは
// 定期的に呼ぶこと (メモリ肥大防止)。
func (rl *RateLimiter) GC(ttl time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := rl.now().Add(-ttl)
	for k, b := range rl.buckets {
		if b.last.Before(cutoff) {
			delete(rl.buckets, k)
		}
	}
}
