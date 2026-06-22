// Package httpmw — BLRCS HTTP middleware
//
// Apple サーバ実践:
//   - 全リクエストに request-id 付与 (debugging/tracing)
//   - panic で goroutine が死ぬのを防ぐ
//   - 構造化 access log
//   - 機密データを含まない安全な error response
//
// 全 middleware は composable:
//
//	handler := httpmw.Recovery(httpmw.RequestID(httpmw.AccessLog(myHandler)))
//
// または:
//
//	chain := httpmw.Chain(myHandler, httpmw.AccessLog, httpmw.RequestID, httpmw.Recovery)
package httpmw

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"time"

	"blrcs/telemetry"
)

// ============================================================================
// Recovery — panic 復帰 (本番必須)
// ============================================================================

// Recovery — panic を捕捉して 500 を返す middleware
//
// stack trace は server log に出力、クライアントには漏らさない。
// telemetry.Default() で recovery counter / error span を発行。
func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w}
		defer func() {
			if rec := recover(); rec != nil {
				// stack trace を server log に
				stack := debug.Stack()
				rid := RequestIDFromContext(r.Context())
				telemetry.Default().Error("http.panic_recovered",
					slog.String("path", r.URL.Path),
					slog.String("method", r.Method),
					slog.String("requestId", rid),
					slog.Any("panic", rec),
					slog.String("stack", string(stack)),
				)
				telemetry.Default().Counter("http.panics_recovered").Inc()
				// クライアントには汎用 500 のみ (機密漏洩防止)
				if !headerWritten(sw) {
					sw.Header().Set("Content-Type", "application/json")
					sw.WriteHeader(http.StatusInternalServerError)
					_, _ = sw.Write([]byte(`{"error":"internal_server_error","requestId":"` + rid + `"}`))
				}
			}
		}()
		next.ServeHTTP(sw, r)
	})
}

// statusWriter — ResponseWriter wrapper recording whether WriteHeader was called
type statusWriter struct {
	http.ResponseWriter
	written bool
	status  int
}

func (s *statusWriter) WriteHeader(code int) {
	s.written = true
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	s.written = true
	return s.ResponseWriter.Write(b)
}

// headerWritten — ResponseWriter が既に status を書いたか判定
func headerWritten(w http.ResponseWriter) bool {
	if sw, ok := w.(*statusWriter); ok {
		return sw.written
	}
	return false
}

// ============================================================================
// RequestID — 全リクエストに ID 付与 (X-Request-ID ヘッダ)
// ============================================================================

type requestIDKey struct{}

// RequestID — リクエスト ID を context と response header に注入
//
// 既存の X-Request-ID ヘッダが client から送られていれば尊重 (一部 frontend proxy)
// なければサーバ側で生成
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Sanitize any client-supplied X-Request-ID: it is echoed into the
		// response header and concatenated into JSON error bodies, so restrict it
		// to a safe charset and bounded length (else a value like `"},"x":"`
		// would corrupt the error JSON / log lines).
		rid := sanitizeRequestID(r.Header.Get("X-Request-ID"))
		if rid == "" {
			b := make([]byte, 8)
			_, _ = rand.Read(b)
			rid = hex.EncodeToString(b)
		}
		w.Header().Set("X-Request-ID", rid)
		ctx := context.WithValue(r.Context(), requestIDKey{}, rid)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// sanitizeRequestID keeps only safe identifier characters (alphanumeric, '-',
// '_', '.') and caps the length at 128. Returns "" if nothing survives.
func sanitizeRequestID(s string) string {
	if len(s) > 128 {
		s = s[:128]
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.':
			out = append(out, c)
		}
	}
	return string(out)
}

// RequestIDFromContext — handler 内から request ID を取得
func RequestIDFromContext(ctx context.Context) string {
	if rid, ok := ctx.Value(requestIDKey{}).(string); ok {
		return rid
	}
	return ""
}

// ============================================================================
// AccessLog — 構造化 access log
// ============================================================================

// loggingResponseWriter — status code 取得用ラッパ
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
	bytes      int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func (lrw *loggingResponseWriter) Write(b []byte) (int, error) {
	if lrw.statusCode == 0 {
		lrw.statusCode = http.StatusOK
	}
	n, err := lrw.ResponseWriter.Write(b)
	lrw.bytes += n
	return n, err
}

// AccessLog — 構造化 HTTP アクセスログ + telemetry counter/histogram
//
// 出力例 (slog text):
//
//	time=... msg=http.access method=POST path=/mcp status=200 elapsed=12ms requestId=abc
//
// telemetry に http.requests.total と http.duration_ms を自動記録
func AccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lrw := &loggingResponseWriter{ResponseWriter: w}
		next.ServeHTTP(lrw, r)
		elapsed := time.Since(start)

		rid := RequestIDFromContext(r.Context())
		status := lrw.statusCode
		if status == 0 {
			status = http.StatusOK
		}

		telemetry.Default().Info("http.access",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", status),
			slog.Duration("elapsed", elapsed),
			slog.Int("bytes", lrw.bytes),
			slog.String("requestId", rid),
			slog.String("remote", clientIP(r)),
		)
		telemetry.Default().Counter(fmt.Sprintf("http.requests.%d", status/100)).Inc()
		telemetry.Default().Histogram("http.duration_ms").Observe(float64(elapsed.Milliseconds()))
	})
}

// TrustProxyHeaders controls whether clientIP honors the client-supplied
// X-Forwarded-For / X-Real-IP headers. It defaults to false (secure): those
// headers are trivially spoofable, so honoring them unconditionally lets any
// client mint a fresh rate-limit bucket per request (bypass) and forge access
// logs. Set to true ONLY when the server sits behind a trusted reverse proxy
// that overwrites these headers.
var TrustProxyHeaders = false

// clientIP — 真のクライアント IP (ポート無し)。TrustProxyHeaders=true のときのみ
// X-Forwarded-For / X-Real-IP を尊重し、それ以外は r.RemoteAddr を使う。
// Extracted IP candidates are validated with net.ParseIP: an invalid/spoofed
// value (e.g. "BYPASS_ME" or "admin@corp.example") is rejected and the code
// falls through to r.RemoteAddr, preventing rate-limit bypass and log forgery.
func clientIP(r *http.Request) string {
	if TrustProxyHeaders {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Use the first (left-most) value only: rightmost is the immediate
			// upstream proxy (trusted), but the XFF spec sends the original
			// client IP first. Strip trailing peers.
			candidate := xff
			for i := 0; i < len(xff); i++ {
				if xff[i] == ',' || xff[i] == ' ' {
					candidate = xff[:i]
					break
				}
			}
			if net.ParseIP(candidate) != nil {
				return candidate
			}
		}
		if xr := r.Header.Get("X-Real-IP"); xr != "" {
			if net.ParseIP(xr) != nil {
				return xr
			}
		}
	}
	// r.RemoteAddr is "IP:port" (Go's net/http server fills it). Strip the
	// ephemeral port: keying the rate limiter on IP:port would make it
	// per-connection rather than per-IP, so an attacker opening a fresh
	// connection per request gets a new ephemeral port — hence a brand-new token
	// bucket — and bypasses the limit entirely. Also keeps the access-log
	// `remote` field a clean IP. SplitHostPort fails for an already-bare host
	// (or a Unix socket); fall back to the raw value in that case.
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// ============================================================================
// SecurityHeaders — Apple WWWDC "Building Trust" headers
// ============================================================================

// SecurityHeaders — 標準セキュリティヘッダを応答に追加
//
// 設定:
//
//	X-Content-Type-Options: nosniff
//	Strict-Transport-Security: max-age=31536000; includeSubDomains
//	X-Frame-Options: DENY
//	Referrer-Policy: strict-origin-when-cross-origin
//	Permissions-Policy: (権限最小化)
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// HSTS は HTTPS 配信時のみ意味があるが、付けて困らない
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		// Permissions-Policy: 不要権限を全部 deny
		w.Header().Set("Permissions-Policy",
			"camera=(), microphone=(), geolocation=(), payment=()")
		next.ServeHTTP(w, r)
	})
}

// ============================================================================
// Chain — composable middleware
// ============================================================================

// Middleware — Apple HandlerFunc-like alias
type Middleware func(http.Handler) http.Handler

// Chain — middleware を順序通りに重ねる
//
//	chain(handler, m1, m2, m3) == m1(m2(m3(handler)))
//
// 実行順: m1 → m2 → m3 → handler → m3 returns → m2 returns → m1 returns
func Chain(h http.Handler, mws ...Middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// Default — BLRCS 推奨デフォルトチェーン
//
//	Recovery → RequestID → SecurityHeaders → AccessLog → handler
func Default(handler http.Handler) http.Handler {
	return Chain(handler, Recovery, RequestID, SecurityHeaders, AccessLog)
}

// ============================================================================
// MaxBodyBytes — リクエストボディサイズ制限
// ============================================================================

// MaxBodyBytes returns a middleware that caps inbound request bodies at limit
// bytes. Requests whose bodies exceed the limit receive 413 Request Entity Too
// Large before the inner handler is invoked. Without this guard, handlers that
// read the entire body (json.Decode, io.ReadAll) are vulnerable to DoS via
// unbounded memory allocation on oversized payloads.
//
// Typical values: 1<<20 (1 MiB) for API endpoints, 50<<20 (50 MiB) for
// file-upload endpoints. Use limit ≤ 0 to disable the cap (not recommended).
func MaxBodyBytes(limit int64) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if limit > 0 && r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, limit)
			}
			next.ServeHTTP(w, r)
		})
	}
}
