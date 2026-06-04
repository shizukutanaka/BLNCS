// Package httpchain — HTTP middleware composition + W3C TraceContext
//
// 設計: Apple URLSession の delegate chain / Express middleware 思想。
//
//	ハンドラ毎に書いていた boilerplate を1関数に集約:
//
// Before:
//
//	handler := myHandler
//	handler = telemetryWrap(handler)
//	handler = authMiddleware(handler)
//	handler = recovery.Wrap(handler, tel)
//	handler = traceContextMiddleware(handler)
//	mux.Handle("/api", handler)
//
// After:
//
//	chain := httpchain.New(tel).
//	    WithRecovery().
//	    WithTraceContext().
//	    WithRequestLogging().
//	    WithAuth(authFunc)
//	mux.Handle("/api", chain.Then(myHandler))
//
// W3C Trace Context (REC 2020):
//   - traceparent: 00-{trace_id}-{span_id}-{flags}
//   - tracestate: vendor-specific (本実装は通過のみ)
//   - 受信した trace_id を継続、ない場合は新規生成
package httpchain

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"blrcs/recovery"
	"blrcs/telemetry"
)

// ============================================================================
// Chain
// ============================================================================

// Chain — middleware の合成器
type Chain struct {
	tel         *telemetry.Telemetry
	middlewares []func(http.Handler) http.Handler
}

// New — Chain 構築
func New(tel *telemetry.Telemetry) *Chain {
	if tel == nil {
		tel = telemetry.Default()
	}
	return &Chain{tel: tel}
}

// Then — 全 middleware を適用してから handler を返す
//
// 適用順: 最後に追加されたものが最も外側 (defer 風)
// 例: WithRecovery().WithAuth(...).Then(h)
//
//	→ Recovery(Auth(h)) なので Recovery が outer (panic は Auth 内まで届かない)
func (c *Chain) Then(h http.Handler) http.Handler {
	for i := len(c.middlewares) - 1; i >= 0; i-- {
		h = c.middlewares[i](h)
	}
	return h
}

// Use — 任意 middleware 追加
func (c *Chain) Use(mw func(http.Handler) http.Handler) *Chain {
	c.middlewares = append(c.middlewares, mw)
	return c
}

// ============================================================================
// 1. Recovery — panic 回復 (recovery package と統合)
// ============================================================================

// WithRecovery — panic を recover して 500 を返す
func (c *Chain) WithRecovery() *Chain {
	tel := c.tel
	return c.Use(func(next http.Handler) http.Handler {
		return recovery.Wrap(next, tel)
	})
}

// ============================================================================
// 2. TraceContext — W3C Trace Context propagation
// ============================================================================

// traceCtxKey — context key for trace info
type traceCtxKey struct{}

// TraceContextValues — request にattach されたトレース情報
type TraceContextValues struct {
	TraceID      string // 32 hex chars
	SpanID       string // 16 hex chars (this server's span)
	ParentSpanID string // 16 hex chars (caller's span, may be empty)
	Sampled      bool
}

// TraceFromContext — context から取り出し (nil safe)
func TraceFromContext(ctx context.Context) *TraceContextValues {
	v, _ := ctx.Value(traceCtxKey{}).(*TraceContextValues)
	return v
}

// WithTraceContext — W3C Trace Context header を尊重
//
// 仕様: traceparent: 00-{32hex traceId}-{16hex spanId}-{2hex flags}
// flags の 0x01 ビットがサンプリング推奨
//
// 動作:
//   - 受信した traceparent を parse
//   - 新規 spanID を生成 (このサーバ独自 span)
//   - context に TraceContextValues 注入
//   - response に traceparent 反映 (caller への継続)
func (c *Chain) WithTraceContext() *Chain {
	tel := c.tel
	return c.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tc := parseTraceparent(r.Header.Get("traceparent"))
			// Always generate new span for this hop
			tc.ParentSpanID = tc.SpanID
			tc.SpanID = randomSpanID()

			// Propagate to context
			ctx := context.WithValue(r.Context(), traceCtxKey{}, tc)
			r = r.WithContext(ctx)

			// Echo traceparent to response (downstream services use it)
			w.Header().Set("traceparent", buildTraceparent(tc))

			// Telemetry hint
			tel.Counter("http.request.total").Inc()

			next.ServeHTTP(w, r)
		})
	})
}

// parseTraceparent — W3C Trace Context format parser
func parseTraceparent(header string) *TraceContextValues {
	parts := strings.Split(header, "-")
	tc := &TraceContextValues{}
	if len(parts) != 4 {
		// No incoming context — generate fresh
		tc.TraceID = randomTraceID()
		tc.SpanID = randomSpanID()
		tc.Sampled = true
		return tc
	}
	// Validate parts
	if parts[0] != "00" {
		// Unknown version — graceful fallback
		tc.TraceID = randomTraceID()
		tc.SpanID = randomSpanID()
		tc.Sampled = true
		return tc
	}
	if len(parts[1]) != 32 || len(parts[2]) != 16 {
		tc.TraceID = randomTraceID()
		tc.SpanID = randomSpanID()
		return tc
	}
	tc.TraceID = parts[1]
	tc.SpanID = parts[2]
	if len(parts[3]) >= 2 {
		flags := parts[3][:2]
		tc.Sampled = flags == "01" || flags == "03"
	}
	return tc
}

func buildTraceparent(tc *TraceContextValues) string {
	flags := "00"
	if tc.Sampled {
		flags = "01"
	}
	return fmt.Sprintf("00-%s-%s-%s", tc.TraceID, tc.SpanID, flags)
}

func randomTraceID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randomSpanID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ============================================================================
// 3. Request logging — 構造化ログ
// ============================================================================

// statusCapturingWriter — http.ResponseWriter wrapper recording status
type statusCapturingWriter struct {
	http.ResponseWriter
	statusCode int
	bytes      atomic.Int64
}

func (s *statusCapturingWriter) WriteHeader(code int) {
	s.statusCode = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusCapturingWriter) Write(b []byte) (int, error) {
	if s.statusCode == 0 {
		s.statusCode = 200
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes.Add(int64(n))
	return n, err
}

// WithRequestLogging — 全リクエストの method/path/status/duration を構造化ログ
func (c *Chain) WithRequestLogging() *Chain {
	tel := c.tel
	return c.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			scw := &statusCapturingWriter{ResponseWriter: w}
			next.ServeHTTP(scw, r)
			dur := time.Since(start)

			tc := TraceFromContext(r.Context())
			attrs := []slog.Attr{
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", scw.statusCode),
				slog.Int64("bytes", scw.bytes.Load()),
				slog.Duration("elapsed", dur),
			}
			if tc != nil {
				attrs = append(attrs, slog.String("traceID", tc.TraceID))
				attrs = append(attrs, slog.String("spanID", tc.SpanID))
			}

			level := slog.LevelInfo
			if scw.statusCode >= 500 {
				level = slog.LevelError
			} else if scw.statusCode >= 400 {
				level = slog.LevelWarn
			}
			tel.Recorder().Record(telemetry.Event{
				Name:      "http.request",
				Level:     level,
				Timestamp: time.Now(),
				Attrs:     attrs,
			})
			tel.Histogram("http.request.duration_ms").Observe(float64(dur.Milliseconds()))
			tel.Counter(fmt.Sprintf("http.status.%dxx", scw.statusCode/100)).Inc()
		})
	})
}

// ============================================================================
// 4. Auth — pluggable authentication
// ============================================================================

// AuthFunc — 認証関数 (returns authenticated principal or error)
type AuthFunc func(r *http.Request) (string, error)

type authCtxKey struct{}

// PrincipalFromContext — auth で確立された principal
func PrincipalFromContext(ctx context.Context) string {
	v, _ := ctx.Value(authCtxKey{}).(string)
	return v
}

// WithAuth — 認証 middleware 追加
//
// 401 を返すか、principal を context に注入
func (c *Chain) WithAuth(fn AuthFunc) *Chain {
	tel := c.tel
	return c.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, err := fn(r)
			if err != nil {
				tel.Counter("http.auth.fail").Inc()
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), authCtxKey{}, principal)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
}

// BearerAuth — 共通の Bearer token 検証関数
//
// tokens: token → principal name のマップ
func BearerAuth(tokens map[string]string) AuthFunc {
	return func(r *http.Request) (string, error) {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			return "", errors.New("missing Bearer token")
		}
		token := strings.TrimPrefix(header, "Bearer ")
		principal, ok := tokens[token]
		if !ok {
			return "", errors.New("invalid token")
		}
		return principal, nil
	}
}

// ============================================================================
// 5. CORS — cross-origin resource sharing
// ============================================================================

// CORSConfig — CORS 設定
type CORSConfig struct {
	AllowedOrigins []string
	AllowedMethods []string
	AllowedHeaders []string
	MaxAgeSeconds  int
}

// WithCORS — CORS preflight 対応
func (c *Chain) WithCORS(cfg CORSConfig) *Chain {
	if len(cfg.AllowedMethods) == 0 {
		cfg.AllowedMethods = []string{"GET", "POST", "OPTIONS"}
	}
	if cfg.MaxAgeSeconds == 0 {
		cfg.MaxAgeSeconds = 600
	}
	originSet := make(map[string]bool)
	for _, o := range cfg.AllowedOrigins {
		originSet[o] = true
	}
	wildcard := originSet["*"]

	return c.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" {
				allow := wildcard || originSet[origin]
				if allow {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Vary", "Origin")
				}
			}
			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", strings.Join(cfg.AllowedMethods, ", "))
				if len(cfg.AllowedHeaders) > 0 {
					w.Header().Set("Access-Control-Allow-Headers", strings.Join(cfg.AllowedHeaders, ", "))
				}
				w.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", cfg.MaxAgeSeconds))
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	})
}
