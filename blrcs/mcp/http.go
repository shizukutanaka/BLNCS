// Package mcp — HTTP Streamable transport (MCP 2.0準拠)
//
// 仕様: Model Context Protocol 2024-11-05 + 2025-03 Streamable HTTP addendum
//
// エンドポイント:
//
//	POST /mcp   — クライアント→サーバ (JSON-RPC リクエスト)
//	GET  /mcp   — サーバ→クライアント (SSE ストリーム、オプション)
//
// ヘッダ:
//
//	Mcp-Session-Id   — initialize後に発行。以降必須
//	Authorization    — Bearer <token> (AuthVerifier が設定された場合)
//
// 耐久性/運用:
//   - net/http標準。TLS終端は外 (envoy/nginx/CF Workers) 推奨
//   - セッションはin-memory LRU (本番は Redis等に差替可能)
//   - ping/SSE heartbeatで30秒タイムアウト延長
//
// 設計: Carmack式 — 直接net/http、抽象は必要最小限
package mcp

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	sessionHeader      = "Mcp-Session-Id"
	sessionIdleTimeout = 30 * time.Minute
	sseHeartbeatPeriod = 25 * time.Second
	// sseWriteTimeout bounds each individual SSE write. The SSE server runs with
	// http.Server WriteTimeout=0 (a global write timeout would kill long-lived
	// streams), so without a per-write deadline a stuck/slow client — one whose
	// TCP send buffer is full but whose connection is still open — would block
	// Write/Flush forever, leaking this goroutine and the connection.
	// r.Context().Done() does NOT fire for a slow-but-open client, so the deadline
	// is the only way out. Set via http.ResponseController before each write.
	sseWriteTimeout     = 10 * time.Second
	defaultMaxBodyBytes = 16 * 1024 * 1024
	// defaultMaxSessions bounds the in-memory session map. Sessions live up to
	// sessionIdleTimeout (30m) and the background GC only sweeps every 5m, so
	// without a hard cap a client issuing `initialize` repeatedly accumulates
	// entries faster than they idle-expire — an unbounded-memory DoS. At the cap
	// the least-recently-seen session is evicted (true LRU), bounding memory to
	// "cap entries" regardless of request rate.
	defaultMaxSessions = 16384
)

// AuthVerifier — 認証プラガブル契約。nilなら認証なし。
// 実装例: OAuth2 Bearer, mTLS fingerprint, API key
type AuthVerifier interface {
	Verify(ctx context.Context, r *http.Request) (principal string, err error)
}

// RateLimiter — 呼出制御プラガブル契約。nilなら無制限。
// principal単位で 許可/拒否 を判断
type RateLimiter interface {
	Allow(principal string) bool
}

// HTTPHandler — MCP Server を net/http.Handler としてラップ
type HTTPHandler struct {
	server   *Server
	auth     AuthVerifier
	limiter  RateLimiter
	sessions *sessionStore
	maxBody  int64
}

// NewHTTPHandler — HTTP transport 構築
// auth, limiter は nil可 (未設定 = 素通し)
func NewHTTPHandler(srv *Server, auth AuthVerifier, limiter RateLimiter) *HTTPHandler {
	return &HTTPHandler{
		server:   srv,
		auth:     auth,
		limiter:  limiter,
		sessions: newSessionStore(),
		maxBody:  defaultMaxBodyBytes,
	}
}

// Close stops the handler's background session-GC goroutine. Call it when the
// handler is no longer needed (e.g. on server shutdown) to avoid leaking a
// goroutine + ticker per handler. Safe to call multiple times; the handler must
// not be used to serve requests afterward.
func (h *HTTPHandler) Close() error {
	h.sessions.close()
	return nil
}

// SetMaxBody — 1リクエスト最大サイズ変更 (default 16MB)
func (h *HTTPHandler) SetMaxBody(n int64) { h.maxBody = n }

// SetMaxSessions — concurrent live セッション上限を変更 (default 16384)。
// 上限到達時は最終アクセスが最も古いセッションを退避する (LRU)。
// n <= 0 は無視 (上限を無効化しない — DoS 防御のため)。
func (h *HTTPHandler) SetMaxSessions(n int) {
	if n <= 0 {
		return
	}
	h.sessions.mu.Lock()
	h.sessions.maxSessions = n
	h.sessions.mu.Unlock()
}

// ServeHTTP — net/http.Handler実装
func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 認証
	principal := "anonymous"
	if h.auth != nil {
		p, err := h.auth.Verify(r.Context(), r)
		if err != nil {
			writeHTTPError(w, http.StatusUnauthorized, err.Error())
			return
		}
		principal = p
	}
	// レート制限
	if h.limiter != nil && !h.limiter.Allow(principal) {
		w.Header().Set("Retry-After", "1")
		writeHTTPError(w, http.StatusTooManyRequests, "rate limited")
		return
	}

	switch r.Method {
	case http.MethodPost:
		h.handlePost(w, r, principal)
	case http.MethodGet:
		h.handleGet(w, r, principal)
	case http.MethodDelete:
		h.handleDelete(w, r, principal)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		writeHTTPError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// ============================================================================
// POST /mcp — single request/response (or initialize)
// ============================================================================

func (h *HTTPHandler) handlePost(w http.ResponseWriter, r *http.Request, principal string) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.maxBody))
	if err != nil {
		writeHTTPError(w, http.StatusBadRequest, "body read: "+err.Error())
		return
	}
	// 空リクエスト拒否
	if len(body) == 0 {
		writeHTTPError(w, http.StatusBadRequest, "empty body")
		return
	}

	// method peek
	var peek struct {
		Method string `json:"method"`
	}
	_ = json.Unmarshal(body, &peek)

	// initialize: 新セッション発行
	if peek.Method == "initialize" {
		sid := newSessionID()
		h.sessions.create(sid, principal)
		w.Header().Set(sessionHeader, sid)
	} else {
		// 既存セッション必須 (notifications/initialized はセッション無しでも受けるが簡略化)
		sid := r.Header.Get(sessionHeader)
		if sid == "" && peek.Method != "ping" {
			writeHTTPError(w, http.StatusBadRequest, "missing "+sessionHeader)
			return
		}
		if sid != "" {
			if !h.sessions.touch(sid, principal) {
				writeHTTPError(w, http.StatusNotFound, "session expired or unknown")
				return
			}
		}
	}

	resp := h.server.HandleRaw(body)
	if resp == nil {
		// 通知 (notifications/*) — 202 Accepted
		w.WriteHeader(http.StatusAccepted)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}

// ============================================================================
// GET /mcp — SSE server→client stream
// ============================================================================

func (h *HTTPHandler) handleGet(w http.ResponseWriter, r *http.Request, principal string) {
	sid := r.Header.Get(sessionHeader)
	if sid == "" {
		writeHTTPError(w, http.StatusBadRequest, "missing "+sessionHeader)
		return
	}
	if !h.sessions.touch(sid, principal) {
		writeHTTPError(w, http.StatusNotFound, "session expired")
		return
	}

	if _, ok := w.(http.Flusher); !ok {
		writeHTTPError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}
	rc := http.NewResponseController(w)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // nginx対策
	w.WriteHeader(http.StatusOK)

	// writeEvent writes one SSE frame under a bounded write deadline so a stuck or
	// slow client cannot block this goroutine forever (the SSE server runs with
	// WriteTimeout=0). Returns false on any write/flush error (deadline exceeded,
	// broken pipe) so the caller stops the stream and releases the connection.
	// SetWriteDeadline / Flush are best-effort: a ResponseWriter that doesn't
	// support them (e.g. some test recorders) returns ErrNotSupported, which we
	// treat as success rather than aborting the stream.
	writeEvent := func(s string) bool {
		_ = rc.SetWriteDeadline(time.Now().Add(sseWriteTimeout))
		if _, err := io.WriteString(w, s); err != nil {
			return false
		}
		if err := rc.Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
			return false
		}
		return true
	}

	// Heartbeat — 接続保持用コメント行
	// 本MVPでは通知購読なし。heartbeatのみ。後でnotifications実装時にsubscribe層追加。
	ticker := time.NewTicker(sseHeartbeatPeriod)
	defer ticker.Stop()

	// 初回確立通知
	if !writeEvent(fmt.Sprintf(": connected sid=%s\n\n", sid)) {
		return
	}

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if !writeEvent(": heartbeat\n\n") {
				return
			}
			h.sessions.touch(sid, principal) // SSE継続中はアクティブ扱い
		}
	}
}

// ============================================================================
// DELETE /mcp — explicit session close
// ============================================================================

func (h *HTTPHandler) handleDelete(w http.ResponseWriter, r *http.Request, _ string) {
	sid := r.Header.Get(sessionHeader)
	if sid == "" {
		writeHTTPError(w, http.StatusBadRequest, "missing "+sessionHeader)
		return
	}
	h.sessions.drop(sid)
	w.WriteHeader(http.StatusNoContent)
}

// ============================================================================
// Session store — in-memory LRU with idle expiry
// ============================================================================

type sessionStore struct {
	mu          sync.Mutex
	data        map[string]*sessionEntry
	maxSessions int
	stop        chan struct{}
	stopOnce    sync.Once
}

type sessionEntry struct {
	principal string
	lastSeen  time.Time
}

func newSessionStore() *sessionStore {
	s := &sessionStore{
		data:        make(map[string]*sessionEntry),
		maxSessions: defaultMaxSessions,
		stop:        make(chan struct{}),
	}
	go s.gcLoop()
	return s
}

// close stops the background GC goroutine. Safe to call multiple times.
func (s *sessionStore) close() {
	s.stopOnce.Do(func() { close(s.stop) })
}

func (s *sessionStore) create(id, principal string) {
	s.mu.Lock()
	// Enforce the hard cap before inserting so the map can never exceed
	// maxSessions. First drop any idle-expired entries (cheap, frees space
	// without losing live sessions); if still at capacity, evict the
	// least-recently-seen entry (LRU).
	if s.maxSessions > 0 && len(s.data) >= s.maxSessions {
		s.evictIdleLocked()
		for len(s.data) >= s.maxSessions {
			s.evictOldestLocked()
		}
	}
	s.data[id] = &sessionEntry{principal: principal, lastSeen: time.Now()}
	s.mu.Unlock()
}

// evictIdleLocked removes all idle-expired entries. Caller holds s.mu.
func (s *sessionStore) evictIdleLocked() {
	cutoff := time.Now().Add(-sessionIdleTimeout)
	for id, e := range s.data {
		if e.lastSeen.Before(cutoff) {
			delete(s.data, id)
		}
	}
}

// evictOldestLocked removes the single least-recently-seen entry. Caller holds
// s.mu and must ensure the map is non-empty.
func (s *sessionStore) evictOldestLocked() {
	var oldestID string
	var oldestSeen time.Time
	first := true
	for id, e := range s.data {
		if first || e.lastSeen.Before(oldestSeen) {
			oldestID, oldestSeen, first = id, e.lastSeen, false
		}
	}
	if !first {
		delete(s.data, oldestID)
	}
}

// touch — セッション存在確認 + 最終アクセス更新
// principalが変われば拒否 (セッション乗っ取り防止)
func (s *sessionStore) touch(id, principal string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[id]
	if !ok {
		return false
	}
	if e.principal != principal {
		return false
	}
	if time.Since(e.lastSeen) > sessionIdleTimeout {
		delete(s.data, id)
		return false
	}
	e.lastSeen = time.Now()
	return true
}

func (s *sessionStore) drop(id string) {
	s.mu.Lock()
	delete(s.data, id)
	s.mu.Unlock()
}

func (s *sessionStore) gcLoop() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	// Must select on s.stop: a bare `for range t.C` never terminates (the ticker
	// channel is never closed), so the goroutine — and the ticker — would leak for
	// the process lifetime and `defer t.Stop()` would be unreachable. Every other
	// GC loop in the codebase (replay, openid4vp, httpmw) uses this stop pattern.
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.gc()
		}
	}
}

func (s *sessionStore) gc() {
	s.mu.Lock()
	s.evictIdleLocked()
	s.mu.Unlock()
}

func newSessionID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// ============================================================================
// Helpers
// ============================================================================

func writeHTTPError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	resp := rpcResponse{
		JSONRPC: "2.0",
		Error: &rpcError{
			Code:    status,
			Message: msg,
		},
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// ============================================================================
// Default AuthVerifier: Bearer token (static, for dev)
// 本番: OAuth2 Resource Server 実装で差替
// ============================================================================

// BearerTokenAuth — 固定トークン認証 (開発/テスト用)
// tokens: token string → principal識別子
type BearerTokenAuth struct {
	Tokens map[string]string
}

func (b *BearerTokenAuth) Verify(_ context.Context, r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return "", errors.New("missing or malformed Authorization header")
	}
	token := strings.TrimPrefix(h, "Bearer ")
	// Constant-time comparison against every configured token (no early exit),
	// so timing does not reveal which token matched or how many bytes were right.
	tb := []byte(token)
	var principal string
	found := 0
	for k, v := range b.Tokens {
		if subtle.ConstantTimeCompare([]byte(k), tb) == 1 {
			principal = v
			found = 1
		}
	}
	if found == 0 {
		return "", errors.New("invalid token")
	}
	return principal, nil
}

// ============================================================================
// Default RateLimiter: token bucket per-principal
// ============================================================================

// TokenBucketLimiter — principal毎 N req/sec
type TokenBucketLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // tokens per second
	burst   float64
}

type bucket struct {
	tokens float64
	last   time.Time
}

func NewTokenBucketLimiter(rate, burst float64) *TokenBucketLimiter {
	return &TokenBucketLimiter{
		buckets: make(map[string]*bucket),
		rate:    rate,
		burst:   burst,
	}
}

func (l *TokenBucketLimiter) Allow(principal string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b, ok := l.buckets[principal]
	if !ok {
		l.buckets[principal] = &bucket{tokens: l.burst - 1, last: now}
		return true
	}
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
