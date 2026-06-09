// Package webhook — 外部システムへの outbound 通知
//
// 設計: Apple ServerSentNotifications / Stripe webhooks / GitHub webhooks の
//
//	業界標準パターンに準拠。
//
// 機能:
//   - 1イベント → N subscribers (subscriber 一覧管理)
//   - HMAC-SHA256 署名 + timestamp で改ざん検知 + 再送攻撃防止
//   - 指数バックオフ再送 (1s, 2s, 4s, 8s, 16s)
//   - 配信ステータス記録 (telemetry counter)
//   - 受信側ライブラリ用の検証ヘルパ
//
// 用途:
//   - DPP発行時 → ERP/在庫管理システムに通知
//   - SCITT登録時 → audit log aggregator に push
//   - 検証失敗時 → security ops にalert
//
// 利用例:
//
//	bus := webhook.NewBus(tel)
//	bus.Subscribe("dpp.issued",
//	    webhook.Subscriber{URL: "https://erp.example/hooks/dpp", Secret: []byte("...")})
//	bus.Publish(ctx, "dpp.issued", map[string]any{"productId": "..."})
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"blrcs/telemetry"
)

// ============================================================================
// Subscriber
// ============================================================================

// Subscriber — 通知先 1個
type Subscriber struct {
	URL     string            // POST 先 URL
	Secret  []byte            // HMAC-SHA256 共有秘密
	Headers map[string]string // 追加 HTTP header (auth等)
	Timeout time.Duration     // request timeout (default 5s)
	Retries int               // 再送上限 (default 4)
}

// Event — 通知ペイロード
type Event struct {
	ID        string    `json:"id"`   // 一意 ID (リプレイ検知用)
	Type      string    `json:"type"` // "dpp.issued" 等
	Timestamp time.Time `json:"timestamp"`
	Data      any       `json:"data"`
}

// ============================================================================
// Bus
// ============================================================================

// Bus — webhook 送信機
type Bus struct {
	tel  *telemetry.Telemetry
	HTTP *http.Client
	Now  func() time.Time

	// AllowPrivateTargets — true で loopback / private / link-local 宛の配信を許可。
	// 既定 false (secure-by-default): subscriber URL は信頼境界外で設定され得るため、
	// 内部サービスやクラウドメタデータ (169.254.169.254) への SSRF を防ぐ。
	// httptest など localhost を相手にするテスト/開発時のみ true。
	AllowPrivateTargets bool

	mu          sync.RWMutex
	subscribers map[string][]Subscriber // event type → subscribers
}

// NewBus — Bus 構築
func NewBus(tel *telemetry.Telemetry) *Bus {
	if tel == nil {
		tel = telemetry.Default()
	}
	b := &Bus{
		tel:         tel,
		Now:         time.Now,
		subscribers: make(map[string][]Subscriber),
	}
	b.HTTP = &http.Client{
		Timeout: 5 * time.Second,
		// Re-validate every redirect hop so a 30x cannot bounce delivery into a
		// private/loopback target (SSRF).
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			return b.validateOutboundURL(req.URL)
		},
	}
	return b
}

// ErrBlockedTarget is returned when a subscriber URL resolves to a disallowed
// (private/loopback/link-local) address or uses a non-http(s) scheme.
var ErrBlockedTarget = errors.New("webhook: delivery target blocked (SSRF guard)")

// validateOutboundURL enforces the SSRF policy for a delivery target.
func (b *Bus) validateOutboundURL(u *url.URL) error {
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: scheme %q", ErrBlockedTarget, u.Scheme)
	}
	if b.AllowPrivateTargets {
		return nil
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("%w: empty host", ErrBlockedTarget)
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("%w: resolve %s: %v", ErrBlockedTarget, host, err)
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("%w: %s resolves to non-public %s", ErrBlockedTarget, host, ip)
		}
	}
	return nil
}

// Subscribe — イベント種別 → subscriber を追加
func (b *Bus) Subscribe(eventType string, s Subscriber) {
	if s.Timeout == 0 {
		s.Timeout = 5 * time.Second
	}
	if s.Retries == 0 {
		s.Retries = 4
	}
	b.mu.Lock()
	b.subscribers[eventType] = append(b.subscribers[eventType], s)
	b.mu.Unlock()
}

// Subscribers — 現在の購読者数 (テスト/監視用)
func (b *Bus) Subscribers(eventType string) []Subscriber {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return append([]Subscriber{}, b.subscribers[eventType]...)
}

// Publish — イベントを全 subscribers に並列送信
//
// 戻り値: 送信に成功した subscriber 数 / 全 subscriber 数 / エラー
// ベストエフォート: 失敗 subscriber は背景再送、エラーで全体は停止しない
func (b *Bus) Publish(ctx context.Context, eventType string, data any) (succeeded, total int, err error) {
	b.mu.RLock()
	subs := append([]Subscriber{}, b.subscribers[eventType]...)
	b.mu.RUnlock()

	if len(subs) == 0 {
		return 0, 0, nil
	}

	event := Event{
		ID:        randomEventID(),
		Type:      eventType,
		Timestamp: b.Now().UTC(),
		Data:      data,
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return 0, len(subs), fmt.Errorf("webhook: marshal: %w", err)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, s := range subs {
		wg.Add(1)
		go func(s Subscriber) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					b.tel.Counter("webhook.panic").Inc()
				}
			}()
			if err := b.deliverWithRetry(ctx, s, eventType, payload); err == nil {
				mu.Lock()
				succeeded++
				mu.Unlock()
				b.tel.Counter("webhook.delivered." + eventType).Inc()
			} else {
				b.tel.Counter("webhook.failed." + eventType).Inc()
			}
		}(s)
	}
	wg.Wait()
	return succeeded, len(subs), nil
}

// ============================================================================
// Delivery
// ============================================================================

// deliverWithRetry — 1 subscriber へ指数バックオフで送信
func (b *Bus) deliverWithRetry(ctx context.Context, s Subscriber, eventType string, payload []byte) error {
	var lastErr error
	delay := 1 * time.Second
	for attempt := 0; attempt <= s.Retries; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
			delay *= 2
		}
		err := b.deliverOnce(ctx, s, eventType, payload)
		if err == nil {
			b.tel.Histogram("webhook.attempt").Observe(float64(attempt + 1))
			return nil
		}
		lastErr = err
		b.tel.Counter("webhook.retry." + eventType).Inc()
	}
	return fmt.Errorf("webhook: exhausted %d retries: %w", s.Retries, lastErr)
}

// deliverOnce — HMAC 署名付き single POST
func (b *Bus) deliverOnce(ctx context.Context, s Subscriber, eventType string, payload []byte) error {
	timeoutCtx := ctx
	if s.Timeout > 0 {
		var cancel context.CancelFunc
		timeoutCtx, cancel = context.WithTimeout(ctx, s.Timeout)
		defer cancel()
	}

	req, err := http.NewRequestWithContext(timeoutCtx, http.MethodPost, s.URL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	// SSRF guard: reject private/loopback/link-local targets before sending.
	if err := b.validateOutboundURL(req.URL); err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "BLRCS-Webhook/1.0")
	req.Header.Set("X-BLRCS-Event", eventType)

	// HMAC signature
	timestamp := strconv.FormatInt(b.Now().Unix(), 10)
	req.Header.Set("X-BLRCS-Timestamp", timestamp)
	if len(s.Secret) > 0 {
		sig := signPayload(s.Secret, timestamp, payload)
		req.Header.Set("X-BLRCS-Signature", "v1="+sig)
	}

	for k, v := range s.Headers {
		req.Header.Set(k, v)
	}

	resp, err := b.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// ============================================================================
// HMAC signing / verification
// ============================================================================

// signPayload — timestamp と body を結合して HMAC-SHA256
//
// 形式: HMAC(secret, timestamp + "." + payload)
// Stripe webhook style — タイムスタンプ含めることで再送攻撃検知可能
func signPayload(secret []byte, timestamp string, payload []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(timestamp))
	mac.Write([]byte{'.'})
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyRequest — receiver-side 検証 (purposes: incoming webhook validation)
//
// 受信ライブラリのため、本パッケージから独立して使えるように切出。
// timeWindow: 容認する timestamp ずれ (recommended 5min)
func VerifyRequest(secret []byte, headers map[string]string, body []byte, timeWindow time.Duration, now time.Time) error {
	if len(secret) == 0 {
		return errors.New("webhook: empty secret")
	}
	timestampStr := headers["X-BLRCS-Timestamp"]
	if timestampStr == "" {
		// HTTP は case-insensitive
		timestampStr = headers["X-Blrcs-Timestamp"]
	}
	if timestampStr == "" {
		return errors.New("webhook: missing X-BLRCS-Timestamp")
	}
	ts, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return fmt.Errorf("webhook: bad timestamp: %w", err)
	}
	t := time.Unix(ts, 0)
	if now.Sub(t).Abs() > timeWindow {
		return fmt.Errorf("webhook: timestamp outside window: %v vs %v", t, now)
	}

	sigHeader := headers["X-BLRCS-Signature"]
	if sigHeader == "" {
		sigHeader = headers["X-Blrcs-Signature"]
	}
	if sigHeader == "" {
		return errors.New("webhook: missing signature")
	}
	const prefix = "v1="
	if len(sigHeader) <= len(prefix) || sigHeader[:len(prefix)] != prefix {
		return errors.New("webhook: signature must use the v1= prefix")
	}
	got := sigHeader[len(prefix):]
	want := signPayload(secret, timestampStr, body)
	// constant-time compare
	if !hmac.Equal([]byte(got), []byte(want)) {
		return errors.New("webhook: signature mismatch")
	}
	return nil
}

// ============================================================================
// Helpers
// ============================================================================

// randomEventID — UUIDv4 identifier. The event ID is the receiver-side
// replay-detection key, so it MUST be unpredictable and collision-resistant:
// use crypto/rand, not the clock (clock-derived IDs share most bytes and are
// forgeable). Falls back to time only if the CSPRNG is unavailable.
func randomEventID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		for i := range b {
			b[i] = byte(time.Now().UnixNano() >> uint(i*4))
		}
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
