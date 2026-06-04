// Package replay — リプレイ攻撃検出
//
// Apple Receipt Validation / Apple Pay token の中核不変条件:
//
//	"同一署名を二度処理してはならない"
//
// 用途:
//   - SD-JWT presentation: 同一 vp_token を盗み再送 → 検出
//   - SCITT receipt: 同じ statement を二重登録 → 検出
//   - OpenID4VCI pre-auth code: 既に消費されたコード → 拒否 (既存)
//
// 設計:
//   - SHA-256 fingerprint をキーに TTL 付き bloom-like cache
//   - LRU eviction + 期限切れ自動削除
//   - sync.Map ベース、ロックフリー読取
//   - 偽陽性なし (full SHA-256 比較、bloom filterではない)
//
// 制限:
//   - メモリ常駐 — 巨大スケールでは Redis backend が必要
//   - 単一プロセス内のみ — クラスタでは shared store 必要 (将来 storage interface 化)
package replay

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// ErrReplay — 同一署名/nonce/トークンを既に処理済み
var ErrReplay = errors.New("replay: already processed")

// Detector — リプレイ検出器
type Detector struct {
	mu      sync.RWMutex
	seen    map[string]time.Time // fingerprint -> first-seen
	ttl     time.Duration
	maxSize int
	gcStop  chan struct{}
}

// NewDetector — TTL と最大サイズを指定して構築
//
//	ttl: エントリ保持期間 (例: 1時間 — 同一署名はこれ以内なら拒否)
//	maxSize: メモリ保護のための上限 (超えたら最古を削除)
func NewDetector(ttl time.Duration, maxSize int) *Detector {
	if ttl <= 0 {
		ttl = 1 * time.Hour
	}
	if maxSize <= 0 {
		maxSize = 100_000
	}
	d := &Detector{
		seen:    make(map[string]time.Time),
		ttl:     ttl,
		maxSize: maxSize,
		gcStop:  make(chan struct{}),
	}
	go d.gcLoop()
	return d
}

// Close — GC goroutine を停止
func (d *Detector) Close() {
	close(d.gcStop)
}

// Check — fingerprint を計算、既に登録済みなら ErrReplay
//
// payload はバイト列ならなんでも良い (SD-JWT, signature, nonce 等)
// 初回登録は nil、2回目以降は ErrReplay
func (d *Detector) Check(payload []byte) error {
	fp := fingerprint(payload)
	now := time.Now()

	// 早期 return: 既知ならロック取得前に detect (read lock)
	d.mu.RLock()
	if seenAt, ok := d.seen[fp]; ok && now.Sub(seenAt) < d.ttl {
		d.mu.RUnlock()
		return ErrReplay
	}
	d.mu.RUnlock()

	// Write lock to insert
	d.mu.Lock()
	defer d.mu.Unlock()
	// double-check (race condition with GC)
	if seenAt, ok := d.seen[fp]; ok && now.Sub(seenAt) < d.ttl {
		return ErrReplay
	}
	// メモリ保護: maxSize 超えたら最古を削除 (粗い LRU)
	if len(d.seen) >= d.maxSize {
		d.evictOldest()
	}
	d.seen[fp] = now
	return nil
}

// CheckString — 文字列向け薄いラッパ
func (d *Detector) CheckString(s string) error {
	return d.Check([]byte(s))
}

// Size — 現在保持しているエントリ数 (メトリクス用)
func (d *Detector) Size() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.seen)
}

// Forget — テスト用: 特定 fingerprint を削除
func (d *Detector) Forget(payload []byte) {
	fp := fingerprint(payload)
	d.mu.Lock()
	delete(d.seen, fp)
	d.mu.Unlock()
}

// ============================================================================
// 内部 helpers
// ============================================================================

// fingerprint — SHA-256 hex (32バイトハッシュは衝突確率実質ゼロ)
func fingerprint(payload []byte) string {
	h := sha256.Sum256(payload)
	return hex.EncodeToString(h[:])
}

// evictOldest — caller がロックを保持している前提
func (d *Detector) evictOldest() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, t := range d.seen {
		if first || t.Before(oldestTime) {
			oldestKey = k
			oldestTime = t
			first = false
		}
	}
	if oldestKey != "" {
		delete(d.seen, oldestKey)
	}
}

// gcLoop — TTL 期限切れエントリを定期削除
func (d *Detector) gcLoop() {
	tickInterval := d.ttl / 4
	if tickInterval < time.Second {
		tickInterval = time.Second
	}
	if tickInterval > 5*time.Minute {
		tickInterval = 5 * time.Minute
	}
	t := time.NewTicker(tickInterval)
	defer t.Stop()
	for {
		select {
		case <-d.gcStop:
			return
		case <-t.C:
			d.collect()
		}
	}
}

func (d *Detector) collect() {
	cutoff := time.Now().Add(-d.ttl)
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, t := range d.seen {
		if t.Before(cutoff) {
			delete(d.seen, k)
		}
	}
}
