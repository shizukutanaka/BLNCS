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
	"sort"
	"sync"
	"time"
)

// ErrReplay — 同一署名/nonce/トークンを既に処理済み
var ErrReplay = errors.New("replay: already processed")

// Detector — リプレイ検出器
type Detector struct {
	mu        sync.RWMutex
	seen      map[string]time.Time // fingerprint -> first-seen
	ttl       time.Duration
	maxSize   int
	gcStop    chan struct{}
	closeOnce sync.Once
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
//
// 冪等: 複数回呼んでも安全 (defer + explicit close の組合せが一般的)。
// sync.Once がないと close(d.gcStop) を 2 回呼んだ時 Go はパニックする。
func (d *Detector) Close() {
	d.closeOnce.Do(func() { close(d.gcStop) })
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

// evictBatchFraction — evict this fraction of maxSize entries per bulk-eviction.
// At maxSize=100 000 this is 10 000, amortising the O(n) scan 10 000-fold vs
// the previous single-entry eviction (where every insertion forced a full scan).
const evictBatchFraction = 10

// evictOldest — caller がロックを保持している前提.
//
// Two-phase eviction:
//  1. Delete all TTL-expired entries (free; causes no replay-window loss).
//  2. If still at cap, bulk-delete the oldest maxSize/evictBatchFraction entries
//     so the O(n) sort cost is amortized over a batch rather than paid per insert.
func (d *Detector) evictOldest() {
	// Phase 1: purge expired entries — no replay-window loss.
	cutoff := time.Now().Add(-d.ttl)
	for k, t := range d.seen {
		if t.Before(cutoff) {
			delete(d.seen, k)
		}
	}
	if len(d.seen) < d.maxSize {
		return
	}
	// Phase 2: bulk-evict the oldest batch when no expired entries freed enough space.
	target := d.maxSize / evictBatchFraction
	if target < 1 {
		target = 1
	}
	type kv struct {
		k string
		t time.Time
	}
	entries := make([]kv, 0, len(d.seen))
	for k, t := range d.seen {
		entries = append(entries, kv{k, t})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].t.Before(entries[j].t)
	})
	for i := 0; i < target && i < len(entries); i++ {
		delete(d.seen, entries[i].k)
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
