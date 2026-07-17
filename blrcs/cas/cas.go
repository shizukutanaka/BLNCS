// Package cas — Content-Addressed Storage
//
// 設計: Git object database / IPFS / Apple Time Machine と同様。
//   - SHA-256 hash でアドレス決定 (immutable, dedup)
//   - 同一 payload の重複保存ゼロ (integrity-by-hash)
//   - 逆引き: hash → payload 取得
//   - audit時の dataprovenance 追跡 (どの credential が永続化されたか)
//
// 用途:
//   - 発行済 DPP の hash を SCITT receipt に紐付け
//   - 「この受領証はどの payload に対するものか」を即座に検索
//   - 同一 product の再発行で重複保存防止
//
// 設計原則 (Apple Time Machine 相当):
//   - 単一の不変条件: hash(content) == address
//   - 既存 storage interface 上に乗る (差替可能 backend)
//   - 並行安全 (sync.Map ベース、read lock-free)
package cas

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
)

// ErrNotFound — 指定 hash が存在しない
var ErrNotFound = errors.New("cas: not found")

// ErrCorrupted is returned by GetVerified / Provenance.LookupByID when a backend
// returns a payload whose SHA-256 does not match the requested hash. This breaks
// the sole CAS invariant — hash(content) == address — and signals backend
// corruption (disk bitrot, a tampered object store, a buggy cache) or a backend
// that does not honor the content-addressed contract. The in-memory store cannot
// trigger this, but the Store interface is explicitly pluggable, so any read that
// crosses a trust boundary must be integrity-checked rather than trusted.
var ErrCorrupted = errors.New("cas: retrieved payload does not match requested hash")

// Hash — 32-byte SHA-256 を hex 文字列で表現 (always 64 chars lowercase)
type Hash string

// String — fmt.Stringer
func (h Hash) String() string { return string(h) }

// Bytes — raw 32 bytes
func (h Hash) Bytes() ([]byte, error) {
	return hex.DecodeString(string(h))
}

// ============================================================================
// Store interface — backend 差替可能
// ============================================================================

// Store — content-addressed storage
type Store interface {
	// Put — payload を保存し hash を返す
	// 既存の同一 payload は no-op (dedup)
	Put(payload []byte) (Hash, error)

	// Get — hash で payload を取得
	Get(h Hash) ([]byte, error)

	// Has — 存在確認 (Get より軽量)
	Has(h Hash) bool

	// Size — 保管している unique payload 数
	Size() int

	// Iterate — 全 hash を visit する
	Iterate(fn func(h Hash) error) error
}

// ============================================================================
// MemoryStore — in-memory 実装 (テスト & 軽量本番用)
// ============================================================================

// MemoryStore — sync.Map ベース concurrent CAS
type MemoryStore struct {
	mu      sync.RWMutex
	objects map[Hash][]byte
}

// NewMemoryStore — 空の memory store
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		objects: make(map[Hash][]byte),
	}
}

// Put — SHA-256 で hash 計算、既存なら hash のみ返却
func (m *MemoryStore) Put(payload []byte) (Hash, error) {
	h := ComputeHash(payload)
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.objects[h]; !exists {
		// Defensive copy — caller が後で payload を変更しても影響受けない
		cp := make([]byte, len(payload))
		copy(cp, payload)
		m.objects[h] = cp
	}
	return h, nil
}

// Get — hash で payload を取得
func (m *MemoryStore) Get(h Hash) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.objects[h]
	if !ok {
		return nil, ErrNotFound
	}
	// Defensive copy: caller が変更しても store に影響なし
	cp := make([]byte, len(b))
	copy(cp, b)
	return cp, nil
}

// Has — 存在確認
func (m *MemoryStore) Has(h Hash) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.objects[h]
	return ok
}

// Size — unique payload 数
func (m *MemoryStore) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.objects)
}

// Iterate — 全 hash を visit (順不同)
func (m *MemoryStore) Iterate(fn func(h Hash) error) error {
	m.mu.RLock()
	hashes := make([]Hash, 0, len(m.objects))
	for h := range m.objects {
		hashes = append(hashes, h)
	}
	m.mu.RUnlock()
	for _, h := range hashes {
		if err := fn(h); err != nil {
			return err
		}
	}
	return nil
}

// ============================================================================
// Helpers
// ============================================================================

// ComputeHash — SHA-256 hex (deterministic, address-defining)
//
// 不変条件: 同じ payload は同じ hash、異なる payload は (確率的に) 異なる hash
func ComputeHash(payload []byte) Hash {
	sum := sha256.Sum256(payload)
	return Hash(hex.EncodeToString(sum[:]))
}

// Verify — payload が指定 hash と一致するか
//
// CAS の整合性検証 — 取得した payload が hash と整合するか確認
func Verify(payload []byte, h Hash) bool {
	return ComputeHash(payload) == h
}

// GetVerified retrieves a payload from the store and enforces the CAS invariant
// before returning it: the payload's SHA-256 must equal the requested hash. Use
// this — not the bare Store.Get — whenever the backend is not fully trusted
// (file/network/object-store backends), so corruption or tampering surfaces as
// ErrCorrupted instead of silently returning wrong bytes. With the in-memory
// store the check always passes; the cost is one SHA-256 over the payload.
func GetVerified(store Store, h Hash) ([]byte, error) {
	payload, err := store.Get(h)
	if err != nil {
		return nil, err
	}
	if !Verify(payload, h) {
		return nil, fmt.Errorf("%w: requested %s, got %s", ErrCorrupted, h, ComputeHash(payload))
	}
	return payload, nil
}

// ============================================================================
// Provenance — content hash と外部 ID の対応
//
// 用途: SCITT receipt → credential payload の逆引き
// ============================================================================

// Provenance — 外部 ID (受領証 ID, document ID) から hash への索引
//
// CAS Store に重ね合わせる薄いインデックスレイヤ
type Provenance struct {
	store Store

	mu        sync.RWMutex
	idToHash  map[string]Hash   // external ID → content hash
	hashToIDs map[Hash][]string // content hash → external IDs (1:N)
}

// NewProvenance — provenance index 構築
func NewProvenance(store Store) *Provenance {
	return &Provenance{
		store:     store,
		idToHash:  make(map[string]Hash),
		hashToIDs: make(map[Hash][]string),
	}
}

// Record — payload を保存し、外部 ID と紐付ける
func (p *Provenance) Record(externalID string, payload []byte) (Hash, error) {
	h, err := p.store.Put(payload)
	if err != nil {
		return "", err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	// If this external ID already maps to the same hash, don't append a
	// duplicate (re-recording the same pair would otherwise inflate
	// hashToIDs / TotalMappings without bound and return dupes from LookupIDs).
	if prev, ok := p.idToHash[externalID]; ok && prev == h {
		return h, nil
	}
	// If the ID previously mapped to a different hash, drop the stale reverse entry.
	if prev, ok := p.idToHash[externalID]; ok && prev != h {
		ids := p.hashToIDs[prev]
		for i, id := range ids {
			if id == externalID {
				p.hashToIDs[prev] = append(ids[:i], ids[i+1:]...)
				break
			}
		}
	}
	p.idToHash[externalID] = h
	p.hashToIDs[h] = append(p.hashToIDs[h], externalID)
	return h, nil
}

// LookupByID — 外部 ID で payload を取得
//
// The payload is integrity-checked against its content hash before being
// returned (GetVerified): a corrupted or tampered backend surfaces as
// ErrCorrupted rather than silently returning wrong bytes for an audit lookup.
func (p *Provenance) LookupByID(externalID string) ([]byte, Hash, error) {
	p.mu.RLock()
	h, ok := p.idToHash[externalID]
	p.mu.RUnlock()
	if !ok {
		return nil, "", ErrNotFound
	}
	payload, err := GetVerified(p.store, h)
	if err != nil {
		return nil, h, err
	}
	return payload, h, nil
}

// LookupIDs — content hash から関連付けられた全 ID を取得
func (p *Provenance) LookupIDs(h Hash) []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	ids := p.hashToIDs[h]
	cp := make([]string, len(ids))
	copy(cp, ids)
	return cp
}

// Stats — 索引統計
type Stats struct {
	UniquePayloads int
	UniqueIDs      int
	TotalMappings  int
}

func (p *Provenance) Stats() Stats {
	p.mu.RLock()
	defer p.mu.RUnlock()
	total := 0
	for _, ids := range p.hashToIDs {
		total += len(ids)
	}
	return Stats{
		UniquePayloads: p.store.Size(),
		UniqueIDs:      len(p.idToHash),
		TotalMappings:  total,
	}
}
