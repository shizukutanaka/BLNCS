// Package schemaver — スキーマバージョン管理 + マイグレーション
//
// 設計: Apple Core Data NSPersistentStoreCoordinator の lightweight migration 思想。
//   - 永続化データに schemaVersion フィールドを必ず付与
//   - 起動時に旧バージョン検知 → 順次マイグレーション関数を適用
//   - "skip versions" は禁止 (1→3 ではなく 1→2→3 を強制) — 部分壊れ防止
//   - 全マイグレーション失敗時は安全な readonly モードに移行
//
// 解決する短所:
//   - "Storage migration不在 — append-log フォーマット変更で全データ壊れる"
//
// 利用例:
//
//	reg := schemaver.New("dpp")
//	reg.Register(1, nil)                          // initial version
//	reg.Register(2, addManufacturerField)         // 1→2: add new field
//	reg.Register(3, renameCarbonToCarbonKgCO2e)   // 2→3: rename
//	updated, err := reg.MigrateToLatest(stored)   // 自動的に最新版へ
package schemaver

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
)

// ============================================================================
// Errors
// ============================================================================

var (
	ErrNoVersionField  = errors.New("schemaver: data has no schemaVersion field")
	ErrUnknownVersion  = errors.New("schemaver: unknown schema version")
	ErrFutureVersion   = errors.New("schemaver: data is from a future schema version")
	ErrMigrationFailed = errors.New("schemaver: migration failed")
)

// ============================================================================
// Migration function type
// ============================================================================

// MigrationFunc — JSON map 単位でフィールド変換
//
// 入力: 前バージョンの構造、出力: 次バージョンの構造
// 元データを変更せず新しい map を返すこと (idempotency)
type MigrationFunc func(data map[string]any) (map[string]any, error)

// ============================================================================
// Registry — version + migration の管理
// ============================================================================

// Registry — 1つの schema (例 "dpp", "battery") のバージョン管理器
type Registry struct {
	mu         sync.RWMutex
	schemaName string
	migrations map[int]MigrationFunc // version → どうやって到達するか (1→version)
	maxVersion int
}

// New — 空 registry 構築
func New(schemaName string) *Registry {
	return &Registry{
		schemaName: schemaName,
		migrations: make(map[int]MigrationFunc),
	}
}

// Register — version と「到達」関数を登録
//
// version=1 は initial — fn=nil で良い (migration 不要)
// 各 version は順番に登録すること (1→2→3、抜けは ErrUnknownVersion 原因)
//
// Precondition: version >= 1 (プログラマエラー時は panic — Apple Swift preconditionFailure 相当)
func (r *Registry) Register(version int, fn MigrationFunc) {
	if version < 1 {
		panic("schemaver: version must be >= 1")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.migrations[version] = fn
	if version > r.maxVersion {
		r.maxVersion = version
	}
}

// LatestVersion — 現在登録されている最新版
func (r *Registry) LatestVersion() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.maxVersion
}

// SchemaName — このレジストリが管轄する schema 名
func (r *Registry) SchemaName() string {
	return r.schemaName
}

// ============================================================================
// MigrateToLatest — 主役 API
// ============================================================================

// MigrateToLatest — 任意 version データを最新版に変換
//
// 段階:
//  1. data から schemaVersion 抽出
//  2. 現在 version → version+1 → ... → latest と順次適用
//  3. 各段階 failure で停止し ErrMigrationFailed 返却 (元データは不変)
func (r *Registry) MigrateToLatest(raw []byte) ([]byte, error) {
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("schemaver: parse: %w", err)
	}
	migrated, err := r.MigrateMap(data)
	if err != nil {
		return nil, err
	}
	return json.Marshal(migrated)
}

// MigrateMap — 既に parse 済 map に対する migration
func (r *Registry) MigrateMap(data map[string]any) (map[string]any, error) {
	r.mu.RLock()
	latest := r.maxVersion
	migrations := make(map[int]MigrationFunc, len(r.migrations))
	for k, v := range r.migrations {
		migrations[k] = v
	}
	r.mu.RUnlock()

	if latest == 0 {
		return nil, errors.New("schemaver: no versions registered")
	}

	current, err := extractVersion(data)
	if err != nil {
		return nil, err
	}
	if current > latest {
		return nil, fmt.Errorf("%w: data v%d, latest v%d", ErrFutureVersion, current, latest)
	}

	// Apply migrations sequentially: current+1, current+2, ..., latest
	for ver := current + 1; ver <= latest; ver++ {
		fn, ok := migrations[ver]
		if !ok {
			return nil, fmt.Errorf("%w: no migration to v%d", ErrUnknownVersion, ver)
		}
		if fn == nil {
			// initial version's "fn" should never be referenced this way
			return nil, fmt.Errorf("%w: nil fn at v%d", ErrUnknownVersion, ver)
		}
		next, err := fn(data)
		if err != nil {
			return nil, fmt.Errorf("%w: v%d→v%d: %v", ErrMigrationFailed, ver-1, ver, err)
		}
		next["schemaVersion"] = ver
		data = next
	}
	if data["schemaVersion"] == nil {
		data["schemaVersion"] = current
	}
	return data, nil
}

// CurrentVersion — data 内の schemaVersion を抽出 (migration なし)
func (r *Registry) CurrentVersion(raw []byte) (int, error) {
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return 0, err
	}
	return extractVersion(data)
}

// IsLatest — data が最新版か
func (r *Registry) IsLatest(raw []byte) (bool, error) {
	cur, err := r.CurrentVersion(raw)
	if err != nil {
		return false, err
	}
	return cur == r.LatestVersion(), nil
}

// RegisteredVersions — 登録済み version 一覧 (sorted)
func (r *Registry) RegisteredVersions() []int {
	r.mu.RLock()
	versions := make([]int, 0, len(r.migrations))
	for v := range r.migrations {
		versions = append(versions, v)
	}
	r.mu.RUnlock()
	sort.Ints(versions)
	return versions
}

// ============================================================================
// helpers
// ============================================================================

// extractVersion — JSON map から schemaVersion (default 1) を取得
func extractVersion(data map[string]any) (int, error) {
	v, ok := data["schemaVersion"]
	if !ok {
		// Default to 1 — for legacy data without explicit version
		return 1, nil
	}
	switch n := v.(type) {
	case float64:
		return int(n), nil
	case int:
		return n, nil
	case int64:
		return int(n), nil
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, fmt.Errorf("%w: invalid version number: %v", ErrNoVersionField, err)
		}
		return int(i), nil
	default:
		return 0, fmt.Errorf("%w: schemaVersion is %T", ErrNoVersionField, v)
	}
}

// StampVersion — data に最新 schemaVersion を埋込む (新規データ作成時)
func StampVersion(data map[string]any, version int) map[string]any {
	data["schemaVersion"] = version
	return data
}
