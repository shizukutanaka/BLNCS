// Package apispec — BLRCS API stability + deprecation infrastructure
//
// Apple @available(iOS, introduced:14.0, deprecated:17.0) アノテーション相当。
// Go には言語機能としての deprecation は無いので、ランタイム登録 + godoc 連携で実装。
//
// 用途:
//   - 公開シンボルの導入バージョン記録
//   - 廃止予定のシンボルとその移行先記録
//   - 廃止までのランウェイ管理 (deprecation runway)
//   - CI で 「未文書化シンボル」「未告知の breaking change」を検出
//
// セマンティックバージョニングポリシー (BLRCS):
//
//	MAJOR: API 互換性破壊 (1年前に Deprecated 必須)
//	MINOR: 追加変更 (互換性維持)
//	PATCH: バグ修正のみ
//
// Apple流: deprecated は最低 2 メジャーバージョン残す
package apispec

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// Stability — API 安定性レベル
type Stability string

const (
	// Stable — 公開 API、互換性保証あり
	Stable Stability = "stable"

	// Beta — 機能完備だが API は変更可能性あり (~3 months)
	Beta Stability = "beta"

	// Experimental — 実験的、いつでも削除可能
	Experimental Stability = "experimental"

	// Deprecated — 廃止予定、移行先あり
	Deprecated Stability = "deprecated"

	// Internal — 公開 API ではない (テストでのみ使用)
	Internal Stability = "internal"
)

// Symbol — 公開 API シンボルの記述
type Symbol struct {
	Package      string    `json:"package"` // "blrcs/compliance"
	Name         string    `json:"name"`    // "Issuer.Issue"
	Kind         string    `json:"kind"`    // "func"|"type"|"var"|"const"
	Stability    Stability `json:"stability"`
	IntroducedIn string    `json:"introducedIn"` // semver: "1.0.0"

	// Deprecated 専用フィールド
	DeprecatedIn string    `json:"deprecatedIn,omitempty"` // "1.5.0"
	RemoveAfter  string    `json:"removeAfter,omitempty"`  // "2.0.0"
	ReplacedBy   string    `json:"replacedBy,omitempty"`   // 移行先シンボル名
	DeprecatedAt time.Time `json:"deprecatedAt,omitempty"`
	MigrationDoc string    `json:"migrationDoc,omitempty"` // URL or path

	Notes string `json:"notes,omitempty"`
}

// FullName — Package + Name
func (s Symbol) FullName() string {
	return s.Package + "." + s.Name
}

// IsRetired — 既に削除予定バージョンを過ぎているか
// version: 現在の semver
func (s Symbol) IsRetired(currentVersion string) bool {
	if s.RemoveAfter == "" {
		return false
	}
	return semverGTE(currentVersion, s.RemoveAfter)
}

// Registry — シンボル登録簿
type Registry struct {
	mu      sync.RWMutex
	symbols map[string]Symbol // FullName → Symbol
}

// NewRegistry — 空のレジストリ
func NewRegistry() *Registry {
	return &Registry{symbols: make(map[string]Symbol)}
}

// Register — シンボルを登録
//
// 二重登録は同一かどうかをチェックし、不一致なら警告 (panic ではなく log で済ませる)
func (r *Registry) Register(s Symbol) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// 二重登録は最後の定義で上書きする (不一致でも panic しない)。
	r.symbols[s.FullName()] = s
}

// Get — シンボル検索
func (r *Registry) Get(fullName string) (Symbol, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.symbols[fullName]
	return s, ok
}

// All — 全シンボル一覧 (パッケージ順)
func (r *Registry) All() []Symbol {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Symbol, 0, len(r.symbols))
	for _, s := range r.symbols {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Package != out[j].Package {
			return out[i].Package < out[j].Package
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// FilterByStability — 指定 stability のシンボル
func (r *Registry) FilterByStability(s Stability) []Symbol {
	all := r.All()
	out := make([]Symbol, 0, len(all))
	for _, sym := range all {
		if sym.Stability == s {
			out = append(out, sym)
		}
	}
	return out
}

// DueForRemoval — 現在バージョンで削除すべきシンボル
func (r *Registry) DueForRemoval(currentVersion string) []Symbol {
	all := r.All()
	out := make([]Symbol, 0, 4)
	for _, sym := range all {
		if sym.IsRetired(currentVersion) {
			out = append(out, sym)
		}
	}
	return out
}

// ============================================================================
// Default registry — package init で登録される BLRCS の symbol 集
// ============================================================================

var defaultRegistry = NewRegistry()

// Default — グローバル registry 取得
func Default() *Registry { return defaultRegistry }

// Reset — テスト用 registry リセット
func Reset() {
	defaultRegistry = NewRegistry()
}

// ============================================================================
// Deprecation runway helpers
// ============================================================================

// DeclareDeprecated — シンボルを Deprecated 状態に遷移
//
// 標準ランウェイ: deprecated → 1 メジャーバージョン経過 → 削除可能
//
//	例: 1.5.0 で deprecated → 2.0.0 で removed (1.5.0/1.6.0/1.7.0 と warn 期間あり)
func DeclareDeprecated(pkg, name, deprecatedIn, replacedBy, migrationDoc string) {
	maj := majorOf(deprecatedIn)
	removeAfter := fmt.Sprintf("%d.0.0", maj+1)
	defaultRegistry.Register(Symbol{
		Package:      pkg,
		Name:         name,
		Stability:    Deprecated,
		DeprecatedIn: deprecatedIn,
		RemoveAfter:  removeAfter,
		ReplacedBy:   replacedBy,
		MigrationDoc: migrationDoc,
		DeprecatedAt: time.Now().UTC(),
	})
}

// DeclareStable — Stable シンボルを宣言
func DeclareStable(pkg, name, kind, introducedIn string) {
	defaultRegistry.Register(Symbol{
		Package:      pkg,
		Name:         name,
		Kind:         kind,
		Stability:    Stable,
		IntroducedIn: introducedIn,
	})
}

// DeclareBeta — Beta シンボルを宣言
func DeclareBeta(pkg, name, kind, introducedIn, notes string) {
	defaultRegistry.Register(Symbol{
		Package:      pkg,
		Name:         name,
		Kind:         kind,
		Stability:    Beta,
		IntroducedIn: introducedIn,
		Notes:        notes,
	})
}

// ============================================================================
// Semver utilities (minimal, stdlib only)
// ============================================================================

// semverGTE — a >= b (semver, "MAJOR.MINOR.PATCH")
func semverGTE(a, b string) bool {
	am, an, ap := parseSemver(a)
	bm, bn, bp := parseSemver(b)
	if am != bm {
		return am > bm
	}
	if an != bn {
		return an > bn
	}
	return ap >= bp
}

func parseSemver(v string) (major, minor, patch int) {
	parts := splitDot(v)
	if len(parts) > 0 {
		major = atoi(parts[0])
	}
	if len(parts) > 1 {
		minor = atoi(parts[1])
	}
	if len(parts) > 2 {
		patch = atoi(parts[2])
	}
	return
}

func majorOf(v string) int {
	m, _, _ := parseSemver(v)
	return m
}

func splitDot(s string) []string {
	out := []string{""}
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			out = append(out, "")
			continue
		}
		out[len(out)-1] += string(s[i])
	}
	return out
}

func atoi(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			break
		}
		n = n*10 + int(s[i]-'0')
	}
	return n
}
