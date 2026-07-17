// Package apiversion — API バージョニング・非推奨追跡
//
// Apple `@available(*, deprecated, message:)` + Swift Evolution の API contract
// 思想を Go に移植。
//
// 解決する問題:
//  1. 公開 API 変更を追跡 (semver の判定材料)
//  2. 非推奨 API 利用を実行時警告 (telemetry に乗せる)
//  3. 機械可読な CHANGELOG 生成
//  4. 「いつ削除予定か」を明示
//
// Apple との対応:
//
//	@available(macOS 10.15, *) → API.IntroducedIn
//	@available(*, deprecated, renamed: ...) → API.DeprecatedIn + .Replacement
//	@available(*, unavailable) → API.RemovedIn
package apiversion

import (
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"blrcs/telemetry"
)

// ============================================================================
// API entry — 1つの公開シンボル (関数, type, method)
// ============================================================================

// Stability — API 安定度
type Stability string

const (
	StabilityExperimental Stability = "experimental" // 不安定、いつでも変わる
	StabilityBeta         Stability = "beta"         // 多くの人が使う前段階
	StabilityStable       Stability = "stable"       // 後方互換保証
	StabilityDeprecated   Stability = "deprecated"   // 削除予定
	StabilityRemoved      Stability = "removed"      // 削除済 (refactorカタログ)
)

// API — 公開シンボル定義
type API struct {
	Path         string       `json:"path"`         // "compliance.IssuePassport"
	IntroducedIn string       `json:"introducedIn"` // semver
	Stability    Stability    `json:"stability"`
	Deprecated   *Deprecation `json:"deprecated,omitempty"`
	Description  string       `json:"description,omitempty"`
}

// Deprecation — 非推奨情報
type Deprecation struct {
	Since         string `json:"since"`       // semver
	RemoveIn      string `json:"removeIn"`    // semver (planned)
	Replacement   string `json:"replacement"` // 新 API path
	Reason        string `json:"reason"`
	WarnRateLimit int    `json:"warnRateLimit,omitempty"` // 1 warn per N calls
}

// ============================================================================
// Registry — API カタログ
// ============================================================================

// Registry — 公開 API の中央レジストリ
type Registry struct {
	mu    sync.RWMutex
	apis  map[string]*API
	usage map[string]*int64 // call counts (atomic)
	tel   *telemetry.Telemetry
}

// NewRegistry — レジストリ初期化
func NewRegistry(tel *telemetry.Telemetry) *Registry {
	if tel == nil {
		tel = telemetry.Default()
	}
	return &Registry{
		apis:  make(map[string]*API),
		usage: make(map[string]*int64),
		tel:   tel,
	}
}

// Register — API を登録 (起動時に1回)
func (r *Registry) Register(a API) *Registry {
	if a.Path == "" {
		return r
	}
	r.mu.Lock()
	r.apis[a.Path] = &a
	if _, ok := r.usage[a.Path]; !ok {
		var c int64
		r.usage[a.Path] = &c
	}
	r.mu.Unlock()
	return r
}

// Deprecate — 既存 API を非推奨化 (新 release 時に呼ぶ)
func (r *Registry) Deprecate(path string, dep Deprecation) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.apis[path]
	if !ok {
		return false
	}
	a.Deprecated = &dep
	a.Stability = StabilityDeprecated
	return true
}

// MarkUsed — API 使用を記録 (関数の先頭で呼ぶ)
//
// 非推奨 API の場合: telemetry に warn 発行 + counter inc
// rate-limit 付き (騒がしすぎないように)
func (r *Registry) MarkUsed(path string) {
	r.mu.RLock()
	a, ok := r.apis[path]
	cnt, ok2 := r.usage[path]
	r.mu.RUnlock()
	if !ok || !ok2 {
		return
	}
	n := atomic.AddInt64(cnt, 1)

	if a.Deprecated == nil {
		return
	}
	rate := a.Deprecated.WarnRateLimit
	if rate <= 0 {
		rate = 100 // default: 100呼出毎に1警告
	}
	// Warn on the 1st call and every `rate` calls thereafter. Using (n-1)%rate
	// (rather than n%rate==1) keeps rate==1 meaningful: "warn on every call".
	// With n%rate==1, rate==1 would make the test n%1==1 — never true — so the
	// most aggressive setting silently emitted zero warnings.
	if (n-1)%int64(rate) != 0 {
		return
	}
	r.tel.Warn("apiversion.deprecated_call",
		slog.String("api", path),
		slog.String("since", a.Deprecated.Since),
		slog.String("removeIn", a.Deprecated.RemoveIn),
		slog.String("replacement", a.Deprecated.Replacement),
		slog.Int64("callsSinceStart", n),
	)
	r.tel.Counter("apiversion.deprecated_calls").Inc()
}

// Lookup — API 情報取得
func (r *Registry) Lookup(path string) *API {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if a, ok := r.apis[path]; ok {
		copy := *a // shallow copy
		return &copy
	}
	return nil
}

// AllAPIs — 全 API のスナップショット (ソート済み)
func (r *Registry) AllAPIs() []API {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]API, 0, len(r.apis))
	for _, a := range r.apis {
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// DeprecatedAPIs — 非推奨 API のみ
func (r *Registry) DeprecatedAPIs() []API {
	all := r.AllAPIs()
	out := make([]API, 0)
	for _, a := range all {
		if a.Deprecated != nil {
			out = append(out, a)
		}
	}
	return out
}

// UsageCount — API 呼出回数
func (r *Registry) UsageCount(path string) int64 {
	r.mu.RLock()
	cnt, ok := r.usage[path]
	r.mu.RUnlock()
	if !ok {
		return 0
	}
	return atomic.LoadInt64(cnt)
}

// ============================================================================
// Changelog 生成
// ============================================================================

// Changelog — 機械可読 CHANGELOG エントリ
type ChangelogEntry struct {
	Version    string `json:"version"`
	Date       string `json:"date"`
	Added      []API  `json:"added,omitempty"`
	Deprecated []API  `json:"deprecated,omitempty"`
	Removed    []API  `json:"removed,omitempty"`
}

// Changelog — version までの全変更を集約
func (r *Registry) Changelog(version string) ChangelogEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry := ChangelogEntry{
		Version: version,
		Date:    time.Now().UTC().Format("2006-01-02"),
	}
	for _, a := range r.apis {
		switch {
		case a.Stability == StabilityRemoved:
			entry.Removed = append(entry.Removed, *a)
		case a.Deprecated != nil && a.Deprecated.Since == version:
			entry.Deprecated = append(entry.Deprecated, *a)
		case a.IntroducedIn == version:
			entry.Added = append(entry.Added, *a)
		}
	}
	return entry
}

// MigrationReport — 全非推奨 API について旧→新の移行ガイダンス
type MigrationReport struct {
	Path        string `json:"path"`
	Replacement string `json:"replacement"`
	RemoveIn    string `json:"removeIn"`
	Reason      string `json:"reason"`
	UsageCount  int64  `json:"usageCount"` // 本番計測中の使用数
}

// MigrationReports — 全非推奨 API + 使用回数 (危険度評価用)
func (r *Registry) MigrationReports() []MigrationReport {
	deps := r.DeprecatedAPIs()
	out := make([]MigrationReport, 0, len(deps))
	for _, a := range deps {
		count := int64(0)
		r.mu.RLock()
		if c, ok := r.usage[a.Path]; ok {
			count = atomic.LoadInt64(c)
		}
		r.mu.RUnlock()
		out = append(out, MigrationReport{
			Path:        a.Path,
			Replacement: a.Deprecated.Replacement,
			RemoveIn:    a.Deprecated.RemoveIn,
			Reason:      a.Deprecated.Reason,
			UsageCount:  count,
		})
	}
	// 使用回数降順でソート — 移行優先順
	sort.Slice(out, func(i, j int) bool { return out[i].UsageCount > out[j].UsageCount })
	return out
}

// ============================================================================
// Predefined: BLRCS 公開 API カタログ
// ============================================================================

// BLRCSDefaultRegistry — BLRCS 標準 API 一覧
//
// 主要な公開 API を予め登録。新しいリリースで Deprecate を呼ぶ。
func BLRCSDefaultRegistry(tel *telemetry.Telemetry) *Registry {
	r := NewRegistry(tel)
	apis := []API{
		{Path: "compliance.NewIssuer", IntroducedIn: "1.0.0", Stability: StabilityStable},
		{Path: "compliance.IssuePassport", IntroducedIn: "1.0.0", Stability: StabilityStable},
		{Path: "compliance.IssueSDJWT", IntroducedIn: "1.0.0", Stability: StabilityStable},
		{Path: "compliance.IssueBatteryPassport", IntroducedIn: "1.0.0", Stability: StabilityStable},
		{Path: "compliance.VerifySDJWT", IntroducedIn: "1.0.0", Stability: StabilityStable},
		{Path: "compliance.AttestRange", IntroducedIn: "1.0.0", Stability: StabilityBeta,
			Description: "TEE-attested range proof. Will gain Bulletproofs alternative."},
		{Path: "scitt.NewLedger", IntroducedIn: "1.0.0", Stability: StabilityStable},
		{Path: "scitt.NewLedgerWithStorage", IntroducedIn: "1.0.0", Stability: StabilityStable},
		{Path: "openid4vp.NewVerifier", IntroducedIn: "1.0.0", Stability: StabilityStable},
		{Path: "openid4vci.NewIssuer", IntroducedIn: "1.0.0", Stability: StabilityStable},
		{Path: "dcapi.BuildForVerifier", IntroducedIn: "1.0.0", Stability: StabilityBeta,
			Description: "Browser DC-API integration. Spec is W3C draft, may change."},
		{Path: "builder.NewDPP", IntroducedIn: "1.1.0", Stability: StabilityStable},
		{Path: "builder.NewBattery", IntroducedIn: "1.1.0", Stability: StabilityStable},
	}
	for _, a := range apis {
		r.Register(a)
	}
	return r
}

// ReportLine — 1行 human-readable
func (r *Registry) ReportLine(path string) string {
	a := r.Lookup(path)
	if a == nil {
		return fmt.Sprintf("%s: NOT REGISTERED", path)
	}
	stability := string(a.Stability)
	if a.Deprecated != nil {
		return fmt.Sprintf("%s [%s] introduced=%s deprecated=%s removeIn=%s → use %s (%s)",
			a.Path, stability, a.IntroducedIn, a.Deprecated.Since,
			a.Deprecated.RemoveIn, a.Deprecated.Replacement, a.Deprecated.Reason)
	}
	return fmt.Sprintf("%s [%s] introduced=%s", a.Path, stability, a.IntroducedIn)
}
