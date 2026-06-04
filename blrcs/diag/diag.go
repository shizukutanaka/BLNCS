// Package diag — BLRCS 診断スナップショット (Apple sysdiagnose 相当)
//
// 目的: 問題報告時に1コマンドで全状態をダンプ
//   - サーバ運用者がサポートチケットに添付できる
//   - 機密情報を含まない (公開鍵のみ、秘密鍵は除外)
//   - JSON (機械可読) + テキスト (人間可読) の2形式
//
// 使い方:
//
//	GET /diag/snapshot.json   # 機械可読
//	GET /diag/snapshot.txt    # 人間可読
//	blrcs diag                # CLI から
//
// Apple sysdiagnose との対応:
//
//	bundle ID, version  → ProductInfo
//	metrics             → TelemetrySnapshot
//	crashes             → RecentErrors
//	logs                → 最近の slog 出力 (任意)
package diag

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"blrcs/telemetry"
)

// ============================================================================
// Snapshot — 1リクエストに全情報
// ============================================================================

// Snapshot — システム全状態の単一スナップショット
type Snapshot struct {
	GeneratedAt time.Time         `json:"generatedAt"`
	Product     ProductInfo       `json:"product"`
	Runtime     RuntimeInfo       `json:"runtime"`
	Telemetry   TelemetrySection  `json:"telemetry"`
	Errors      []ErrorRecord     `json:"recentErrors,omitempty"`
	Resources   map[string]string `json:"resources,omitempty"`
}

// ProductInfo — BLRCS バージョン・コミット・ビルド情報
type ProductInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Commit    string `json:"commit,omitempty"`
	BuildDate string `json:"buildDate,omitempty"`
	Service   string `json:"service,omitempty"` // "blrcs-mcpd" 等
}

// RuntimeInfo — Go ランタイム + OS 情報
type RuntimeInfo struct {
	Go           string `json:"go"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	NumCPU       int    `json:"numCPU"`
	NumGoroutine int    `json:"numGoroutine"`
	MemMiB       uint64 `json:"memMiB"`
}

// TelemetrySection — Telemetry スナップショット
type TelemetrySection struct {
	Counters   map[string]int64                  `json:"counters"`
	Histograms map[string]TelemetryHistogramView `json:"histograms"`
}

// TelemetryHistogramView — 平坦化したヒストグラム表現
type TelemetryHistogramView struct {
	Count int64   `json:"count"`
	Sum   float64 `json:"sum"`
	Max   float64 `json:"max"`
	P50   float64 `json:"p50"`
	P95   float64 `json:"p95"`
	P99   float64 `json:"p99"`
}

// ErrorRecord — 最近のエラー記録 (ring buffer)
type ErrorRecord struct {
	Timestamp time.Time `json:"ts"`
	Operation string    `json:"op"`
	Code      string    `json:"code"`
	Message   string    `json:"msg"`
}

// ============================================================================
// Generator
// ============================================================================

// Generator — Snapshot を生成 (差替可能なリソース取得関数)
type Generator struct {
	tel       *telemetry.Telemetry
	product   ProductInfo
	resources map[string]func(context.Context) string
	errBuf    *errorRing
}

// NewGenerator — Generator 構築
func NewGenerator(tel *telemetry.Telemetry, product ProductInfo) *Generator {
	if tel == nil {
		tel = telemetry.Default()
	}
	return &Generator{
		tel:       tel,
		product:   product,
		resources: make(map[string]func(context.Context) string),
		errBuf:    newErrorRing(64), // 直近 64 件
	}
}

// AddResource — 動的リソース情報を登録 (例: ledger size, db connections)
//
//	gen.AddResource("ledger.size", func(ctx context.Context) string {
//	    return fmt.Sprintf("%d", ledger.Size())
//	})
func (g *Generator) AddResource(name string, fn func(context.Context) string) {
	g.resources[name] = fn
}

// RecordError — エラーリング bufferに追加 (運用中常時呼び出し)
func (g *Generator) RecordError(op, code, message string) {
	g.errBuf.Add(ErrorRecord{
		Timestamp: time.Now().UTC(),
		Operation: op,
		Code:      code,
		Message:   message,
	})
}

// Snapshot — 現在のスナップショット生成
func (g *Generator) Snapshot(ctx context.Context) Snapshot {
	telSnap := g.tel.Snapshot()
	hists := make(map[string]TelemetryHistogramView, len(telSnap.Histograms))
	for k, v := range telSnap.Histograms {
		hists[k] = TelemetryHistogramView{
			Count: v.Count,
			Sum:   v.Sum,
			Max:   v.Max,
			P50:   v.P50,
			P95:   v.P95,
			P99:   v.P99,
		}
	}
	resources := make(map[string]string, len(g.resources))
	for k, fn := range g.resources {
		resources[k] = fn(ctx)
	}
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	return Snapshot{
		GeneratedAt: time.Now().UTC(),
		Product:     g.product,
		Runtime: RuntimeInfo{
			Go:           runtime.Version(),
			OS:           runtime.GOOS,
			Arch:         runtime.GOARCH,
			NumCPU:       runtime.NumCPU(),
			NumGoroutine: runtime.NumGoroutine(),
			MemMiB:       memStats.Alloc / (1024 * 1024),
		},
		Telemetry: TelemetrySection{
			Counters:   telSnap.Counters,
			Histograms: hists,
		},
		Errors:    g.errBuf.All(),
		Resources: resources,
	}
}

// ============================================================================
// Output formats
// ============================================================================

// MarshalJSON — JSON シリアライズ
func (s Snapshot) MarshalJSON() ([]byte, error) {
	type alias Snapshot
	return json.MarshalIndent(alias(s), "", "  ")
}

// Text — 人間可読テキスト形式
func (s Snapshot) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "BLRCS Diagnostic Snapshot — %s\n", s.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintln(&b, strings.Repeat("─", 70))

	fmt.Fprintln(&b, "\n■ Product")
	fmt.Fprintf(&b, "  name=%s version=%s service=%s\n",
		s.Product.Name, s.Product.Version, s.Product.Service)
	if s.Product.Commit != "" {
		fmt.Fprintf(&b, "  commit=%s build=%s\n", s.Product.Commit, s.Product.BuildDate)
	}

	fmt.Fprintln(&b, "\n■ Runtime")
	fmt.Fprintf(&b, "  go=%s os=%s/%s cpus=%d goroutines=%d mem=%dMiB\n",
		s.Runtime.Go, s.Runtime.OS, s.Runtime.Arch,
		s.Runtime.NumCPU, s.Runtime.NumGoroutine, s.Runtime.MemMiB)

	if len(s.Resources) > 0 {
		fmt.Fprintln(&b, "\n■ Resources")
		keys := sortedStringKeys(s.Resources)
		for _, k := range keys {
			fmt.Fprintf(&b, "  %s = %s\n", k, s.Resources[k])
		}
	}

	if len(s.Telemetry.Counters) > 0 {
		fmt.Fprintln(&b, "\n■ Counters")
		keys := sortedInt64Keys(s.Telemetry.Counters)
		for _, k := range keys {
			fmt.Fprintf(&b, "  %-50s %d\n", k, s.Telemetry.Counters[k])
		}
	}

	if len(s.Telemetry.Histograms) > 0 {
		fmt.Fprintln(&b, "\n■ Histograms")
		keys := sortedHistKeys(s.Telemetry.Histograms)
		for _, k := range keys {
			h := s.Telemetry.Histograms[k]
			if h.Count == 0 {
				continue
			}
			fmt.Fprintf(&b, "  %-40s n=%-8d p50=%.2f p95=%.2f p99=%.2f max=%.2f\n",
				k, h.Count, h.P50, h.P95, h.P99, h.Max)
		}
	}

	if len(s.Errors) > 0 {
		fmt.Fprintln(&b, "\n■ Recent Errors")
		for _, e := range s.Errors {
			fmt.Fprintf(&b, "  %s [%s] %s: %s\n",
				e.Timestamp.Format("15:04:05"),
				e.Code, e.Operation, e.Message)
		}
	}

	return b.String()
}

// ============================================================================
// HTTP handler
// ============================================================================

// Handler — /diag/* エンドポイント
//
//	GET /diag/snapshot.json   — JSON
//	GET /diag/snapshot.txt    — 人間可読
func (g *Generator) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/diag/snapshot.json", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		snap := g.Snapshot(r.Context())
		b, err := snap.MarshalJSON()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("/diag/snapshot.txt", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		snap := g.Snapshot(r.Context())
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(snap.Text()))
	})
	return mux
}

// ============================================================================
// errorRing — ring buffer for recent errors
// ============================================================================

type errorRing struct {
	mu       sync.Mutex
	items    []ErrorRecord
	capacity int
	next     int
	full     bool
}

func newErrorRing(capacity int) *errorRing {
	return &errorRing{
		items:    make([]ErrorRecord, capacity),
		capacity: capacity,
	}
}

func (r *errorRing) Add(rec ErrorRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items[r.next] = rec
	r.next++
	if r.next >= r.capacity {
		r.next = 0
		r.full = true
	}
}

func (r *errorRing) All() []ErrorRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.full {
		out := make([]ErrorRecord, r.next)
		copy(out, r.items[:r.next])
		return out
	}
	// reorder: 最も古いものから
	out := make([]ErrorRecord, r.capacity)
	copy(out, r.items[r.next:])
	copy(out[r.capacity-r.next:], r.items[:r.next])
	return out
}

// ============================================================================
// helpers
// ============================================================================

func sortedStringKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedInt64Keys(m map[string]int64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedHistKeys(m map[string]TelemetryHistogramView) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
