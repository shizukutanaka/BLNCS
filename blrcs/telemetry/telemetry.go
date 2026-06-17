// Package telemetry — BLRCS の構造化観測性
//
// Apple os_signpost / OSLog 哲学:
//   - 開発時は詳細、本番では低オーバーヘッド
//   - 構造化属性 (key=value) 中心、文字列フォーマット最小
//   - Span で 開始/終了をペア、所要時間自動計測
//   - Metric は cumulative counter / histogram
//
// stdlib log/slog のみ使用 (Go 1.21+)。OTel への bridge は将来別パッケージ。
//
// 利用例:
//
//	tel := telemetry.Default()
//	span := tel.StartSpan(ctx, "DPP.Issue", "did", iss.ID.String())
//	defer span.End()
//	...
//	tel.Counter("dpp.issued").Inc()
//
//	if err != nil {
//	    span.RecordError(err)
//	    return err
//	}
package telemetry

import (
	"context"
	"io"
	"log/slog"
	"math/rand"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// Recorder — イベント記録の差替可能インタフェース
// ============================================================================

// Event — 構造化イベント
type Event struct {
	Name      string
	Level     slog.Level
	Timestamp time.Time
	Attrs     []slog.Attr
}

// Recorder — telemetry 出力先 (slog/OTel/Prometheus 差替可能)
type Recorder interface {
	Record(ev Event)
}

// SlogRecorder — slog backend (default)
type SlogRecorder struct {
	logger *slog.Logger
}

// NewSlogRecorder — テキスト or JSON 形式
func NewSlogRecorder(w io.Writer, jsonFmt bool) *SlogRecorder {
	var h slog.Handler
	opts := &slog.HandlerOptions{Level: slog.LevelDebug}
	if jsonFmt {
		h = slog.NewJSONHandler(w, opts)
	} else {
		h = slog.NewTextHandler(w, opts)
	}
	return &SlogRecorder{logger: slog.New(h)}
}

func (s *SlogRecorder) Record(ev Event) {
	s.logger.LogAttrs(context.Background(), ev.Level, ev.Name, ev.Attrs...)
}

// NopRecorder — 出力無し (本番で telemetry オフ、ベンチで使用)
type NopRecorder struct{}

func (NopRecorder) Record(ev Event) {}

// ============================================================================
// Telemetry — 中心オブジェクト
// ============================================================================

// Telemetry — 集中管理オブジェクト
type Telemetry struct {
	rec      Recorder
	counters sync.Map // name -> *Counter
	hist     sync.Map // name -> *Histogram
}

// New — Telemetry 構築
func New(rec Recorder) *Telemetry {
	if rec == nil {
		rec = NopRecorder{}
	}
	return &Telemetry{rec: rec}
}

// defaultTel — package-level default (Apple OSLog のグローバル感)
var defaultTel atomic.Pointer[Telemetry]

// SetDefault — プロセス起動時に1回呼ぶ
func SetDefault(t *Telemetry) {
	defaultTel.Store(t)
}

// Default — package-level default (未設定なら Nop)
func Default() *Telemetry {
	if t := defaultTel.Load(); t != nil {
		return t
	}
	return New(NopRecorder{})
}

// 標準的な初期化ヘルパ
func init() {
	// 開発時のデフォルト: stderr に text 形式
	SetDefault(New(NewSlogRecorder(os.Stderr, false)))
}

// Recorder — 内部 Recorder 取得 (低レベル拡張用)
func (t *Telemetry) Recorder() Recorder { return t.rec }

// ============================================================================
// Event emission
// ============================================================================

// Info — 情報レベルイベント
func (t *Telemetry) Info(name string, attrs ...slog.Attr) {
	t.rec.Record(Event{Name: name, Level: slog.LevelInfo, Timestamp: time.Now(), Attrs: attrs})
}

// Warn — 警告レベル
func (t *Telemetry) Warn(name string, attrs ...slog.Attr) {
	t.rec.Record(Event{Name: name, Level: slog.LevelWarn, Timestamp: time.Now(), Attrs: attrs})
}

// Error — エラー
func (t *Telemetry) Error(name string, attrs ...slog.Attr) {
	t.rec.Record(Event{Name: name, Level: slog.LevelError, Timestamp: time.Now(), Attrs: attrs})
}

// Debug — デバッグ (low overhead で本番でも有効化可)
func (t *Telemetry) Debug(name string, attrs ...slog.Attr) {
	t.rec.Record(Event{Name: name, Level: slog.LevelDebug, Timestamp: time.Now(), Attrs: attrs})
}

// ============================================================================
// Span — 開始/終了ペア (OS_signpost 相当)
// ============================================================================

// Span — 計測区間
type Span struct {
	tel       *Telemetry
	name      string
	startedAt time.Time
	attrs     []slog.Attr
	err       error
	once      sync.Once
}

// StartSpan — 計測開始 (defer span.End() ペア必須)
//
//	span := tel.StartSpan(ctx, "DPP.Issue", slog.String("issuer", id))
//	defer span.End()
func (t *Telemetry) StartSpan(ctx context.Context, name string, attrs ...slog.Attr) *Span {
	t.Debug(name+".start", attrs...)
	return &Span{
		tel:       t,
		name:      name,
		startedAt: time.Now(),
		attrs:     attrs,
	}
}

// AddAttr — 実行中の属性追加
func (s *Span) AddAttr(a slog.Attr) {
	s.attrs = append(s.attrs, a)
}

// RecordError — エラー記録 (まだ End() しない)
func (s *Span) RecordError(err error) {
	if err == nil {
		return
	}
	s.err = err
}

// End — 計測終了
func (s *Span) End() {
	s.once.Do(func() {
		dur := time.Since(s.startedAt)
		attrs := append(s.attrs, slog.Duration("elapsed", dur))
		level := slog.LevelInfo
		name := s.name + ".end"
		if s.err != nil {
			attrs = append(attrs, slog.String("error", s.err.Error()))
			level = slog.LevelError
			name = s.name + ".error"
		}
		s.tel.rec.Record(Event{
			Name:      name,
			Level:     level,
			Timestamp: time.Now(),
			Attrs:     attrs,
		})
		// metric: 名前と所要時間でhistogram
		s.tel.Histogram(s.name + ".duration_ms").Observe(float64(dur.Milliseconds()))
		if s.err != nil {
			s.tel.Counter(s.name + ".errors").Inc()
		} else {
			s.tel.Counter(s.name + ".success").Inc()
		}
	})
}

// ============================================================================
// Metrics — Counter, Histogram (atomic, lock-free hot path)
// ============================================================================

// Counter — 単調増加
type Counter struct {
	value atomic.Int64
}

func (t *Telemetry) Counter(name string) *Counter {
	if v, ok := t.counters.Load(name); ok {
		return v.(*Counter)
	}
	c := &Counter{}
	actual, _ := t.counters.LoadOrStore(name, c)
	return actual.(*Counter)
}

func (c *Counter) Inc() { c.value.Add(1) }

func (c *Counter) Add(n int64) { c.value.Add(n) }

func (c *Counter) Value() int64 { return c.value.Load() }

// Histogram — 簡易ヒストグラム (p50/p95/p99 推定用 reservoir)
//
// Apple な選択: 重い percentile 計算は default off, observe() は cheap.
// reservoir は最後の 1024 サンプルを保持 — 限定アルゴリズム
type Histogram struct {
	mu       sync.Mutex
	samples  []float64
	count    atomic.Int64
	sum      atomic.Int64 // *1000 (ms単位想定)
	maxValue atomic.Int64
}

const histogramReservoirSize = 1024

func (t *Telemetry) Histogram(name string) *Histogram {
	if v, ok := t.hist.Load(name); ok {
		return v.(*Histogram)
	}
	h := &Histogram{samples: make([]float64, 0, histogramReservoirSize)}
	actual, _ := t.hist.LoadOrStore(name, h)
	return actual.(*Histogram)
}

func (h *Histogram) Observe(v float64) {
	n := h.count.Add(1) // capture 1-indexed position for Vitter's Algorithm R
	h.sum.Add(int64(v * 1000))
	for {
		old := h.maxValue.Load()
		if int64(v) <= old {
			break
		}
		if h.maxValue.CompareAndSwap(old, int64(v)) {
			break
		}
	}
	h.mu.Lock()
	if len(h.samples) < histogramReservoirSize {
		h.samples = append(h.samples, v)
	} else {
		// Vitter's Algorithm R: each past observation has equal probability k/n
		// of surviving in the reservoir, giving an unbiased random sample.
		// math/rand is correct here — reservoir selection is a statistical
		// estimator for latency percentiles, not a security primitive; no secret
		// is derived from these draws.
		j := rand.Int63n(n) //nolint:gosec // G404: statistical sampling, not security-sensitive
		if j < histogramReservoirSize {
			h.samples[j] = v
		}
	}
	h.mu.Unlock()
}

// Snapshot — 現在のメトリクス値スナップショット
type HistogramSnapshot struct {
	Count int64
	Sum   float64
	Max   float64
	P50   float64
	P95   float64
	P99   float64
}

// Snapshot — 簡易 percentile 計算
func (h *Histogram) Snapshot() HistogramSnapshot {
	h.mu.Lock()
	cp := make([]float64, len(h.samples))
	copy(cp, h.samples)
	h.mu.Unlock()
	if len(cp) == 0 {
		return HistogramSnapshot{}
	}
	// in-place sort
	sortFloat64s(cp)
	pick := func(p float64) float64 {
		idx := int(float64(len(cp)) * p)
		if idx >= len(cp) {
			idx = len(cp) - 1
		}
		return cp[idx]
	}
	return HistogramSnapshot{
		Count: h.count.Load(),
		Sum:   float64(h.sum.Load()) / 1000,
		Max:   float64(h.maxValue.Load()),
		P50:   pick(0.50),
		P95:   pick(0.95),
		P99:   pick(0.99),
	}
}

// sortFloat64s — sort.Float64s 自前 (sort import 回避でゼロ依存維持)
func sortFloat64s(a []float64) {
	// insertion sort for small N (reservoir <= 1024 で十分)
	for i := 1; i < len(a); i++ {
		j := i
		for j > 0 && a[j-1] > a[j] {
			a[j-1], a[j] = a[j], a[j-1]
			j--
		}
	}
}

// ============================================================================
// Metric snapshot — ダッシュボード/Prometheus 出力用
// ============================================================================

// Snapshot — 全メトリクス取得
type Snapshot struct {
	Counters   map[string]int64
	Histograms map[string]HistogramSnapshot
}

// Snapshot — atomic 取得
func (t *Telemetry) Snapshot() Snapshot {
	out := Snapshot{
		Counters:   make(map[string]int64),
		Histograms: make(map[string]HistogramSnapshot),
	}
	t.counters.Range(func(k, v any) bool {
		out.Counters[k.(string)] = v.(*Counter).Value()
		return true
	})
	t.hist.Range(func(k, v any) bool {
		out.Histograms[k.(string)] = v.(*Histogram).Snapshot()
		return true
	})
	return out
}
