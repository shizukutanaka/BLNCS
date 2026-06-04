// Package metrics — Prometheus テキスト形式メトリクスエクスポータ
//
// Apple の Instruments / MetricKit 思想:
//   - 計装コードと出力形式を分離
//   - Counter, Histogram を型として宣言
//   - 外部依存ゼロ — prometheus/client_golang は重い、不要
//
// 準拠: Prometheus Exposition Format 0.0.4
// 出力: text/plain; version=0.0.4
//
// エンドポイント: GET /metrics
// Grafana / Prometheus 直結可能。
package metrics

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"blrcs/telemetry"
)

// ============================================================================
// Exporter — telemetry.Snapshot を Prometheus 形式に変換
// ============================================================================

// Exporter — blrcs テレメトリを Prometheus フォーマットで書き出す
type Exporter struct {
	tel    *telemetry.Telemetry
	labels map[string]string // 共通ラベル (instance, version, etc.)
}

// NewExporter — エクスポータ構築
//
// labels: 全メトリクスに付加する共通ラベル
//
//	例: {"instance":"prod-1","version":"1.2.0","region":"jp-east"}
func NewExporter(tel *telemetry.Telemetry, labels map[string]string) *Exporter {
	if labels == nil {
		labels = map[string]string{}
	}
	return &Exporter{tel: tel, labels: labels}
}

// ServeHTTP — GET /metrics ハンドラ (net/http.Handler 実装)
func (e *Exporter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	e.WriteMetrics(w)
}

// WriteTo — Prometheus フォーマットを w に書き出す
func (e *Exporter) WriteMetrics(w io.Writer) {
	snap := e.tel.Snapshot()
	labelStr := e.formatLabels(e.labels)
	ts := fmt.Sprintf("%d", time.Now().UnixMilli())

	// ---- HELP + TYPE ヘッダを出してから値 ----
	// Counter
	cNames := sortedKeys(snap.Counters)
	for _, name := range cNames {
		val := snap.Counters[name]
		metricName := sanitize(name) + "_total"
		fmt.Fprintf(w, "# HELP %s BLRCS counter: %s\n", metricName, name)
		fmt.Fprintf(w, "# TYPE %s counter\n", metricName)
		fmt.Fprintf(w, "%s%s %d %s\n", metricName, labelStr, val, ts)
	}

	// Histogram (summary 形式で emit — quantiles)
	hNames := sortedHistKeys(snap.Histograms)
	for _, name := range hNames {
		h := snap.Histograms[name]
		metricName := sanitize(name)
		fmt.Fprintf(w, "# HELP %s BLRCS histogram: %s\n", metricName, name)
		fmt.Fprintf(w, "# TYPE %s summary\n", metricName)
		// quantiles
		quantiles := map[string]float64{
			"0.5":  h.P50,
			"0.95": h.P95,
			"0.99": h.P99,
		}
		for _, q := range []string{"0.5", "0.95", "0.99"} {
			qv := quantiles[q]
			ql := fmt.Sprintf(`{quantile="%s"`, q)
			extra := ""
			if len(e.labels) > 0 {
				extra = "," + e.formatLabelsInner(e.labels)
			}
			fmt.Fprintf(w, "%s%s%s} %.6g %s\n", metricName, ql, extra, qv, ts)
		}
		countName := metricName + "_count"
		sumName := metricName + "_sum"
		maxName := metricName + "_max"
		fmt.Fprintf(w, "%s%s %d %s\n", countName, labelStr, h.Count, ts)
		fmt.Fprintf(w, "%s%s %.6g %s\n", sumName, labelStr, h.Sum, ts)
		fmt.Fprintf(w, "%s%s %.6g %s\n", maxName, labelStr, h.Max, ts)
	}
}

// ============================================================================
// Dashboard summary — CLI / status page 向け人間可読
// ============================================================================

// DashboardHandler — GET /dashboard 人間可読のテキスト要約
// Apple の macOS Activity Monitor 相当
func (e *Exporter) DashboardHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		snap := e.tel.Snapshot()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "BLRCS Dashboard — %s\n", time.Now().UTC().Format(time.RFC3339))
		fmt.Fprintln(w, strings.Repeat("─", 60))

		fmt.Fprintln(w, "\n■ Counters")
		cNames := sortedKeys(snap.Counters)
		for _, n := range cNames {
			fmt.Fprintf(w, "  %-52s %d\n", n, snap.Counters[n])
		}

		fmt.Fprintln(w, "\n■ Histograms (ms)")
		hNames := sortedHistKeys(snap.Histograms)
		for _, n := range hNames {
			h := snap.Histograms[n]
			if h.Count == 0 {
				continue
			}
			fmt.Fprintf(w, "  %-40s count=%-8d p50=%.2f p95=%.2f p99=%.2f max=%.2f\n",
				n, h.Count, h.P50, h.P95, h.P99, h.Max)
		}

		fmt.Fprintln(w, "\n■ Labels")
		for k, v := range e.labels {
			fmt.Fprintf(w, "  %s=%s\n", k, v)
		}
	})
}

// ============================================================================
// helpers
// ============================================================================

// sanitize — Prometheus メトリクス名: [a-zA-Z_:][a-zA-Z0-9_:]*
func sanitize(s string) string {
	var b strings.Builder
	for i, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_', c == ':':
			b.WriteRune(c)
		case c >= '0' && c <= '9' && i > 0:
			b.WriteRune(c)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

func (e *Exporter) formatLabels(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	return "{" + e.formatLabelsInner(m) + "}"
}

func (e *Exporter) formatLabelsInner(m map[string]string) string {
	pairs := make([]string, 0, len(m))
	for k, v := range m {
		pairs = append(pairs, fmt.Sprintf(`%s="%s"`, k, v))
	}
	sort.Strings(pairs)
	return strings.Join(pairs, ",")
}

func sortedKeys(m map[string]int64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedHistKeys(m map[string]telemetry.HistogramSnapshot) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
