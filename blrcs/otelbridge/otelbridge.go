// Package otelbridge — OTel-compatible JSON exporter
//
// 設計: BLRCS telemetry.Recorder が OpenTelemetry OTLP/JSON 形式で出力。
// 既存の Datadog/Honeycomb/Grafana Tempo などにそのまま流せる。
//
// 制限: stdlib のみ (otel-go SDK は外部依存)。
//   - Trace 部分のみ (logs/metrics は metrics パッケージで Prometheus 経由)
//   - JSON 出力で OTLP HTTP receiver が直接受信可能
//
// Apple原則:
//   - 既存 Recorder インタフェース実装、追加API不要
//   - 中央 SDK の置き換えなし、本ファイル削除しても動作
//
// 利用:
//
//	collector := otelbridge.NewOTLPRecorder("https://otel-collector:4318")
//	tel := telemetry.New(collector)
package otelbridge

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"blrcs/telemetry"
)

// ============================================================================
// OTLP types (subset, JSON encoding only)
// ============================================================================

// OTLPSpan — OpenTelemetry trace span (OTLP Spec v1.0 subset)
type OTLPSpan struct {
	TraceID           string          `json:"traceId"`
	SpanID            string          `json:"spanId"`
	ParentSpanID      string          `json:"parentSpanId,omitempty"`
	Name              string          `json:"name"`
	Kind              int             `json:"kind"` // SPAN_KIND_INTERNAL = 1
	StartTimeUnixNano string          `json:"startTimeUnixNano"`
	EndTimeUnixNano   string          `json:"endTimeUnixNano"`
	Attributes        []OTLPAttribute `json:"attributes,omitempty"`
	Status            OTLPStatus      `json:"status"`
}

// OTLPAttribute — key=value 属性
type OTLPAttribute struct {
	Key   string        `json:"key"`
	Value OTLPAttrValue `json:"value"`
}

// OTLPAttrValue — typed value (OTLP AnyValue)
type OTLPAttrValue struct {
	StringValue *string  `json:"stringValue,omitempty"`
	IntValue    *string  `json:"intValue,omitempty"` // OTLP 仕様で string
	DoubleValue *float64 `json:"doubleValue,omitempty"`
	BoolValue   *bool    `json:"boolValue,omitempty"`
}

// OTLPStatus — span 終了状態
type OTLPStatus struct {
	Code    int    `json:"code"` // OK=1, ERROR=2
	Message string `json:"message,omitempty"`
}

const (
	StatusOK    = 1
	StatusError = 2
)

// OTLPLogRecord — log/event (info/warn/error イベント用)
type OTLPLogRecord struct {
	TimeUnixNano   string          `json:"timeUnixNano"`
	SeverityNumber int             `json:"severityNumber"`
	SeverityText   string          `json:"severityText"`
	Body           OTLPAttrValue   `json:"body"`
	Attributes     []OTLPAttribute `json:"attributes,omitempty"`
}

// ============================================================================
// Recorder — telemetry.Recorder 実装
// ============================================================================

// OTLPRecorder — telemetry.Event を OTLP JSON で出力
//
// span.start/.end ペアを 1 OTLPSpan に集約 (start で記録、end で送信)。
type OTLPRecorder struct {
	Endpoint string // OTLP/HTTP receiver (e.g. https://otel-collector:4318/v1/traces)
	HTTP     *http.Client
	Service  string
	Resource map[string]string

	mu        sync.Mutex
	pending   map[string]*spanInProgress // span name → start info
	flushChan chan struct{}
	closeChan chan struct{}
	output    io.Writer // テスト用 — nil 時は HTTP 送信
}

type spanInProgress struct {
	traceID   string
	spanID    string
	startNano int64
	attrs     []slog.Attr
}

// NewOTLPRecorder — OTLP HTTP endpoint への送信
func NewOTLPRecorder(endpoint string) *OTLPRecorder {
	r := &OTLPRecorder{
		Endpoint:  endpoint,
		HTTP:      &http.Client{Timeout: 10 * time.Second},
		Service:   "blrcs",
		Resource:  map[string]string{},
		pending:   make(map[string]*spanInProgress),
		flushChan: make(chan struct{}, 1),
		closeChan: make(chan struct{}),
	}
	return r
}

// NewWriterRecorder — テスト用、JSON を io.Writer に直接書く
func NewWriterRecorder(w io.Writer) *OTLPRecorder {
	r := NewOTLPRecorder("")
	r.output = w
	return r
}

// Record — telemetry.Recorder 実装
func (r *OTLPRecorder) Record(ev telemetry.Event) {
	// span.start/end の検出
	switch {
	case len(ev.Name) > 6 && ev.Name[len(ev.Name)-6:] == ".start":
		r.recordSpanStart(ev)
	case len(ev.Name) > 4 && ev.Name[len(ev.Name)-4:] == ".end":
		r.recordSpanEnd(ev, false)
	case len(ev.Name) > 6 && ev.Name[len(ev.Name)-6:] == ".error":
		r.recordSpanEnd(ev, true)
	default:
		// Info/Warn/Error logs
		r.recordLog(ev)
	}
}

func (r *OTLPRecorder) recordSpanStart(ev telemetry.Event) {
	baseName := ev.Name[:len(ev.Name)-len(".start")]
	r.mu.Lock()
	r.pending[baseName] = &spanInProgress{
		traceID:   randomHex(16),
		spanID:    randomHex(8),
		startNano: ev.Timestamp.UnixNano(),
		attrs:     ev.Attrs,
	}
	r.mu.Unlock()
}

func (r *OTLPRecorder) recordSpanEnd(ev telemetry.Event, isError bool) {
	suffix := ".end"
	if isError {
		suffix = ".error"
	}
	baseName := ev.Name[:len(ev.Name)-len(suffix)]
	r.mu.Lock()
	start, ok := r.pending[baseName]
	if !ok {
		// orphan end (start was missed) — synthesize a 1ns span
		start = &spanInProgress{
			traceID:   randomHex(16),
			spanID:    randomHex(8),
			startNano: ev.Timestamp.UnixNano() - 1,
		}
	}
	delete(r.pending, baseName)
	r.mu.Unlock()

	// Merge end-time attrs (incl. elapsed, error)
	allAttrs := append([]slog.Attr{}, start.attrs...)
	allAttrs = append(allAttrs, ev.Attrs...)

	span := OTLPSpan{
		TraceID:           start.traceID,
		SpanID:            start.spanID,
		Name:              baseName,
		Kind:              1, // INTERNAL
		StartTimeUnixNano: fmt.Sprintf("%d", start.startNano),
		EndTimeUnixNano:   fmt.Sprintf("%d", ev.Timestamp.UnixNano()),
		Attributes:        slogToOTLP(allAttrs),
	}
	if isError {
		span.Status = OTLPStatus{Code: StatusError, Message: extractErrorMsg(ev.Attrs)}
	} else {
		span.Status = OTLPStatus{Code: StatusOK}
	}
	r.emit(span)
}

func (r *OTLPRecorder) recordLog(ev telemetry.Event) {
	severity := slogToOTLPSeverity(ev.Level)
	body := ev.Name
	rec := OTLPLogRecord{
		TimeUnixNano:   fmt.Sprintf("%d", ev.Timestamp.UnixNano()),
		SeverityNumber: severity,
		SeverityText:   ev.Level.String(),
		Body:           OTLPAttrValue{StringValue: &body},
		Attributes:     slogToOTLP(ev.Attrs),
	}
	r.emitLog(rec)
}

// ============================================================================
// Output (HTTP POST or io.Writer)
// ============================================================================

func (r *OTLPRecorder) emit(span OTLPSpan) {
	wrapper := map[string]any{
		"resourceSpans": []map[string]any{
			{
				"resource": map[string]any{
					"attributes": []OTLPAttribute{
						{Key: "service.name", Value: stringValue(r.Service)},
					},
				},
				"scopeSpans": []map[string]any{
					{"spans": []OTLPSpan{span}},
				},
			},
		},
	}
	r.send(wrapper)
}

func (r *OTLPRecorder) emitLog(rec OTLPLogRecord) {
	wrapper := map[string]any{
		"resourceLogs": []map[string]any{
			{
				"resource": map[string]any{
					"attributes": []OTLPAttribute{
						{Key: "service.name", Value: stringValue(r.Service)},
					},
				},
				"scopeLogs": []map[string]any{
					{"logRecords": []OTLPLogRecord{rec}},
				},
			},
		},
	}
	r.send(wrapper)
}

func (r *OTLPRecorder) send(payload map[string]any) {
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	if r.output != nil {
		// テストパス
		_, _ = r.output.Write(body)
		_, _ = r.output.Write([]byte("\n"))
		return
	}
	if r.Endpoint == "" {
		return // dry run
	}
	go func() {
		defer func() { _ = recover() }() // fire-and-forget safety
		req, err := http.NewRequestWithContext(
			context.Background(),
			http.MethodPost, r.Endpoint, bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := r.HTTP.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()
}

// ============================================================================
// Conversion helpers
// ============================================================================

func slogToOTLP(attrs []slog.Attr) []OTLPAttribute {
	out := make([]OTLPAttribute, 0, len(attrs))
	for _, a := range attrs {
		out = append(out, OTLPAttribute{Key: a.Key, Value: slogValueToOTLP(a.Value)})
	}
	return out
}

func slogValueToOTLP(v slog.Value) OTLPAttrValue {
	switch v.Kind() {
	case slog.KindString:
		s := v.String()
		return OTLPAttrValue{StringValue: &s}
	case slog.KindInt64:
		i := fmt.Sprintf("%d", v.Int64())
		return OTLPAttrValue{IntValue: &i}
	case slog.KindUint64:
		i := fmt.Sprintf("%d", v.Uint64())
		return OTLPAttrValue{IntValue: &i}
	case slog.KindFloat64:
		f := v.Float64()
		return OTLPAttrValue{DoubleValue: &f}
	case slog.KindBool:
		b := v.Bool()
		return OTLPAttrValue{BoolValue: &b}
	case slog.KindDuration:
		f := v.Duration().Seconds()
		return OTLPAttrValue{DoubleValue: &f}
	default:
		s := v.String()
		return OTLPAttrValue{StringValue: &s}
	}
}

func slogToOTLPSeverity(l slog.Level) int {
	// OTLP SeverityNumber: TRACE=1, DEBUG=5, INFO=9, WARN=13, ERROR=17
	switch {
	case l >= slog.LevelError:
		return 17
	case l >= slog.LevelWarn:
		return 13
	case l >= slog.LevelInfo:
		return 9
	case l >= slog.LevelDebug:
		return 5
	}
	return 1
}

func extractErrorMsg(attrs []slog.Attr) string {
	for _, a := range attrs {
		if a.Key == "error" {
			return a.Value.String()
		}
	}
	return "error"
}

func stringValue(s string) OTLPAttrValue {
	return OTLPAttrValue{StringValue: &s}
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
