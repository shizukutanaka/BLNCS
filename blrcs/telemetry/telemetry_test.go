package telemetry

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// captureRecorder — テスト用 in-memory Recorder
type captureRecorder struct {
	mu     sync.Mutex
	events []Event
}

func (c *captureRecorder) Record(ev Event) {
	c.mu.Lock()
	c.events = append(c.events, ev)
	c.mu.Unlock()
}

func (c *captureRecorder) names() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.events))
	for i, e := range c.events {
		out[i] = e.Name
	}
	return out
}

// ============================================================================
// Basic emission
// ============================================================================

func TestInfoEmitsEvent(t *testing.T) {
	rec := &captureRecorder{}
	tel := New(rec)
	tel.Info("test.event", slog.String("k", "v"))

	if len(rec.events) != 1 {
		t.Fatalf("got %d events", len(rec.events))
	}
	ev := rec.events[0]
	if ev.Name != "test.event" {
		t.Errorf("name: %s", ev.Name)
	}
	if ev.Level != slog.LevelInfo {
		t.Errorf("level: %v", ev.Level)
	}
	if len(ev.Attrs) != 1 || ev.Attrs[0].Key != "k" {
		t.Errorf("attrs: %+v", ev.Attrs)
	}
}

func TestLevels(t *testing.T) {
	rec := &captureRecorder{}
	tel := New(rec)
	tel.Debug("a")
	tel.Info("b")
	tel.Warn("c")
	tel.Error("d")
	if len(rec.events) != 4 {
		t.Fatalf("got %d", len(rec.events))
	}
	wants := []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError}
	for i, want := range wants {
		if rec.events[i].Level != want {
			t.Errorf("event %d level: %v want %v", i, rec.events[i].Level, want)
		}
	}
}

// ============================================================================
// Span timing
// ============================================================================

func TestSpanRecordsStartAndEnd(t *testing.T) {
	rec := &captureRecorder{}
	tel := New(rec)
	span := tel.StartSpan(context.Background(), "DPP.Issue", slog.String("issuer", "did:web:test"))
	time.Sleep(2 * time.Millisecond)
	span.End()

	names := rec.names()
	if len(names) < 2 {
		t.Fatalf("expected start+end, got %v", names)
	}
	if names[0] != "DPP.Issue.start" {
		t.Errorf("first event: %s", names[0])
	}
	if names[1] != "DPP.Issue.end" {
		t.Errorf("second event: %s", names[1])
	}
	// elapsed attr present
	endEvent := rec.events[1]
	hasElapsed := false
	for _, a := range endEvent.Attrs {
		if a.Key == "elapsed" {
			hasElapsed = true
		}
	}
	if !hasElapsed {
		t.Error("elapsed attr missing")
	}
}

func TestSpanEndIsIdempotent(t *testing.T) {
	rec := &captureRecorder{}
	tel := New(rec)
	span := tel.StartSpan(context.Background(), "X")
	span.End()
	span.End() // double End()
	span.End()
	// Should still only fire one .end event
	endCount := 0
	for _, n := range rec.names() {
		if strings.HasSuffix(n, ".end") {
			endCount++
		}
	}
	if endCount != 1 {
		t.Errorf("end fired %d times, want 1", endCount)
	}
}

func TestSpanRecordError(t *testing.T) {
	rec := &captureRecorder{}
	tel := New(rec)
	span := tel.StartSpan(context.Background(), "Op.Fail")
	span.RecordError(errors.New("boom"))
	span.End()

	names := rec.names()
	endName := names[len(names)-1]
	if endName != "Op.Fail.error" {
		t.Errorf("expected .error suffix, got %s", endName)
	}
	// Error metric incremented
	if tel.Counter("Op.Fail.errors").Value() != 1 {
		t.Errorf("error counter: %d", tel.Counter("Op.Fail.errors").Value())
	}
}

func TestSpanRecordsDurationHistogram(t *testing.T) {
	rec := &captureRecorder{}
	tel := New(rec)
	span := tel.StartSpan(context.Background(), "Hot.Path")
	time.Sleep(1 * time.Millisecond)
	span.End()

	hist := tel.Histogram("Hot.Path.duration_ms")
	if hist.Snapshot().Count != 1 {
		t.Errorf("histogram count: %d", hist.Snapshot().Count)
	}
}

// ============================================================================
// Counter
// ============================================================================

func TestCounter(t *testing.T) {
	tel := New(NopRecorder{})
	c := tel.Counter("requests")
	c.Inc()
	c.Inc()
	c.Add(5)
	if c.Value() != 7 {
		t.Errorf("count: %d", c.Value())
	}
}

func TestCounterReturnsSameInstance(t *testing.T) {
	tel := New(NopRecorder{})
	c1 := tel.Counter("x")
	c2 := tel.Counter("x")
	if c1 != c2 {
		t.Error("different instances")
	}
}

func TestCounterConcurrent(t *testing.T) {
	tel := New(NopRecorder{})
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tel.Counter("hot").Inc()
		}()
	}
	wg.Wait()
	if tel.Counter("hot").Value() != 100 {
		t.Errorf("count: %d", tel.Counter("hot").Value())
	}
}

// ============================================================================
// Histogram
// ============================================================================

func TestHistogramObserveAndSnapshot(t *testing.T) {
	tel := New(NopRecorder{})
	h := tel.Histogram("latency")
	for i := 1; i <= 100; i++ {
		h.Observe(float64(i))
	}
	snap := h.Snapshot()
	if snap.Count != 100 {
		t.Errorf("count: %d", snap.Count)
	}
	if snap.Max != 100 {
		t.Errorf("max: %f", snap.Max)
	}
	// p50 around 50
	if snap.P50 < 40 || snap.P50 > 60 {
		t.Errorf("p50: %f", snap.P50)
	}
	if snap.P95 < 90 {
		t.Errorf("p95: %f", snap.P95)
	}
}

func TestHistogramReservoirCap(t *testing.T) {
	tel := New(NopRecorder{})
	h := tel.Histogram("flood")
	for i := 0; i < 5000; i++ {
		h.Observe(float64(i))
	}
	snap := h.Snapshot()
	if snap.Count != 5000 {
		t.Errorf("count: %d", snap.Count)
	}
	// Max should still be 4999
	if snap.Max != 4999 {
		t.Errorf("max: %f", snap.Max)
	}
}

// ============================================================================
// Snapshot
// ============================================================================

func TestSnapshot(t *testing.T) {
	tel := New(NopRecorder{})
	tel.Counter("a").Inc()
	tel.Counter("a").Inc()
	tel.Counter("b").Add(5)
	tel.Histogram("h").Observe(1.0)
	tel.Histogram("h").Observe(2.0)

	snap := tel.Snapshot()
	if snap.Counters["a"] != 2 {
		t.Errorf("a: %d", snap.Counters["a"])
	}
	if snap.Counters["b"] != 5 {
		t.Errorf("b: %d", snap.Counters["b"])
	}
	if snap.Histograms["h"].Count != 2 {
		t.Errorf("hist count: %d", snap.Histograms["h"].Count)
	}
}

// ============================================================================
// Slog backend — actual output check
// ============================================================================

func TestSlogRecorderText(t *testing.T) {
	var buf bytes.Buffer
	rec := NewSlogRecorder(&buf, false)
	tel := New(rec)
	tel.Info("test.event", slog.String("k", "v"))
	out := buf.String()
	if !strings.Contains(out, "test.event") {
		t.Errorf("missing event name: %s", out)
	}
	if !strings.Contains(out, "k=v") {
		t.Errorf("missing attr: %s", out)
	}
}

func TestSlogRecorderJSON(t *testing.T) {
	var buf bytes.Buffer
	rec := NewSlogRecorder(&buf, true)
	tel := New(rec)
	tel.Info("test.event", slog.Int("count", 42))
	out := buf.String()
	if !strings.Contains(out, `"msg":"test.event"`) {
		t.Errorf("missing msg in JSON: %s", out)
	}
	if !strings.Contains(out, `"count":42`) {
		t.Errorf("missing count in JSON: %s", out)
	}
}

// ============================================================================
// Default Telemetry
// ============================================================================

func TestDefaultTelemetryReturnsNonNil(t *testing.T) {
	tel := Default()
	if tel == nil {
		t.Fatal("Default() returned nil")
	}
	// Won't panic
	tel.Info("x")
	tel.Counter("y").Inc()
	tel.Histogram("z").Observe(1)
}

func TestSetDefault(t *testing.T) {
	original := Default()
	defer SetDefault(original)
	custom := New(NopRecorder{})
	SetDefault(custom)
	if Default() != custom {
		t.Error("SetDefault did not take effect")
	}
}

// TestNewNilRecorderFallback covers the nil-recorder path in New: when a nil
// Recorder is passed, New must substitute a NopRecorder so later calls don't
// panic.
func TestNewNilRecorderFallback(t *testing.T) {
	tel := New(nil)
	if tel == nil {
		t.Fatal("New(nil) returned nil Telemetry")
	}
	// Verify it works — no panic
	tel.Info("nop.event")
}

// TestSpanRecordErrorNil covers the "if err == nil { return }" guard in
// RecordError so a nil error is a no-op and does not affect the span's error
// state.
func TestSpanRecordErrorNil(t *testing.T) {
	rec := &captureRecorder{}
	tel := New(rec)
	span := tel.StartSpan(context.Background(), "Op.NilErr")
	span.RecordError(nil) // must be a no-op
	span.End()
	// No error recorded → End should emit "<name>.end", not "<name>.error"
	names := rec.names()
	last := names[len(names)-1]
	if last != "Op.NilErr.end" {
		t.Errorf("nil RecordError should leave span clean; got event %q", last)
	}
}

// TestRecorderMethod covers the Recorder() accessor.
func TestRecorderMethod(t *testing.T) {
	rec := NopRecorder{}
	tel := New(rec)
	if tel.Recorder() == nil {
		t.Error("Recorder() should return the configured recorder")
	}
}

// TestSpanAddAttr covers the AddAttr path on an in-flight span.
func TestSpanAddAttr(t *testing.T) {
	tel := New(NopRecorder{})
	span := tel.StartSpan(context.Background(), "Op.AddAttr")
	span.AddAttr(slog.String("key", "value"))
	span.End()
}

// TestHistogramEmptySnapshot covers the early-return when a histogram has no
// observations (len(cp) == 0 path in Snapshot).
func TestHistogramEmptySnapshot(t *testing.T) {
	tel := New(NopRecorder{})
	snap := tel.Histogram("empty.hist").Snapshot()
	if snap.Count != 0 || snap.Sum != 0 {
		t.Errorf("empty histogram snapshot should be zero-valued, got %+v", snap)
	}
}

// TestHistogramSingleSamplePickCap covers the `idx = len(cp)-1` guard in pick
// when p95/p99 would otherwise compute an out-of-bounds index (single sample).
func TestHistogramSingleSamplePickCap(t *testing.T) {
	tel := New(NopRecorder{})
	h := tel.Histogram("single.hist")
	h.Observe(42.0)
	snap := h.Snapshot()
	// With one sample P95 and P99 must cap to the only element.
	if snap.P95 != 42.0 || snap.P99 != 42.0 {
		t.Errorf("P95/P99 with single sample should equal 42.0, got P95=%v P99=%v", snap.P95, snap.P99)
	}
}

// TestDefaultNilFallback covers the `return New(NopRecorder{})` branch in
// Default() when no default has been set.
func TestDefaultNilFallback(t *testing.T) {
	original := defaultTel.Load()
	defer defaultTel.Store(original)
	defaultTel.Store(nil) // clear default
	tel := Default()
	if tel == nil {
		t.Fatal("Default() should return a non-nil fallback when unset")
	}
	tel.Info("fallback.event") // must not panic
}
