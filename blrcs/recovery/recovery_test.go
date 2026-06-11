package recovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"blrcs/telemetry"
)

// captureRec — テスト用 in-memory recorder
type captureRec struct {
	mu     sync.Mutex
	events []telemetry.Event
}

func (c *captureRec) Record(ev telemetry.Event) {
	c.mu.Lock()
	c.events = append(c.events, ev)
	c.mu.Unlock()
}

func (c *captureRec) hasEvent(name string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.events {
		if e.Name == name {
			return true
		}
	}
	return false
}

// ============================================================================
// HTTP Handler recovery
// ============================================================================

func TestHTTPHandlerPanicRecovered(t *testing.T) {
	rec := &captureRec{}
	tel := telemetry.New(rec)

	panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("explosion!")
	})
	wrapped := Wrap(panicHandler, tel)

	ts := httptest.NewServer(wrapped)
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 500 {
		t.Fatalf("want 500, got %d", resp.StatusCode)
	}
	// Counter incremented
	if tel.Counter("panic.recovered.total").Value() != 1 {
		t.Errorf("counter: %d", tel.Counter("panic.recovered.total").Value())
	}
	// Telemetry event recorded
	if !rec.hasEvent("panic.recovered") {
		t.Error("panic.recovered event not emitted")
	}
}

func TestHTTPHandlerNormalRequestPassesThrough(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})
	normalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	wrapped := Wrap(normalHandler, tel)

	ts := httptest.NewServer(wrapped)
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("normal request: %d", resp.StatusCode)
	}
	if tel.Counter("panic.recovered.total").Value() != 0 {
		t.Errorf("counter should be 0, got %d", tel.Counter("panic.recovered.total").Value())
	}
}

func TestHTTPHandlerPanicWithNilTelemetry(t *testing.T) {
	// nil tel should fall through to telemetry.Default()
	panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("nil tel")
	})
	wrapped := Wrap(panicHandler, nil)

	ts := httptest.NewServer(wrapped)
	defer ts.Close()
	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 500 {
		t.Fatalf("nil tel should still recover: %d", resp.StatusCode)
	}
}

func TestHTTPHandlerPanicAfterPartialResponse(t *testing.T) {
	// Handler が一部書き込んでから panic — double-panic で hang しないこと
	tel := telemetry.New(telemetry.NopRecorder{})
	partial := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("partial..."))
		panic("after write")
	})
	wrapped := Wrap(partial, tel)

	ts := httptest.NewServer(wrapped)
	defer ts.Close()

	// Should not hang — set timeout to verify
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(ts.URL)
	if err == nil {
		resp.Body.Close()
	}
	// Either way, recovery counter should be incremented
	if tel.Counter("panic.recovered.total").Value() != 1 {
		t.Error("recovery should have triggered")
	}
}

// ============================================================================
// Goroutine recovery
// ============================================================================

func TestGoRecoversPanicInGoroutine(t *testing.T) {
	rec := &captureRec{}
	tel := telemetry.New(rec)

	done := make(chan struct{})
	Go(context.Background(), tel, "worker", func() {
		defer close(done)
		panic("goroutine boom!")
	})

	// goroutine 完了を待つ
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("goroutine hung")
	}
	// close(done) は fn の defer で走り、panic 回復 (handlePanic) は外側の defer で
	// その後に走るため、カウンタ確定まで短時間ポーリングする (close との競合を避ける)。
	deadline := time.After(2 * time.Second)
	for tel.Counter("panic.recovered.total").Value() != 1 {
		select {
		case <-deadline:
			t.Fatalf("goroutine panic not counted: total=%d", tel.Counter("panic.recovered.total").Value())
		case <-time.After(time.Millisecond):
		}
	}
	// Source-specific counter
	if tel.Counter("panic.recovered.goroutine.worker").Value() != 1 {
		t.Errorf("source-specific counter missing")
	}
}

func TestGoNormalGoroutineNoEffect(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})
	var ran atomic.Int32
	done := make(chan struct{})
	Go(context.Background(), tel, "ok", func() {
		ran.Store(1)
		close(done)
	})
	<-done
	if ran.Load() != 1 {
		t.Error("goroutine did not run")
	}
	if tel.Counter("panic.recovered.total").Value() != 0 {
		t.Error("no panic should produce no counter increment")
	}
}

// ============================================================================
// Safe — defer-style recovery
// ============================================================================

func TestSafeConvertsPanicToError(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})

	risky := func() (err error) {
		defer Safe(tel, "risky", &err)
		panic("converted to error")
	}

	err := risky()
	if err == nil {
		t.Fatal("panic should be converted to error")
	}
	if !strings.Contains(err.Error(), "risky") {
		t.Errorf("error should mention func name: %s", err.Error())
	}
	if !strings.Contains(err.Error(), "converted to error") {
		t.Errorf("error should mention panic value: %s", err.Error())
	}
}

func TestSafeNoPanicNoError(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})

	safe := func() (err error) {
		defer Safe(tel, "safe", &err)
		return nil
	}
	if err := safe(); err != nil {
		t.Errorf("normal exec should not produce error: %v", err)
	}
}

func TestSafeWithNilErrPtr(t *testing.T) {
	// nil errOut shouldn't panic the recovery itself
	tel := telemetry.New(telemetry.NopRecorder{})
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Safe with nil errOut should not panic: %v", r)
		}
	}()
	func() {
		defer Safe(tel, "nilptr", nil)
		panic("test")
	}()
}

// ============================================================================
// Stack capture
// ============================================================================

func TestPanicEventIncludesStack(t *testing.T) {
	rec := &captureRec{}
	tel := telemetry.New(rec)
	wrapped := Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("stack me")
	}), tel)
	ts := httptest.NewServer(wrapped)
	defer ts.Close()

	resp, _ := http.Get(ts.URL)
	if resp != nil {
		resp.Body.Close()
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	for _, e := range rec.events {
		if e.Name == "panic.recovered" {
			for _, a := range e.Attrs {
				if a.Key == "stack" && len(a.Value.String()) > 0 {
					return
				}
			}
		}
	}
	t.Error("stack attr missing from panic event")
}

// TestWrapNoDoubleWriteOnPartialResponse verifies that a panic AFTER the handler
// has begun writing does not trigger a superfluous 500 WriteHeader (which would
// corrupt the body / log "superfluous WriteHeader").
func TestWrapNoDoubleWriteOnPartialResponse(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})
	h := Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("partial"))
		panic("boom after write")
	}), tel)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	// Status must remain 200 (the handler's), not overwritten to 500.
	if rec.Code != http.StatusOK {
		t.Errorf("status got %d, want 200 (no overwrite)", rec.Code)
	}
	// Body must be exactly what the handler wrote (no appended 500 JSON).
	if rec.Body.String() != "partial" {
		t.Errorf("body got %q, want %q", rec.Body.String(), "partial")
	}
	// Panic still recorded.
	if tel.Counter("panic.recovered.total").Value() != 1 {
		t.Error("panic not counted")
	}
}

// TestWrap500OnPanicBeforeWrite verifies the 500 is still written when the
// handler panics before writing anything.
func TestWrap500OnPanicBeforeWrite(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})
	h := Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom before write")
	}), tel)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status got %d, want 500", rec.Code)
	}
}

// ============================================================================
// statusWriter.Flush — forwards to underlying Flusher when supported
// ============================================================================

// flusherRecorder wraps httptest.ResponseRecorder and records Flush calls.
type flusherRecorder struct {
	*httptest.ResponseRecorder
	flushed int
}

func (f *flusherRecorder) Flush() {
	f.flushed++
	f.ResponseRecorder.Flush()
}

func TestStatusWriterFlushForwards(t *testing.T) {
	// statusWriter should forward Flush() to the underlying ResponseWriter
	// when it implements http.Flusher.
	tel := telemetry.New(telemetry.NopRecorder{})
	var sw *statusWriter
	h := Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw = w.(*statusWriter)
		// Flush via the wrapper — should reach the underlying Flusher
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		} else {
			t.Error("wrapped writer should expose http.Flusher")
		}
	}), tel)

	underlying := &flusherRecorder{ResponseRecorder: httptest.NewRecorder()}
	h.ServeHTTP(underlying, httptest.NewRequest("GET", "/flush", nil))

	if sw == nil {
		t.Fatal("statusWriter not captured")
	}
	if underlying.flushed != 1 {
		t.Errorf("Flush not forwarded: flushed=%d", underlying.flushed)
	}
}

// TestGoNilTelemetry exercises the nil-telemetry branch in Go (uses Default()).
func TestGoNilTelemetry(t *testing.T) {
	done := make(chan struct{})
	Go(context.Background(), nil, "nil-tel-test", func() {
		close(done)
	})
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("goroutine hung with nil telemetry")
	}
}

// TestSafeNilTelemetryWithPanic exercises the nil-telemetry branch in Safe.
func TestSafeNilTelemetryWithPanic(t *testing.T) {
	var err error
	func() {
		defer Safe(nil, "nil-tel-safe", &err)
		panic("panic with nil telemetry")
	}()
	if err == nil {
		t.Fatal("panic should be converted to error even with nil telemetry")
	}
}

func TestStatusWriterFlushNoFlusher(t *testing.T) {
	// When underlying ResponseWriter does NOT implement Flusher, Flush() must
	// not panic.
	sw := &statusWriter{ResponseWriter: httptest.NewRecorder()}
	// Should be a no-op (httptest.ResponseRecorder DOES implement Flusher,
	// so use a plain non-Flusher wrapper to exercise the nil-interface path).
	type noFlusher struct{ http.ResponseWriter }
	sw2 := &statusWriter{ResponseWriter: noFlusher{httptest.NewRecorder()}}
	sw2.Flush() // must not panic
	_ = sw
}
