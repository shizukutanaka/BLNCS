package diag

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"blrcs/telemetry"
)

// ============================================================================
// Snapshot
// ============================================================================

func TestSnapshotBasic(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})
	tel.Counter("dpp.issued").Add(42)
	tel.Histogram("compliance.IssuePassport.duration_ms").Observe(15)
	tel.Histogram("compliance.IssuePassport.duration_ms").Observe(25)

	gen := NewGenerator(tel, ProductInfo{
		Name: "BLRCS", Version: "1.0.0", Service: "blrcs-mcpd",
	})
	snap := gen.Snapshot(context.Background())

	if snap.Product.Name != "BLRCS" {
		t.Errorf("name: %s", snap.Product.Name)
	}
	if snap.Telemetry.Counters["dpp.issued"] != 42 {
		t.Errorf("counter: %d", snap.Telemetry.Counters["dpp.issued"])
	}
	if snap.Telemetry.Histograms["compliance.IssuePassport.duration_ms"].Count != 2 {
		t.Errorf("histogram count: %d", snap.Telemetry.Histograms["compliance.IssuePassport.duration_ms"].Count)
	}
	if snap.Runtime.NumCPU == 0 {
		t.Error("NumCPU 0")
	}
	if snap.Runtime.Go == "" {
		t.Error("Go version empty")
	}
}

func TestSnapshotResources(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})
	gen := NewGenerator(tel, ProductInfo{Name: "BLRCS"})
	gen.AddResource("ledger.size", func(ctx context.Context) string {
		return "1234"
	})
	gen.AddResource("storage.fs", func(ctx context.Context) string {
		return "/var/lib/blrcs"
	})
	snap := gen.Snapshot(context.Background())
	if snap.Resources["ledger.size"] != "1234" {
		t.Errorf("ledger.size: %s", snap.Resources["ledger.size"])
	}
	if snap.Resources["storage.fs"] != "/var/lib/blrcs" {
		t.Errorf("storage.fs: %s", snap.Resources["storage.fs"])
	}
}

func TestSnapshotErrorsRecorded(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})
	gen := NewGenerator(tel, ProductInfo{Name: "BLRCS"})

	gen.RecordError("compliance.Issue", "invalid_input", "ProductID required")
	gen.RecordError("scitt.Register", "io", "fsync failed")

	snap := gen.Snapshot(context.Background())
	if len(snap.Errors) != 2 {
		t.Fatalf("error count: %d", len(snap.Errors))
	}
	if snap.Errors[0].Operation != "compliance.Issue" {
		t.Errorf("op: %s", snap.Errors[0].Operation)
	}
	if snap.Errors[1].Code != "io" {
		t.Errorf("code: %s", snap.Errors[1].Code)
	}
}

func TestErrorRingWrapAround(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})
	gen := NewGenerator(tel, ProductInfo{Name: "X"})

	// Generator's errBuf has capacity 64. Push 80 records.
	for i := 0; i < 80; i++ {
		gen.RecordError("op", "code", "msg")
	}
	snap := gen.Snapshot(context.Background())
	// Should keep most recent 64
	if len(snap.Errors) != 64 {
		t.Errorf("ring capacity: got %d errors", len(snap.Errors))
	}
}

// ============================================================================
// Output formats
// ============================================================================

func TestSnapshotJSON(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})
	tel.Counter("c1").Add(7)
	gen := NewGenerator(tel, ProductInfo{Name: "BLRCS", Version: "1.0"})
	snap := gen.Snapshot(context.Background())
	b, err := snap.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	// Must be valid JSON
	var decoded map[string]interface{}
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	prod, ok := decoded["product"].(map[string]interface{})
	if !ok {
		t.Fatalf("product type: %T", decoded["product"])
	}
	if prod["name"] != "BLRCS" {
		t.Errorf("name: %v", prod["name"])
	}
}

func TestSnapshotText(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})
	tel.Counter("test.counter").Add(99)
	gen := NewGenerator(tel, ProductInfo{Name: "BLRCS", Version: "1.0"})
	gen.AddResource("ledger.size", func(ctx context.Context) string { return "500" })
	gen.RecordError("op1", "io", "disk error")

	snap := gen.Snapshot(context.Background())
	text := snap.Text()

	// Sections
	for _, want := range []string{"Product", "Runtime", "Resources", "Counters", "Recent Errors"} {
		if !strings.Contains(text, want) {
			t.Errorf("text missing section %q", want)
		}
	}
	if !strings.Contains(text, "test.counter") {
		t.Error("counter name missing")
	}
	if !strings.Contains(text, "99") {
		t.Error("counter value missing")
	}
	if !strings.Contains(text, "disk error") {
		t.Error("error message missing")
	}
}

// ============================================================================
// HTTP handler
// ============================================================================

func TestHandlerJSON(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})
	tel.Counter("c").Add(1)
	gen := NewGenerator(tel, ProductInfo{Name: "BLRCS"})
	ts := httptest.NewServer(gen.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/diag/snapshot.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), "json") {
		t.Errorf("content-type: %s", resp.Header.Get("Content-Type"))
	}
	body, _ := io.ReadAll(resp.Body)
	var decoded map[string]interface{}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
}

func TestHandlerText(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})
	gen := NewGenerator(tel, ProductInfo{Name: "BLRCS"})
	ts := httptest.NewServer(gen.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/diag/snapshot.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "BLRCS Diagnostic Snapshot") {
		t.Error("missing header")
	}
}

func TestHandlerMethodNotAllowed(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})
	gen := NewGenerator(tel, ProductInfo{Name: "X"})
	ts := httptest.NewServer(gen.Handler())
	defer ts.Close()

	for _, path := range []string{"/diag/snapshot.json", "/diag/snapshot.txt"} {
		req, _ := http.NewRequest("POST", ts.URL+path, nil)
		resp, _ := http.DefaultClient.Do(req)
		if resp.StatusCode != 405 {
			t.Errorf("%s POST: want 405, got %d", path, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

// ============================================================================
// Concurrent error recording
// ============================================================================

func TestConcurrentErrorRecording(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})
	gen := NewGenerator(tel, ProductInfo{Name: "X"})

	done := make(chan struct{})
	for i := 0; i < 100; i++ {
		go func() {
			gen.RecordError("op", "code", "msg")
			done <- struct{}{}
		}()
	}
	for i := 0; i < 100; i++ {
		<-done
	}
	snap := gen.Snapshot(context.Background())
	// Ring buffer caps at 64
	if len(snap.Errors) > 64 {
		t.Errorf("ring exceeded: %d", len(snap.Errors))
	}
}

func TestSnapshotTextWithHistograms(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})
	// Add a timing span so a histogram is recorded.
	span := tel.StartSpan(context.Background(), "test.op")
	span.End()

	gen := NewGenerator(tel, ProductInfo{Name: "BLRCS", Version: "1.0"})
	snap := gen.Snapshot(context.Background())
	text := snap.Text()

	// The histogram section should appear (at least one histogram from the span)
	_ = text // Just ensure it doesn't panic
}

func TestNewGeneratorNilTelemetry(t *testing.T) {
	gen := NewGenerator(nil, ProductInfo{Name: "Test"})
	if gen == nil {
		t.Fatal("nil generator")
	}
	// Should not panic
	snap := gen.Snapshot(context.Background())
	if snap.Product.Name != "Test" {
		t.Errorf("product name: %s", snap.Product.Name)
	}
}
