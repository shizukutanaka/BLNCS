package otelbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"blrcs/telemetry"
)

// ============================================================================
// Span pairing
// ============================================================================

func TestSpanStartEndProducesOTLPSpan(t *testing.T) {
	var buf bytes.Buffer
	rec := NewWriterRecorder(&buf)
	tel := telemetry.New(rec)

	span := tel.StartSpan(context.Background(), "test.op",
		slog.String("subject", "p-1"),
	)
	span.End()

	out := buf.String()
	if !strings.Contains(out, "resourceSpans") {
		t.Errorf("OTLP wrapper missing: %s", out)
	}
	if !strings.Contains(out, `"name":"test.op"`) {
		t.Errorf("span name missing: %s", out)
	}
	// Status OK = 1
	if !strings.Contains(out, `"status":{"code":1`) {
		t.Errorf("status missing: %s", out)
	}
	// Attribute preserved
	if !strings.Contains(out, "subject") {
		t.Errorf("attr missing: %s", out)
	}
}

func TestSpanErrorMappedToErrorStatus(t *testing.T) {
	var buf bytes.Buffer
	rec := NewWriterRecorder(&buf)
	tel := telemetry.New(rec)

	span := tel.StartSpan(context.Background(), "fail.op")
	span.RecordError(errInternal{"explosion"})
	span.End()

	out := buf.String()
	if !strings.Contains(out, `"code":2`) {
		t.Errorf("error code 2 missing: %s", out)
	}
}

type errInternal struct{ msg string }

func (e errInternal) Error() string { return e.msg }

// ============================================================================
// Trace and span ID format
// ============================================================================

func TestTraceIDIsHexAndCorrectLength(t *testing.T) {
	var buf bytes.Buffer
	rec := NewWriterRecorder(&buf)
	tel := telemetry.New(rec)
	span := tel.StartSpan(context.Background(), "x")
	span.End()

	// Parse first emitted line
	var payload struct {
		ResourceSpans []struct {
			ScopeSpans []struct {
				Spans []OTLPSpan `json:"spans"`
			} `json:"scopeSpans"`
		} `json:"resourceSpans"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.ResourceSpans) != 1 {
		t.Fatal("no resourceSpans")
	}
	if len(payload.ResourceSpans[0].ScopeSpans) != 1 {
		t.Fatal("no scopeSpans")
	}
	spans := payload.ResourceSpans[0].ScopeSpans[0].Spans
	if len(spans) != 1 {
		t.Fatalf("got %d spans", len(spans))
	}
	s := spans[0]
	if len(s.TraceID) != 32 {
		t.Errorf("traceID length: %d (want 32)", len(s.TraceID))
	}
	if len(s.SpanID) != 16 {
		t.Errorf("spanID length: %d (want 16)", len(s.SpanID))
	}
}

// ============================================================================
// Log records
// ============================================================================

func TestInfoEventBecomesLogRecord(t *testing.T) {
	var buf bytes.Buffer
	rec := NewWriterRecorder(&buf)
	tel := telemetry.New(rec)
	tel.Info("user.action", slog.String("user", "alice"))

	out := buf.String()
	if !strings.Contains(out, "resourceLogs") {
		t.Errorf("log wrapper missing: %s", out)
	}
	if !strings.Contains(out, `"severityText":"INFO"`) {
		t.Errorf("severity missing: %s", out)
	}
	if !strings.Contains(out, `"severityNumber":9`) {
		t.Errorf("severity 9 (INFO) missing: %s", out)
	}
}

func TestErrorLevelMappedTo17(t *testing.T) {
	var buf bytes.Buffer
	rec := NewWriterRecorder(&buf)
	tel := telemetry.New(rec)
	tel.Error("explosion", slog.String("reason", "x"))

	out := buf.String()
	if !strings.Contains(out, `"severityNumber":17`) {
		t.Errorf("ERROR=17 missing: %s", out)
	}
}

// ============================================================================
// Attribute type conversion
// ============================================================================

func TestAttributeTypes(t *testing.T) {
	var buf bytes.Buffer
	rec := NewWriterRecorder(&buf)
	tel := telemetry.New(rec)
	tel.Info("typed",
		slog.String("s", "v"),
		slog.Int("i", 42),
		slog.Float64("f", 3.14),
		slog.Bool("b", true),
	)
	out := buf.String()
	if !strings.Contains(out, `"stringValue":"v"`) {
		t.Errorf("stringValue: %s", out)
	}
	if !strings.Contains(out, `"intValue":"42"`) {
		t.Errorf("intValue: %s", out)
	}
	if !strings.Contains(out, `"doubleValue":3.14`) {
		t.Errorf("doubleValue: %s", out)
	}
	if !strings.Contains(out, `"boolValue":true`) {
		t.Errorf("boolValue: %s", out)
	}
}

// ============================================================================
// Span without start (orphan end)
// ============================================================================

func TestOrphanEndDoesNotCrash(t *testing.T) {
	var buf bytes.Buffer
	rec := NewWriterRecorder(&buf)

	// Direct emit of .end without preceding .start
	rec.Record(telemetry.Event{
		Name:      "orphan.end",
		Timestamp: time.Now(),
		Level:     slog.LevelInfo,
	})
	out := buf.String()
	if !strings.Contains(out, "orphan") {
		t.Errorf("orphan end should still emit: %s", out)
	}
}

// ============================================================================
// HTTP exporter (no panic when endpoint unreachable)
// ============================================================================

func TestUnreachableEndpointDoesNotCrash(t *testing.T) {
	rec := NewOTLPRecorder("http://127.0.0.1:1") // Connection refused
	tel := telemetry.New(rec)
	span := tel.StartSpan(context.Background(), "nope")
	span.End()
	// goroutine が背景で fail するだけ、本体に影響なし
}

// ============================================================================
// slogToOTLPSeverity — all branches
// ============================================================================

func TestSeverityMappingAllLevels(t *testing.T) {
	cases := []struct {
		level    slog.Level
		wantCode int
	}{
		{slog.LevelError, 17},
		{slog.LevelError + 4, 17}, // above Error
		{slog.LevelWarn, 13},
		{slog.LevelWarn + 1, 13},
		{slog.LevelInfo, 9},
		{slog.LevelDebug, 5},
		{slog.LevelDebug - 1, 1}, // below Debug → TRACE
	}
	for _, c := range cases {
		got := slogToOTLPSeverity(c.level)
		if got != c.wantCode {
			t.Errorf("level %v: got severity %d, want %d", c.level, got, c.wantCode)
		}
	}
}

// ============================================================================
// slogValueToOTLP — all type branches
// ============================================================================

func TestAttributeAllTypes(t *testing.T) {
	var buf bytes.Buffer
	rec := NewWriterRecorder(&buf)
	tel := telemetry.New(rec)
	tel.Info("all-types",
		slog.String("s", "hello"),
		slog.Int("i", -7),
		slog.Uint64("u", 42),
		slog.Float64("f", 1.5),
		slog.Bool("b", false),
		slog.Duration("d", 2*time.Second),
		slog.Any("x", struct{ V int }{3}), // KindAny → String fallback
	)
	out := buf.String()
	for _, want := range []string{`"hello"`, `"-7"`, `"42"`, `1.5`, `false`} {
		if !strings.Contains(out, want) {
			t.Errorf("attr missing %q in: %s", want, out)
		}
	}
}

// ============================================================================
// extractErrorMsg — with and without error attr
// ============================================================================

func TestExtractErrorMsgFound(t *testing.T) {
	attrs := []slog.Attr{
		slog.String("foo", "bar"),
		slog.String("error", "something broke"),
	}
	msg := extractErrorMsg(attrs)
	if msg != "something broke" {
		t.Errorf("extractErrorMsg: %s", msg)
	}
}

func TestExtractErrorMsgNotFound(t *testing.T) {
	attrs := []slog.Attr{slog.String("foo", "bar")}
	msg := extractErrorMsg(attrs)
	if msg != "error" {
		t.Errorf("default error msg: %s", msg)
	}
}

// ============================================================================
// send — dry run (no endpoint, no output)
// ============================================================================

func TestDryRunNoOutput(t *testing.T) {
	rec := NewOTLPRecorder("") // empty endpoint = dry run
	tel := telemetry.New(rec)
	// Should not panic even with no output
	span := tel.StartSpan(context.Background(), "dry.op")
	span.End()
	tel.Info("dry.log")
}

// ============================================================================
// service.name in resource
// ============================================================================

func TestServiceNameInResourceSpan(t *testing.T) {
	var buf bytes.Buffer
	rec := NewWriterRecorder(&buf)
	rec.Service = "my-service"
	tel := telemetry.New(rec)
	span := tel.StartSpan(context.Background(), "svc.op")
	span.End()
	out := buf.String()
	if !strings.Contains(out, "my-service") {
		t.Errorf("service name missing: %s", out)
	}
}

// ============================================================================
// Multiple spans — each gets unique traceID
// ============================================================================

func TestMultipleSpansUniqueTraceIDs(t *testing.T) {
	var buf bytes.Buffer
	rec := NewWriterRecorder(&buf)
	tel := telemetry.New(rec)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		s := tel.StartSpan(ctx, fmt.Sprintf("op.%d", i))
		s.End()
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	traceIDs := map[string]bool{}
	for _, line := range lines {
		var payload struct {
			ResourceSpans []struct {
				ScopeSpans []struct {
					Spans []OTLPSpan `json:"spans"`
				} `json:"scopeSpans"`
			} `json:"resourceSpans"`
		}
		if err := json.Unmarshal([]byte(line), &payload); err != nil {
			continue
		}
		for _, rs := range payload.ResourceSpans {
			for _, ss := range rs.ScopeSpans {
				for _, span := range ss.Spans {
					traceIDs[span.TraceID] = true
				}
			}
		}
	}
	if len(traceIDs) < 5 {
		t.Errorf("expected 5 unique traceIDs, got %d", len(traceIDs))
	}
}

// ============================================================================
// send — actual HTTP delivery path (coverage of Endpoint != "" branch)
// ============================================================================

func TestSendToHTTPEndpoint(t *testing.T) {
	received := make(chan []byte, 4)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		select {
		case received <- body:
		default:
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()

	rec := NewOTLPRecorder(ts.URL)
	tel := telemetry.New(rec)
	span := tel.StartSpan(context.Background(), "http-span")
	span.End()

	// send() is fire-and-forget in a goroutine; wait briefly for delivery
	select {
	case body := <-received:
		if len(body) == 0 {
			t.Error("received empty OTLP payload")
		}
	case <-time.After(2 * time.Second):
		t.Error("OTLP span was not delivered to HTTP endpoint")
	}
}

func TestSendLogToHTTPEndpoint(t *testing.T) {
	received := make(chan []byte, 4)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		select {
		case received <- body:
		default:
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()

	rec := NewOTLPRecorder(ts.URL)
	tel := telemetry.New(rec)
	tel.Info("log-to-otlp", slog.String("k", "v"))

	select {
	case <-received:
		// delivered
	case <-time.After(2 * time.Second):
		t.Error("OTLP log was not delivered")
	}
}
