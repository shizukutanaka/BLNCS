// Package telemetry provides structured observability with spans, counters, and
// histograms. Designed for zero overhead when disabled (NopRecorder).
//
// Core types: Telemetry, Span, Counter, Histogram, SlogRecorder.
// Counters use atomic.Int64 (lock-free). Histograms use 1024-sample reservoir sampling.
//
// Compatible with the otelbridge package for OpenTelemetry OTLP export.
package telemetry
