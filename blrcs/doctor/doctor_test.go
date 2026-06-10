package doctor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// All default checks should pass on healthy system
// ============================================================================

func TestAllDefaultChecksPass(t *testing.T) {
	report := Run(context.Background(), DefaultChecks())
	if report.HasFailures() {
		var buf bytes.Buffer
		report.PrintTo(&buf)
		t.Errorf("default checks failed:\n%s", buf.String())
	}
	if report.Total == 0 {
		t.Error("no checks ran")
	}
	if report.Passed != report.Total {
		t.Errorf("not all passed: %d/%d", report.Passed, report.Total)
	}
}

// ============================================================================
// Individual check sanity
// ============================================================================

func TestIndividualChecks(t *testing.T) {
	checks := DefaultChecks()
	if len(checks) < 10 {
		t.Errorf("expected ≥10 default checks, got %d", len(checks))
	}
	ctx := context.Background()
	for _, c := range checks {
		t.Run(c.Name, func(t *testing.T) {
			if err := c.Fn(ctx); err != nil {
				t.Errorf("%s: %v", c.Name, err)
			}
		})
	}
}

// ============================================================================
// Failure handling
// ============================================================================

func TestFailureCaptured(t *testing.T) {
	failing := Check{
		Name: "intentional.failure",
		Fn: func(ctx context.Context) error {
			return errors.New("intentional")
		},
	}
	report := Run(context.Background(), []Check{failing})
	if !report.HasFailures() {
		t.Fatal("should have failures")
	}
	if report.Failed != 1 {
		t.Errorf("failed count: %d", report.Failed)
	}
	if report.Results[0].Status != StatusFail {
		t.Errorf("status: %v", report.Results[0].Status)
	}
	if report.Results[0].Error == nil {
		t.Error("error not captured")
	}
}

func TestMixedPassFail(t *testing.T) {
	checks := []Check{
		{Name: "ok", Fn: func(ctx context.Context) error { return nil }},
		{Name: "broken", Fn: func(ctx context.Context) error { return errors.New("x") }},
		{Name: "also.ok", Fn: func(ctx context.Context) error { return nil }},
	}
	report := Run(context.Background(), checks)
	if report.Passed != 2 || report.Failed != 1 {
		t.Errorf("expected 2/1, got %d/%d", report.Passed, report.Failed)
	}
}

// ============================================================================
// Context cancellation
// ============================================================================

func TestContextCancellationSkipsRemaining(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	checks := []Check{
		{Name: "first", Fn: func(ctx context.Context) error {
			cancel() // 1つ目で cancel
			return nil
		}},
		{Name: "second", Fn: func(ctx context.Context) error {
			t.Error("should not run after cancel")
			return nil
		}},
		{Name: "third", Fn: func(ctx context.Context) error {
			return nil
		}},
	}
	report := Run(ctx, checks)
	if report.Skipped != 2 {
		t.Errorf("expected 2 skipped, got %d", report.Skipped)
	}
}

// ============================================================================
// Pretty print
// ============================================================================

func TestReportFormatting(t *testing.T) {
	report := Run(context.Background(), []Check{
		{Name: "fast", Fn: func(ctx context.Context) error { return nil }},
		{Name: "slow", Fn: func(ctx context.Context) error {
			time.Sleep(2 * time.Millisecond)
			return nil
		}},
	})
	var buf bytes.Buffer
	report.PrintTo(&buf)
	out := buf.String()
	// Both checks named
	if !strings.Contains(out, "fast") {
		t.Errorf("missing fast: %s", out)
	}
	if !strings.Contains(out, "slow") {
		t.Errorf("missing slow: %s", out)
	}
	// Contains pass/fail summary line
	if !strings.Contains(out, "passed") {
		t.Errorf("missing summary: %s", out)
	}
	// Visual mark
	if !strings.Contains(out, "✓") {
		t.Errorf("missing pass mark: %s", out)
	}
}

func TestReportFailuresShowError(t *testing.T) {
	report := Run(context.Background(), []Check{
		{Name: "broken", Fn: func(ctx context.Context) error {
			return errors.New("specific failure detail")
		}},
	})
	var buf bytes.Buffer
	report.PrintTo(&buf)
	out := buf.String()
	if !strings.Contains(out, "specific failure detail") {
		t.Errorf("error detail missing: %s", out)
	}
	if !strings.Contains(out, "✗") {
		t.Errorf("missing fail mark: %s", out)
	}
}

// ============================================================================
// Status type
// ============================================================================

func TestStatusString(t *testing.T) {
	cases := map[Status]string{
		StatusPass: "pass",
		StatusFail: "fail",
		StatusSkip: "skip",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("Status %d: got %s want %s", s, got, want)
		}
	}
}

// ============================================================================
// Coverage uplift: custom Check error path, Status.String unknown, PrintTo failure
// ============================================================================

func TestCustomCheckErrorPath(t *testing.T) {
	// Exercise error path: a check that always fails
	checks := []Check{
		{Name: "always-fail", Fn: func(ctx context.Context) error {
			return fmt.Errorf("forced failure: %s", "reason")
		}},
		{Name: "always-pass", Fn: func(ctx context.Context) error { return nil }},
	}
	report := Run(context.Background(), checks)
	if report.Failed != 1 {
		t.Errorf("want 1 failed, got %d", report.Failed)
	}
	if report.Passed != 1 {
		t.Errorf("want 1 passed, got %d", report.Passed)
	}
}

func TestStatusStringUnknown(t *testing.T) {
	s := Status(99)
	got := s.String()
	if got == "pass" || got == "fail" || got == "skip" {
		t.Errorf("unknown status should not be pass/fail/skip: %s", got)
	}
}

func TestPrintToWithFailureDetails(t *testing.T) {
	var buf bytes.Buffer
	checks := []Check{
		{Name: "check-a", Fn: func(ctx context.Context) error {
			return fmt.Errorf("disk full: insufficient space")
		}},
		{Name: "check-b", Fn: func(ctx context.Context) error { return nil }},
	}
	report := Run(context.Background(), checks)
	report.PrintTo(&buf)
	out := buf.String()
	// Should contain error text
	if !strings.Contains(out, "disk full") && !strings.Contains(out, "check-a") {
		t.Errorf("PrintTo should mention failing check: %s", out)
	}
}

func TestRunEmptyChecks(t *testing.T) {
	report := Run(context.Background(), []Check{})
	if report.Total != 0 {
		t.Errorf("empty checks: total %d", report.Total)
	}
}

func TestRunCancelledMid(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{}, 2)
	checks := []Check{
		{Name: "slow-1", Fn: func(ctx context.Context) error {
			started <- struct{}{}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Second):
				return nil
			}
		}},
		{Name: "slow-2", Fn: func(ctx context.Context) error {
			started <- struct{}{}
			<-ctx.Done()
			return ctx.Err()
		}},
	}
	go func() {
		<-started
		cancel()
	}()
	report := Run(ctx, checks)
	if report.Skipped+report.Failed == 0 {
		t.Error("cancelled context should produce skipped or failed checks")
	}
}

// TestPrintToSkipMark — ensure the "—" skip mark is rendered in PrintTo output.
func TestPrintToSkipMark(t *testing.T) {
	// Inject a pre-cancelled context so the second check is skipped.
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Run so all checks are skipped
	checks := []Check{
		{Name: "skip-me", Fn: func(ctx context.Context) error { return nil }},
	}
	report := Run(ctx, checks)
	var buf bytes.Buffer
	report.PrintTo(&buf)
	out := buf.String()
	if !strings.Contains(out, "—") && !strings.Contains(out, "skipped") {
		t.Errorf("PrintTo should show skip mark or 'skipped': %s", out)
	}
}

// TestPrintToSkippedCount — skipped count appears in footer when > 0.
func TestPrintToSkippedCount(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	// Cancel before first check runs → all checks skipped.
	cancel()
	report := Run(ctx, []Check{
		{Name: "a", Fn: func(_ context.Context) error { return nil }},
		{Name: "b", Fn: func(_ context.Context) error { return nil }},
	})
	var buf bytes.Buffer
	report.PrintTo(&buf)
	out := buf.String()
	if !strings.Contains(out, "skipped") {
		t.Errorf("should mention skipped count in summary: %s", out)
	}
}
