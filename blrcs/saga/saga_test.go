package saga

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// State helpers
// ============================================================================

func TestStateSetGet(t *testing.T) {
	s := NewState(map[string]any{"foo": "initial"})
	if v, _ := s.Get("foo"); v != "initial" {
		t.Errorf("initial: %v", v)
	}
	s.Set("bar", 42)
	if v, _ := s.Get("bar"); v != 42 {
		t.Errorf("set/get: %v", v)
	}
	if _, ok := s.Get("missing"); ok {
		t.Error("missing should be false")
	}
}

func TestStateSnapshot(t *testing.T) {
	s := NewState(map[string]any{"a": 1, "b": 2})
	snap := s.Snapshot()
	if len(snap) != 2 {
		t.Errorf("snapshot size: %d", len(snap))
	}
	// Modifying snapshot doesn't affect original
	snap["c"] = 3
	if _, ok := s.Get("c"); ok {
		t.Error("snapshot should be independent")
	}
}

func TestStateNilInitial(t *testing.T) {
	s := NewState(nil)
	s.Set("x", 1)
	if v, _ := s.Get("x"); v != 1 {
		t.Errorf("nil initial: %v", v)
	}
}

// ============================================================================
// Empty saga
// ============================================================================

func TestEmptySagaFails(t *testing.T) {
	s := New("empty")
	_, err := s.Run(context.Background(), nil)
	if !errors.Is(err, ErrNoSteps) {
		t.Errorf("want ErrNoSteps, got %v", err)
	}
}

// ============================================================================
// Happy path
// ============================================================================

func TestHappyPathAllStepsRun(t *testing.T) {
	executed := []string{}
	s := New("happy").
		Step("a", func(ctx context.Context, s *State) error {
			executed = append(executed, "a")
			s.Set("a-result", "ok")
			return nil
		}, nil).
		Step("b", func(ctx context.Context, s *State) error {
			executed = append(executed, "b")
			s.Set("b-result", "ok")
			return nil
		}, nil).
		Step("c", func(ctx context.Context, s *State) error {
			executed = append(executed, "c")
			return nil
		}, nil)

	report, err := s.Run(context.Background(), NewState(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(executed) != 3 {
		t.Errorf("expected 3 steps, got %d: %v", len(executed), executed)
	}
	if len(report.StepsCompleted) != 3 {
		t.Errorf("completed: %v", report.StepsCompleted)
	}
	if v, _ := report.State.Get("a-result"); v != "ok" {
		t.Errorf("state propagation: %v", v)
	}
}

// ============================================================================
// Mid-failure → compensate in reverse
// ============================================================================

func TestMidFailureCompensatesInReverse(t *testing.T) {
	executedOrder := []string{}
	compensatedOrder := []string{}

	s := New("with-failure").
		Step("step1",
			func(ctx context.Context, s *State) error {
				executedOrder = append(executedOrder, "step1.do")
				return nil
			},
			func(ctx context.Context, s *State) error {
				compensatedOrder = append(compensatedOrder, "step1.undo")
				return nil
			},
		).
		Step("step2",
			func(ctx context.Context, s *State) error {
				executedOrder = append(executedOrder, "step2.do")
				return nil
			},
			func(ctx context.Context, s *State) error {
				compensatedOrder = append(compensatedOrder, "step2.undo")
				return nil
			},
		).
		Step("step3-fails",
			func(ctx context.Context, s *State) error {
				executedOrder = append(executedOrder, "step3.do")
				return errors.New("step3 failed")
			},
			func(ctx context.Context, s *State) error {
				compensatedOrder = append(compensatedOrder, "step3.undo")
				return nil
			},
		).
		Step("step4-never-runs",
			func(ctx context.Context, s *State) error {
				executedOrder = append(executedOrder, "step4.do")
				return nil
			},
			nil,
		)

	report, err := s.Run(context.Background(), NewState(nil))
	if err == nil {
		t.Fatal("should have failed")
	}
	if !errors.Is(err, ErrStepFailed) {
		t.Errorf("expected ErrStepFailed, got %v", err)
	}
	// step3 attempted, step4 never reached
	wantExec := []string{"step1.do", "step2.do", "step3.do"}
	if !equalSlices(executedOrder, wantExec) {
		t.Errorf("execution order: %v want %v", executedOrder, wantExec)
	}
	// Compensates run in REVERSE: step3 NOT compensated (its do failed),
	// step2 then step1 (in reverse of execution order)
	wantUndo := []string{"step2.undo", "step1.undo"}
	if !equalSlices(compensatedOrder, wantUndo) {
		t.Errorf("compensate order: %v want %v", compensatedOrder, wantUndo)
	}
	if report.FailedStep != "step3-fails" {
		t.Errorf("failed step: %s", report.FailedStep)
	}
}

// ============================================================================
// Compensate without compensate function — no-op (Webhook style)
// ============================================================================

func TestNilCompensateIsSkipped(t *testing.T) {
	executed := []string{}
	s := New("with-nil-compensate").
		Step("step1",
			func(ctx context.Context, s *State) error {
				executed = append(executed, "step1.do")
				return nil
			},
			nil, // no compensate (e.g. fired webhook can't be unsent)
		).
		Step("step2-fails",
			func(ctx context.Context, s *State) error {
				return errors.New("oops")
			},
			nil,
		)

	_, err := s.Run(context.Background(), NewState(nil))
	if err == nil {
		t.Fatal("should fail")
	}
	if len(executed) != 1 {
		t.Errorf("step1 should have run: %v", executed)
	}
	// No panic — nil compensate handled
}

// ============================================================================
// Compensate failure tracked
// ============================================================================

func TestCompensateFailureTracked(t *testing.T) {
	s := New("compensate-fail").
		Step("step1",
			func(ctx context.Context, s *State) error { return nil },
			func(ctx context.Context, s *State) error {
				return errors.New("compensate failed!")
			},
		).
		Step("step2",
			func(ctx context.Context, s *State) error {
				return errors.New("forced failure")
			},
			nil,
		)

	report, err := s.Run(context.Background(), NewState(nil))
	if err == nil {
		t.Fatal("should fail")
	}
	if !report.HasCompensateErrors() {
		t.Error("compensate errors should be tracked")
	}
	summary := report.CompensateErrorSummary()
	if !strings.Contains(summary, "compensate failed") {
		t.Errorf("compensate summary: %s", summary)
	}
}

// ============================================================================
// Context cancellation
// ============================================================================

func TestContextCancellationRollsBack(t *testing.T) {
	var step2Compensated atomic.Bool
	ctx, cancel := context.WithCancel(context.Background())

	s := New("ctx-cancel").
		Step("step1",
			func(ctx context.Context, s *State) error {
				return nil
			},
			func(ctx context.Context, s *State) error {
				return nil
			},
		).
		Step("step2",
			func(ctx context.Context, s *State) error {
				cancel() // cancel during step2
				return nil
			},
			func(ctx context.Context, s *State) error {
				step2Compensated.Store(true)
				return nil
			},
		).
		Step("step3-never-reached",
			func(ctx context.Context, s *State) error {
				t.Error("should not reach step3 after cancel")
				return nil
			},
			nil,
		)

	report, err := s.Run(ctx, NewState(nil))
	if err == nil {
		t.Fatal("should fail with context error")
	}
	// step2 was completed — should be compensated
	if !step2Compensated.Load() {
		t.Error("step2 compensate should have run")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
	_ = report
}

// ============================================================================
// State propagation
// ============================================================================

func TestStateAccessibleAcrossSteps(t *testing.T) {
	s := New("state-prop").
		Step("create", func(ctx context.Context, s *State) error {
			s.Set("created-id", "id-123")
			return nil
		}, nil).
		Step("use", func(ctx context.Context, s *State) error {
			id, _ := s.Get("created-id")
			if id != "id-123" {
				return fmt.Errorf("missing id: %v", id)
			}
			s.Set("used-id", id)
			return nil
		}, nil)

	report, err := s.Run(context.Background(), NewState(nil))
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := report.State.Get("used-id"); v != "id-123" {
		t.Errorf("state propagation broken: %v", v)
	}
}

func TestCompensateSeesStateFromDo(t *testing.T) {
	var capturedID atomic.Value

	s := New("compensate-uses-state").
		Step("create",
			func(ctx context.Context, s *State) error {
				s.Set("resource-id", "r-456")
				return nil
			},
			func(ctx context.Context, s *State) error {
				if v, ok := s.Get("resource-id"); ok {
					capturedID.Store(v)
				}
				return nil
			},
		).
		Step("fail-step",
			func(ctx context.Context, s *State) error {
				return errors.New("fail")
			},
			nil,
		)

	_, _ = s.Run(context.Background(), NewState(nil))
	if v := capturedID.Load(); v != "r-456" {
		t.Errorf("compensate could not see state from do: %v", v)
	}
}

// ============================================================================
// Concurrent state access (within same saga)
// ============================================================================

func TestStateConcurrentAccess(t *testing.T) {
	state := NewState(nil)
	done := make(chan struct{}, 100)
	for i := 0; i < 100; i++ {
		go func() {
			state.Set(fmt.Sprintf("k-%d", i), i)
			state.Snapshot()
			done <- struct{}{}
		}()
	}
	for i := 0; i < 100; i++ {
		<-done
	}
	if len(state.Snapshot()) != 100 {
		t.Errorf("concurrent set: got %d", len(state.Snapshot()))
	}
}

// ============================================================================
// Real-world usage simulation: Issue→CAS→SCITT→Webhook
// ============================================================================

func TestSimulatedIssueWorkflow(t *testing.T) {
	scittRegistered := atomic.Bool{}
	scittRolledBack := atomic.Bool{}
	casStored := atomic.Bool{}
	casRolledBack := atomic.Bool{}

	workflow := New("issue-dpp").
		Step("issue-credential",
			func(ctx context.Context, s *State) error {
				s.Set("credential-id", "cred-001")
				return nil
			},
			func(ctx context.Context, s *State) error {
				s.Set("credential-revoked", true)
				return nil
			},
		).
		Step("save-cas",
			func(ctx context.Context, s *State) error {
				casStored.Store(true)
				s.Set("cas-hash", "abc123")
				return nil
			},
			func(ctx context.Context, s *State) error {
				casRolledBack.Store(true)
				return nil
			},
		).
		Step("scitt-register",
			func(ctx context.Context, s *State) error {
				// Simulate SCITT failing
				return errors.New("SCITT ledger unavailable")
			},
			func(ctx context.Context, s *State) error {
				scittRolledBack.Store(true)
				return nil
			},
		).
		Step("webhook",
			func(ctx context.Context, s *State) error {
				t.Error("webhook should not fire after SCITT fail")
				return nil
			},
			nil,
		)

	report, err := workflow.Run(context.Background(), NewState(nil))
	if err == nil {
		t.Fatal("should fail with SCITT error")
	}
	// Earlier steps should be rolled back
	if !casRolledBack.Load() {
		t.Error("CAS should be rolled back")
	}
	if !casStored.Load() {
		t.Error("CAS should have been attempted")
	}
	// SCITT itself didn't complete, so no rollback
	if scittRegistered.Load() {
		t.Error("SCITT should NOT have completed")
	}
	if scittRolledBack.Load() {
		t.Error("SCITT failed do — its compensate should NOT run")
	}
	if revoked, _ := report.State.Get("credential-revoked"); revoked != true {
		t.Error("credential should be revoked in compensate")
	}
}

// ============================================================================
// helpers
// ============================================================================

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Ensure time import remains used
var _ = time.Now

func TestSagaSteps(t *testing.T) {
	s := New("test-saga")
	s.Step("step1", func(ctx context.Context, st *State) error { return nil }, nil)
	s.Step("step2", func(ctx context.Context, st *State) error { return nil }, nil)
	steps := s.Steps()
	if len(steps) != 2 {
		t.Fatalf("want 2 steps, got %d", len(steps))
	}
	if steps[0].Name != "step1" {
		t.Errorf("step 0 name: %s", steps[0].Name)
	}
	if steps[1].Name != "step2" {
		t.Errorf("step 1 name: %s", steps[1].Name)
	}
	// Mutating the returned slice must not affect the saga
	steps[0].Name = "mutated"
	if s.Steps()[0].Name != "step1" {
		t.Error("Steps() should return a copy")
	}
}

func TestStateString(t *testing.T) {
	st := NewState(map[string]any{"key": "hello", "num": 42})
	if got := st.String("key"); got != "hello" {
		t.Errorf("String: %q", got)
	}
	// Non-string value → fmt.Sprintf("%v", v)
	if got := st.String("num"); got != "42" {
		t.Errorf("String(non-string): %q", got)
	}
	// Missing key → ""
	if got := st.String("missing"); got != "" {
		t.Errorf("String(missing): %q", got)
	}
}
