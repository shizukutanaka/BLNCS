// Package saga — Saga パターン (補正トランザクション)
//
// 設計: Microsoft / Netflix の saga pattern + Apple URLSession background tasks。
//
//	分散トランザクション無しで多段処理を扱う:
//
//	Issue→CAS→SCITT→Webhook の途中で失敗した場合、
//	既に実行済みステップを「逆操作」で巻き戻す。
//	→ 部分的な不整合状態を残さない (eventual consistency 前提)
//
// 解決する短所:
//   - "Workflow / saga無し — Issue→SCITT→Webhook 失敗時 partial state、
//     補正トランザクション不在"
//
// Apple原則:
//   - 各 Step は独立した小さな関数
//   - 失敗時の compensate も明示的に渡す (合意を強制)
//   - 部分実行ステップは確実に取り消し
//
// 利用例:
//
//	workflow := saga.New("issue-dpp").
//	    Step("issue", issueDPP, undoIssue).
//	    Step("save-cas", saveToCAS, undoCAS).
//	    Step("scitt-register", registerSCITT, undoSCITT).
//	    Step("webhook", fireWebhook, nil) // compensate なしも可
//	ctx_data, err := workflow.Run(ctx, initialState)
package saga

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// Errors
// ============================================================================

var (
	ErrStepFailed       = errors.New("saga: step failed")
	ErrCompensateFailed = errors.New("saga: compensate failed")
	ErrNoSteps          = errors.New("saga: no steps registered")
)

// ============================================================================
// State — saga 内で各 step が共有する key-value
// ============================================================================

// State — saga 実行中の共有データ
//
// 中間結果や補正に必要な値 (例: created credential ID) を格納
// 全 step は同じ State を読み書き可能
type State struct {
	mu   sync.RWMutex
	data map[string]any
}

// NewState — 初期データから State 構築
func NewState(initial map[string]any) *State {
	if initial == nil {
		initial = make(map[string]any)
	}
	return &State{data: initial}
}

// Set — key に値を設定
func (s *State) Set(key string, value any) {
	s.mu.Lock()
	s.data[key] = value
	s.mu.Unlock()
}

// Get — key で値を取得 (存在しないなら nil, false)
func (s *State) Get(key string) (any, bool) {
	s.mu.RLock()
	v, ok := s.data[key]
	s.mu.RUnlock()
	return v, ok
}

// String — debug 用
func (s *State) String(key string) string {
	v, ok := s.Get(key)
	if !ok {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

// Snapshot — copy of internal map (for inspection)
func (s *State) Snapshot() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make(map[string]any, len(s.data))
	for k, v := range s.data {
		cp[k] = v
	}
	return cp
}

// ============================================================================
// Step
// ============================================================================

// StepFunc — 順方向の処理
//
// 受け取る state に書き込み、失敗時はerror返却
// Apple: pure function 推奨、副作用は明示的に state に書込む
type StepFunc func(ctx context.Context, s *State) error

// CompensateFunc — 失敗時の逆操作
//
// nil の場合は no-op (取り消し不可な操作 — webhook 通知等)
type CompensateFunc func(ctx context.Context, s *State) error

// Step — 1ステップの定義
type Step struct {
	Name       string
	Do         StepFunc
	Compensate CompensateFunc
}

// ============================================================================
// Saga
// ============================================================================

// Saga — 順次 step + 失敗時 compensation
type Saga struct {
	Name  string
	steps []Step
}

// New — 空 Saga
func New(name string) *Saga {
	return &Saga{Name: name}
}

// Step — step を追加 (fluent API)
func (s *Saga) Step(name string, do StepFunc, compensate CompensateFunc) *Saga {
	s.steps = append(s.steps, Step{Name: name, Do: do, Compensate: compensate})
	return s
}

// Steps — 登録済 step 一覧 (debug 用)
func (s *Saga) Steps() []Step {
	cp := make([]Step, len(s.steps))
	copy(cp, s.steps)
	return cp
}

// ============================================================================
// Run — saga を実行
// ============================================================================

// RunReport — 実行結果サマリ
type RunReport struct {
	Name             string
	State            *State
	StepsCompleted   []string
	FailedStep       string
	StepError        error
	CompensateErrors map[string]error // step name → compensate error
	Duration         time.Duration
}

// Run — saga 実行
//
// 戻り値:
//
//	nil err → 全 step 成功、State 完成
//	err     → 失敗、既に実行済 step は逆順で compensate 実行
//
// compensate 自体が失敗した場合は ErrCompensateFailed を返す (運用時の手動介入対象)
func (s *Saga) Run(ctx context.Context, state *State) (*RunReport, error) {
	if len(s.steps) == 0 {
		return nil, ErrNoSteps
	}
	if state == nil {
		state = NewState(nil)
	}
	start := time.Now()
	report := &RunReport{
		Name:             s.Name,
		State:            state,
		CompensateErrors: make(map[string]error),
	}
	completedIdx := -1

	for i, step := range s.steps {
		if err := ctx.Err(); err != nil {
			report.FailedStep = step.Name
			report.StepError = err
			s.compensate(ctx, state, completedIdx, report)
			report.Duration = time.Since(start)
			return report, err
		}

		err := step.Do(ctx, state)
		if err != nil {
			report.FailedStep = step.Name
			report.StepError = fmt.Errorf("%w: step %q: %v", ErrStepFailed, step.Name, err)
			s.compensate(ctx, state, completedIdx, report)
			report.Duration = time.Since(start)
			return report, report.StepError
		}
		report.StepsCompleted = append(report.StepsCompleted, step.Name)
		completedIdx = i
	}
	report.Duration = time.Since(start)
	return report, nil
}

// compensate — 既に実行済 step を逆順に compensate
func (s *Saga) compensate(ctx context.Context, state *State, completedIdx int, report *RunReport) {
	for i := completedIdx; i >= 0; i-- {
		step := s.steps[i]
		if step.Compensate == nil {
			continue
		}
		s.runCompensation(ctx, state, step, report)
	}
}

// runCompensation executes a single compensation step, giving it a fresh
// context when the parent is already cancelled (so compensations always run
// even after context cancellation). Splitting into its own function ensures
// defer cancel() fires immediately when this function returns — not at the end
// of the compensate() loop, which would accumulate one timer goroutine per
// step for the entire duration of the compensation chain.
func (s *Saga) runCompensation(ctx context.Context, state *State, step Step, report *RunReport) {
	compCtx := ctx
	if ctx.Err() != nil {
		var cancel context.CancelFunc
		compCtx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
	}
	if err := step.Compensate(compCtx, state); err != nil {
		report.CompensateErrors[step.Name] = err
	}
}

// ============================================================================
// HasCompensateErrors — convenience
// ============================================================================

// HasCompensateErrors — compensate 失敗が発生したか (運用 alert 判定用)
func (r *RunReport) HasCompensateErrors() bool {
	return len(r.CompensateErrors) > 0
}

// CompensateErrorSummary — compensate 失敗の集計文字列
func (r *RunReport) CompensateErrorSummary() string {
	if len(r.CompensateErrors) == 0 {
		return ""
	}
	parts := make([]string, 0, len(r.CompensateErrors))
	for name, err := range r.CompensateErrors {
		parts = append(parts, fmt.Sprintf("%s: %v", name, err))
	}
	return strings.Join(parts, "; ")
}
