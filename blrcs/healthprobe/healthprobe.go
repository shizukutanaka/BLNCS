// Package healthprobe — Liveness / Readiness / Startup probes
//
// 設計: Kubernetes probe 仕様 + Apple launchd KeepAlive 思想。
//   - Liveness: プロセスが alive か (再起動判定)
//   - Readiness: トラフィック受付可能か (依存準備完了判定)
//   - Startup: 起動完了判定 (slow boot サービス用)
//
// 各 probe は配下に複数の Check を持ち、いずれかが失敗すれば NOT OK。
// レスポンスは構造化 JSON で原因詳細を含む (運用時のトラブルシュート支援)。
//
// 解決する短所:
//   - "Health/readiness 簡易 — /healthz が文字列のみ、依存サービス確認なし"
//
// 利用例:
//
//	probe := healthprobe.New()
//	probe.AddLiveness("memory", checkMemory)
//	probe.AddReadiness("ledger", checkLedger)
//	probe.AddReadiness("storage", checkStorage)
//	mux.Handle("/healthz", probe.Liveness())
//	mux.Handle("/readyz", probe.Readiness())
package healthprobe

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// ============================================================================
// Check
// ============================================================================

// Check — 1つの依存確認関数
//
// 期待動作:
//   - 成功: nil 返却
//   - 失敗: error 返却 (メッセージは公開、機密含めないこと)
//   - context cancellation を必ず尊重
type Check func(ctx context.Context) error

// CheckResult — JSON出力用の構造化結果
type CheckResult struct {
	Name     string `json:"name"`
	Status   string `json:"status"` // "ok" | "fail"
	Error    string `json:"error,omitempty"`
	Duration string `json:"duration"`
}

// Report — Probe の集約結果
type Report struct {
	Status    string        `json:"status"` // "ok" | "fail"
	Timestamp time.Time     `json:"timestamp"`
	Checks    []CheckResult `json:"checks"`
	OkCount   int           `json:"okCount"`
	FailCount int           `json:"failCount"`
}

// ============================================================================
// Probe
// ============================================================================

// Probe — Liveness/Readiness/Startup の集約
type Probe struct {
	Timeout time.Duration

	mu        sync.RWMutex
	liveness  map[string]Check
	readiness map[string]Check
	startup   map[string]Check
}

// New — 標準 5秒 timeout の Probe
func New() *Probe {
	return &Probe{
		Timeout:   5 * time.Second,
		liveness:  make(map[string]Check),
		readiness: make(map[string]Check),
		startup:   make(map[string]Check),
	}
}

// AddLiveness — liveness check 登録
func (p *Probe) AddLiveness(name string, check Check) {
	p.mu.Lock()
	p.liveness[name] = check
	p.mu.Unlock()
}

// AddReadiness — readiness check 登録
func (p *Probe) AddReadiness(name string, check Check) {
	p.mu.Lock()
	p.readiness[name] = check
	p.mu.Unlock()
}

// AddStartup — startup check 登録
func (p *Probe) AddStartup(name string, check Check) {
	p.mu.Lock()
	p.startup[name] = check
	p.mu.Unlock()
}

// ============================================================================
// Run — 全 check を並列実行
// ============================================================================

func (p *Probe) runChecks(ctx context.Context, checks map[string]Check) Report {
	p.mu.RLock()
	cp := make(map[string]Check, len(checks))
	for k, v := range checks {
		cp[k] = v
	}
	p.mu.RUnlock()

	if len(cp) == 0 {
		// No checks registered — default to OK
		return Report{
			Status:    "ok",
			Timestamp: time.Now().UTC(),
			Checks:    []CheckResult{},
		}
	}

	results := make([]CheckResult, 0, len(cp))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for name, check := range cp {
		wg.Add(1)
		go func(name string, check Check) {
			defer wg.Done()
			start := time.Now()
			r := CheckResult{Name: name}
			// Run the check in an inner func so a panic is converted into a "fail"
			// result rather than being swallowed. The previous code recovered the
			// panic but then returned WITHOUT appending any result, so a panicking
			// readiness check silently vanished from the report — and if the other
			// checks passed, the endpoint returned 200 OK while a check was broken
			// (fail-open: Kubernetes would keep routing traffic to the pod). Treat a
			// panic as a failure, matching the documented intent.
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						r.Status = "fail"
						r.Error = fmt.Sprintf("check panicked: %v", rec)
					}
				}()
				runCtx, cancel := context.WithTimeout(ctx, p.Timeout)
				defer cancel()
				if err := check(runCtx); err != nil {
					r.Status = "fail"
					r.Error = err.Error()
				} else {
					r.Status = "ok"
				}
			}()
			r.Duration = time.Since(start).String()
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		}(name, check)
	}
	wg.Wait()

	report := Report{
		Status:    "ok",
		Timestamp: time.Now().UTC(),
		Checks:    results,
	}
	for _, r := range results {
		if r.Status == "ok" {
			report.OkCount++
		} else {
			report.FailCount++
			report.Status = "fail"
		}
	}
	return report
}

// ============================================================================
// HTTP Handlers
// ============================================================================

// Liveness — GET /healthz handler
func (p *Probe) Liveness() http.Handler {
	return p.makeHandler(func(ctx context.Context) Report {
		return p.runChecks(ctx, p.liveness)
	})
}

// Readiness — GET /readyz handler
func (p *Probe) Readiness() http.Handler {
	return p.makeHandler(func(ctx context.Context) Report {
		return p.runChecks(ctx, p.readiness)
	})
}

// Startup — GET /startupz handler
func (p *Probe) Startup() http.Handler {
	return p.makeHandler(func(ctx context.Context) Report {
		return p.runChecks(ctx, p.startup)
	})
}

func (p *Probe) makeHandler(runner func(ctx context.Context) Report) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		report := runner(r.Context())
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if report.Status == "ok" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		if r.Method == http.MethodHead {
			return
		}
		_ = json.NewEncoder(w).Encode(report)
	})
}

// ============================================================================
// Pre-built common checks
// ============================================================================

// AlwaysOK — 常に成功 (sanity / wiring 確認用)
func AlwaysOK() Check {
	return func(ctx context.Context) error { return nil }
}

// AlwaysFail — 常に失敗 (テスト用)
func AlwaysFail(msg string) Check {
	return func(ctx context.Context) error {
		return checkErr(msg)
	}
}

// Closure — 既存の関数を Check に変換
func Closure(fn func() error) Check {
	return func(ctx context.Context) error {
		// context cancellation を respect
		done := make(chan error, 1)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					done <- checkErr(fmt.Sprintf("panic: %v", r))
				}
			}()
			done <- fn()
		}()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-done:
			return err
		}
	}
}

// ============================================================================
// Internal error type
// ============================================================================

type checkErr string

func (e checkErr) Error() string { return string(e) }
