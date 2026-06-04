package healthprobe

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// Empty probe — defaults to OK
// ============================================================================

func TestEmptyProbeReturnsOK(t *testing.T) {
	p := New()
	ts := httptest.NewServer(p.Liveness())
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status: %d", resp.StatusCode)
	}
}

// ============================================================================
// Successful checks
// ============================================================================

func TestAllChecksPass(t *testing.T) {
	p := New()
	p.AddLiveness("a", AlwaysOK())
	p.AddLiveness("b", AlwaysOK())
	p.AddLiveness("c", AlwaysOK())

	ts := httptest.NewServer(p.Liveness())
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status: %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var report Report
	if err := json.Unmarshal(body, &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "ok" {
		t.Errorf("status: %s", report.Status)
	}
	if report.OkCount != 3 || report.FailCount != 0 {
		t.Errorf("counts: ok=%d fail=%d", report.OkCount, report.FailCount)
	}
	if len(report.Checks) != 3 {
		t.Errorf("checks: %d", len(report.Checks))
	}
}

// ============================================================================
// Failing check
// ============================================================================

func TestSingleCheckFailsCausesNotOK(t *testing.T) {
	p := New()
	p.AddReadiness("ok-check", AlwaysOK())
	p.AddReadiness("bad-check", AlwaysFail("dependency unavailable"))

	ts := httptest.NewServer(p.Readiness())
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status: %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var report Report
	json.Unmarshal(body, &report)
	if report.Status != "fail" {
		t.Errorf("report status: %s", report.Status)
	}
	// Find bad-check in results and verify error message present
	foundError := false
	for _, c := range report.Checks {
		if c.Name == "bad-check" {
			if c.Status != "fail" {
				t.Errorf("bad-check status: %s", c.Status)
			}
			if !strings.Contains(c.Error, "dependency unavailable") {
				t.Errorf("error message: %s", c.Error)
			}
			foundError = true
		}
	}
	if !foundError {
		t.Error("bad-check missing from report")
	}
}

// ============================================================================
// Parallel execution
// ============================================================================

func TestChecksRunInParallel(t *testing.T) {
	p := New()
	const n = 5
	const each = 100 * time.Millisecond
	for i := 0; i < n; i++ {
		p.AddLiveness("slow-"+string(rune('a'+i)), func(ctx context.Context) error {
			time.Sleep(each)
			return nil
		})
	}
	ts := httptest.NewServer(p.Liveness())
	defer ts.Close()

	start := time.Now()
	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	dur := time.Since(start)

	// Sequential = 500ms; parallel ~100ms (allow 250ms slack)
	if dur > 250*time.Millisecond {
		t.Errorf("checks not parallel: %v elapsed", dur)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status: %d", resp.StatusCode)
	}
}

// ============================================================================
// Timeout enforcement
// ============================================================================

func TestCheckTimeout(t *testing.T) {
	p := New()
	p.Timeout = 50 * time.Millisecond
	p.AddLiveness("slow", func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(1 * time.Second):
			return nil
		}
	})
	ts := httptest.NewServer(p.Liveness())
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status: %d", resp.StatusCode)
	}
}

// ============================================================================
// Method restrictions
// ============================================================================

func TestMethodRestrictions(t *testing.T) {
	p := New()
	ts := httptest.NewServer(p.Liveness())
	defer ts.Close()

	for _, method := range []string{"POST", "PUT", "DELETE"} {
		req, _ := http.NewRequest(method, ts.URL, nil)
		resp, _ := http.DefaultClient.Do(req)
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s: want 405, got %d", method, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

func TestHEADRequestSkipsBody(t *testing.T) {
	p := New()
	p.AddLiveness("ok", AlwaysOK())
	ts := httptest.NewServer(p.Liveness())
	defer ts.Close()

	req, _ := http.NewRequest("HEAD", ts.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status: %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Errorf("HEAD should have empty body, got %d bytes", len(body))
	}
}

// ============================================================================
// Liveness/Readiness/Startup independence
// ============================================================================

func TestProbeKindsIndependent(t *testing.T) {
	p := New()
	p.AddLiveness("alive", AlwaysOK())
	p.AddReadiness("ready", AlwaysFail("not ready"))
	p.AddStartup("start", AlwaysOK())

	livets := httptest.NewServer(p.Liveness())
	readyts := httptest.NewServer(p.Readiness())
	startts := httptest.NewServer(p.Startup())
	defer livets.Close()
	defer readyts.Close()
	defer startts.Close()

	resp, _ := http.Get(livets.URL)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("liveness: %d", resp.StatusCode)
	}
	resp, _ = http.Get(readyts.URL)
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("readiness should fail: %d", resp.StatusCode)
	}
	resp, _ = http.Get(startts.URL)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("startup: %d", resp.StatusCode)
	}
}

// ============================================================================
// Closure helper
// ============================================================================

func TestClosureRespectContextCancel(t *testing.T) {
	called := atomic.Bool{}
	check := Closure(func() error {
		called.Store(true)
		time.Sleep(500 * time.Millisecond)
		return nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	err := check(ctx)
	if err != context.DeadlineExceeded {
		t.Errorf("want DeadlineExceeded, got %v", err)
	}
}

func TestClosureSuccess(t *testing.T) {
	check := Closure(func() error { return nil })
	if err := check(context.Background()); err != nil {
		t.Error(err)
	}
}

func TestClosurePropagatesError(t *testing.T) {
	check := Closure(func() error { return errors.New("specific") })
	err := check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "specific") {
		t.Errorf("error: %v", err)
	}
}

// ============================================================================
// JSON output structure
// ============================================================================

func TestJSONStructure(t *testing.T) {
	p := New()
	p.AddLiveness("a", AlwaysOK())
	p.AddLiveness("b", AlwaysFail("nope"))

	ts := httptest.NewServer(p.Liveness())
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	out := string(body)

	for _, want := range []string{
		`"status":"fail"`,
		`"okCount":1`,
		`"failCount":1`,
		`"name":"a"`,
		`"name":"b"`,
		`"error":"nope"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in: %s", want, out)
		}
	}
}
