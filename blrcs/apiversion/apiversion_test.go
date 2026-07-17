package apiversion

import (
	"strings"
	"sync"
	"testing"

	"blrcs/telemetry"
)

type captureRec struct {
	mu     sync.Mutex
	events []telemetry.Event
}

func (c *captureRec) Record(ev telemetry.Event) {
	c.mu.Lock()
	c.events = append(c.events, ev)
	c.mu.Unlock()
}

func (c *captureRec) eventsCopy() []telemetry.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make([]telemetry.Event, len(c.events))
	copy(cp, c.events)
	return cp
}

// ============================================================================
// Register / Lookup
// ============================================================================

func TestRegisterAndLookup(t *testing.T) {
	r := NewRegistry(nil)
	r.Register(API{Path: "test.Foo", IntroducedIn: "1.0.0", Stability: StabilityStable})

	a := r.Lookup("test.Foo")
	if a == nil {
		t.Fatal("not found")
	}
	if a.Path != "test.Foo" || a.IntroducedIn != "1.0.0" {
		t.Errorf("api: %+v", a)
	}
	if r.Lookup("nope") != nil {
		t.Error("missing api should return nil")
	}
}

func TestRegisterIgnoresEmptyPath(t *testing.T) {
	r := NewRegistry(nil)
	r.Register(API{Path: ""})
	if len(r.AllAPIs()) != 0 {
		t.Error("empty path should not register")
	}
}

// ============================================================================
// Deprecate
// ============================================================================

func TestDeprecate(t *testing.T) {
	r := NewRegistry(nil)
	r.Register(API{Path: "old.Func", IntroducedIn: "1.0.0", Stability: StabilityStable})

	ok := r.Deprecate("old.Func", Deprecation{
		Since: "2.0.0", RemoveIn: "3.0.0", Replacement: "new.Func",
		Reason: "rewritten with type safety",
	})
	if !ok {
		t.Fatal("deprecate failed")
	}
	a := r.Lookup("old.Func")
	if a.Stability != StabilityDeprecated {
		t.Errorf("stability: %s", a.Stability)
	}
	if a.Deprecated == nil || a.Deprecated.Replacement != "new.Func" {
		t.Errorf("deprecation: %+v", a.Deprecated)
	}
}

func TestDeprecateNonExistent(t *testing.T) {
	r := NewRegistry(nil)
	ok := r.Deprecate("nothing.Here", Deprecation{Since: "2.0"})
	if ok {
		t.Error("should fail to deprecate non-existent")
	}
}

// ============================================================================
// MarkUsed — warn rate-limited emission
// ============================================================================

func TestMarkUsedNonDeprecated(t *testing.T) {
	rec := &captureRec{}
	tel := telemetry.New(rec)
	r := NewRegistry(tel)
	r.Register(API{Path: "stable.Func", Stability: StabilityStable})

	for i := 0; i < 10; i++ {
		r.MarkUsed("stable.Func")
	}
	for _, ev := range rec.eventsCopy() {
		if strings.Contains(ev.Name, "deprecated") {
			t.Error("stable API should not emit deprecation warning")
		}
	}
	if r.UsageCount("stable.Func") != 10 {
		t.Errorf("usage count: %d", r.UsageCount("stable.Func"))
	}
}

func TestMarkUsedDeprecatedRateLimited(t *testing.T) {
	rec := &captureRec{}
	tel := telemetry.New(rec)
	r := NewRegistry(tel)
	r.Register(API{Path: "old.F", Stability: StabilityStable})
	r.Deprecate("old.F", Deprecation{
		Since: "2.0", RemoveIn: "3.0", Replacement: "new.F",
		WarnRateLimit: 10, // warn every 10th call
	})

	for i := 0; i < 25; i++ {
		r.MarkUsed("old.F")
	}
	// 1st, 11th, 21st calls warn (3 warnings)
	warnCount := 0
	for _, ev := range rec.eventsCopy() {
		if ev.Name == "apiversion.deprecated_call" {
			warnCount++
		}
	}
	if warnCount < 2 || warnCount > 3 {
		t.Errorf("expected 2-3 rate-limited warnings, got %d", warnCount)
	}

	// Counter should reflect warnings emitted
	snap := tel.Snapshot()
	if snap.Counters["apiversion.deprecated_calls"] < 2 {
		t.Errorf("counter: %d", snap.Counters["apiversion.deprecated_calls"])
	}
}

func TestMarkUsedDefaultRateLimit(t *testing.T) {
	rec := &captureRec{}
	tel := telemetry.New(rec)
	r := NewRegistry(tel)
	r.Register(API{Path: "x.F", Stability: StabilityStable})
	// no WarnRateLimit set → default 100
	r.Deprecate("x.F", Deprecation{Since: "2.0"})

	for i := 0; i < 50; i++ {
		r.MarkUsed("x.F")
	}
	warnCount := 0
	for _, ev := range rec.eventsCopy() {
		if ev.Name == "apiversion.deprecated_call" {
			warnCount++
		}
	}
	// Only the 1st warns (50 < 100)
	if warnCount != 1 {
		t.Errorf("default rate limit warns: %d", warnCount)
	}
}

// TestMarkUsedRateLimitOne pins that WarnRateLimit==1 (the most aggressive
// setting: warn on every call) actually warns on every call. The previous
// n%rate==1 test made rate==1 a no-op (n%1 is always 0), silently disabling
// all deprecation warnings — the opposite of the operator's intent.
func TestMarkUsedRateLimitOne(t *testing.T) {
	rec := &captureRec{}
	tel := telemetry.New(rec)
	r := NewRegistry(tel)
	r.Register(API{Path: "loud.F", Stability: StabilityStable})
	r.Deprecate("loud.F", Deprecation{
		Since: "2.0", RemoveIn: "3.0", Replacement: "new.F",
		WarnRateLimit: 1, // warn on EVERY call
	})

	const calls = 5
	for i := 0; i < calls; i++ {
		r.MarkUsed("loud.F")
	}
	warnCount := 0
	for _, ev := range rec.eventsCopy() {
		if ev.Name == "apiversion.deprecated_call" {
			warnCount++
		}
	}
	if warnCount != calls {
		t.Errorf("WarnRateLimit=1 should warn on every call: got %d warnings for %d calls", warnCount, calls)
	}
}

// ============================================================================
// AllAPIs / DeprecatedAPIs
// ============================================================================

func TestAllAPIsSorted(t *testing.T) {
	r := NewRegistry(nil)
	r.Register(API{Path: "z.A"}).Register(API{Path: "a.B"}).Register(API{Path: "m.C"})
	all := r.AllAPIs()
	if len(all) != 3 {
		t.Fatalf("got %d", len(all))
	}
	if all[0].Path != "a.B" || all[1].Path != "m.C" || all[2].Path != "z.A" {
		t.Errorf("not sorted: %v", []string{all[0].Path, all[1].Path, all[2].Path})
	}
}

func TestDeprecatedAPIs(t *testing.T) {
	r := NewRegistry(nil)
	r.Register(API{Path: "stable.A", Stability: StabilityStable})
	r.Register(API{Path: "old.B", Stability: StabilityStable})
	r.Deprecate("old.B", Deprecation{Since: "2.0"})

	deps := r.DeprecatedAPIs()
	if len(deps) != 1 {
		t.Fatalf("expected 1 deprecated, got %d", len(deps))
	}
	if deps[0].Path != "old.B" {
		t.Errorf("path: %s", deps[0].Path)
	}
}

// ============================================================================
// Changelog
// ============================================================================

func TestChangelog(t *testing.T) {
	r := NewRegistry(nil)
	r.Register(API{Path: "v1.A", IntroducedIn: "1.0.0"})
	r.Register(API{Path: "v2.B", IntroducedIn: "2.0.0"})
	r.Register(API{Path: "old.C", IntroducedIn: "1.0.0"})
	r.Deprecate("old.C", Deprecation{Since: "2.0.0", RemoveIn: "3.0.0"})

	cl := r.Changelog("2.0.0")
	if cl.Version != "2.0.0" {
		t.Errorf("version: %s", cl.Version)
	}
	// v2.B added
	if len(cl.Added) != 1 || cl.Added[0].Path != "v2.B" {
		t.Errorf("added: %+v", cl.Added)
	}
	// old.C deprecated
	if len(cl.Deprecated) != 1 || cl.Deprecated[0].Path != "old.C" {
		t.Errorf("deprecated: %+v", cl.Deprecated)
	}
}

// TestChangelogIncludesRemoved exercises the StabilityRemoved branch.
func TestChangelogIncludesRemoved(t *testing.T) {
	r := NewRegistry(nil)
	r.Register(API{Path: "gone.D", IntroducedIn: "1.0.0", Stability: StabilityRemoved})
	cl := r.Changelog("3.0.0")
	if len(cl.Removed) != 1 || cl.Removed[0].Path != "gone.D" {
		t.Errorf("removed: %+v", cl.Removed)
	}
}

// TestUsageCountUnknownPath exercises the unknown-path (return 0) branch.
func TestUsageCountUnknownPath(t *testing.T) {
	r := NewRegistry(nil)
	if c := r.UsageCount("never.registered"); c != 0 {
		t.Errorf("unknown path usage: want 0, got %d", c)
	}
}

// ============================================================================
// MigrationReports — prioritized by usage
// ============================================================================

func TestMigrationReportsSortedByUsage(t *testing.T) {
	r := NewRegistry(nil)
	r.Register(API{Path: "low.use", Stability: StabilityStable})
	r.Register(API{Path: "high.use", Stability: StabilityStable})
	r.Deprecate("low.use", Deprecation{Since: "2.0", RemoveIn: "3.0", Replacement: "low.new"})
	r.Deprecate("high.use", Deprecation{Since: "2.0", RemoveIn: "3.0", Replacement: "high.new"})

	for i := 0; i < 1000; i++ {
		r.MarkUsed("high.use")
	}
	for i := 0; i < 5; i++ {
		r.MarkUsed("low.use")
	}

	reports := r.MigrationReports()
	if len(reports) != 2 {
		t.Fatalf("got %d reports", len(reports))
	}
	// Highest usage first (highest priority)
	if reports[0].Path != "high.use" {
		t.Errorf("first report: %s (expected high.use)", reports[0].Path)
	}
	if reports[0].UsageCount != 1000 {
		t.Errorf("usage: %d", reports[0].UsageCount)
	}
}

// ============================================================================
// BLRCS default registry
// ============================================================================

func TestBLRCSDefaultRegistry(t *testing.T) {
	r := BLRCSDefaultRegistry(nil)
	apis := r.AllAPIs()
	if len(apis) < 10 {
		t.Errorf("expected ≥10 APIs, got %d", len(apis))
	}
	// Key APIs registered
	for _, want := range []string{
		"compliance.IssuePassport",
		"openid4vp.NewVerifier",
		"scitt.NewLedger",
		"builder.NewDPP",
	} {
		if r.Lookup(want) == nil {
			t.Errorf("missing key API: %s", want)
		}
	}
}

func TestReportLine(t *testing.T) {
	r := NewRegistry(nil)
	r.Register(API{Path: "x.F", IntroducedIn: "1.0.0", Stability: StabilityStable})
	line := r.ReportLine("x.F")
	if !strings.Contains(line, "x.F") || !strings.Contains(line, "1.0.0") {
		t.Errorf("line: %s", line)
	}
	r.Deprecate("x.F", Deprecation{Since: "2.0", RemoveIn: "3.0", Replacement: "x.G", Reason: "renamed"})
	line = r.ReportLine("x.F")
	if !strings.Contains(line, "deprecated") || !strings.Contains(line, "x.G") {
		t.Errorf("deprecated line: %s", line)
	}
	if !strings.Contains(r.ReportLine("nope"), "NOT REGISTERED") {
		t.Error("missing API line")
	}
}

func TestConcurrentMarkUsed(t *testing.T) {
	r := NewRegistry(telemetry.New(telemetry.NopRecorder{}))
	r.Register(API{Path: "concurrent.F", Stability: StabilityStable})

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.MarkUsed("concurrent.F")
		}()
	}
	wg.Wait()
	if r.UsageCount("concurrent.F") != 100 {
		t.Errorf("count: %d", r.UsageCount("concurrent.F"))
	}
}
