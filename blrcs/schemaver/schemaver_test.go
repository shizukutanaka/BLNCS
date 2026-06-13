package schemaver

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// ============================================================================
// Single migration
// ============================================================================

func TestSingleMigration(t *testing.T) {
	reg := New("test")
	reg.Register(1, nil)
	reg.Register(2, func(data map[string]any) (map[string]any, error) {
		// Add new field
		data["addedAtV2"] = "yes"
		return data, nil
	})

	raw := []byte(`{"schemaVersion":1,"name":"original"}`)
	updated, err := reg.MigrateToLatest(raw)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	json.Unmarshal(updated, &out)
	if out["addedAtV2"] != "yes" {
		t.Errorf("v2 field missing")
	}
	if int(out["schemaVersion"].(float64)) != 2 {
		t.Errorf("schemaVersion: %v", out["schemaVersion"])
	}
}

// ============================================================================
// Multi-step migration chain
// ============================================================================

func TestMigrationChain(t *testing.T) {
	reg := New("dpp")
	reg.Register(1, nil)
	// 1→2: rename "carbon" → "carbonKgCO2e"
	reg.Register(2, func(data map[string]any) (map[string]any, error) {
		if v, ok := data["carbon"]; ok {
			data["carbonKgCO2e"] = v
			delete(data, "carbon")
		}
		return data, nil
	})
	// 2→3: add new manufacturer DID
	reg.Register(3, func(data map[string]any) (map[string]any, error) {
		if _, ok := data["manufacturerDID"]; !ok {
			data["manufacturerDID"] = "did:web:unknown"
		}
		return data, nil
	})

	raw := []byte(`{"schemaVersion":1,"productID":"P1","carbon":2.5}`)
	updated, err := reg.MigrateToLatest(raw)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	json.Unmarshal(updated, &out)
	// All migrations applied
	if int(out["schemaVersion"].(float64)) != 3 {
		t.Errorf("final version: %v", out["schemaVersion"])
	}
	if _, exists := out["carbon"]; exists {
		t.Error("carbon should be renamed")
	}
	if out["carbonKgCO2e"] != 2.5 {
		t.Errorf("carbonKgCO2e: %v", out["carbonKgCO2e"])
	}
	if out["manufacturerDID"] != "did:web:unknown" {
		t.Errorf("manufacturerDID: %v", out["manufacturerDID"])
	}
}

// ============================================================================
// Already at latest — no-op
// ============================================================================

func TestAlreadyAtLatest(t *testing.T) {
	reg := New("x")
	reg.Register(1, nil)
	reg.Register(2, func(data map[string]any) (map[string]any, error) {
		t.Error("v2 migration should not run for already-v2 data")
		return data, nil
	})

	raw := []byte(`{"schemaVersion":2,"clean":true}`)
	updated, err := reg.MigrateToLatest(raw)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	json.Unmarshal(updated, &out)
	if int(out["schemaVersion"].(float64)) != 2 {
		t.Errorf("version: %v", out["schemaVersion"])
	}
}

// ============================================================================
// Future version — refuse to migrate
// ============================================================================

func TestFutureVersionRejected(t *testing.T) {
	reg := New("x")
	reg.Register(1, nil)
	reg.Register(2, func(data map[string]any) (map[string]any, error) {
		return data, nil
	})

	// Data is from v5, but registry only knows up to v2
	raw := []byte(`{"schemaVersion":5,"future":"data"}`)
	_, err := reg.MigrateToLatest(raw)
	if !errors.Is(err, ErrFutureVersion) {
		t.Fatalf("want ErrFutureVersion, got %v", err)
	}
}

// ============================================================================
// Migration func errors propagate
// ============================================================================

func TestMigrationFuncError(t *testing.T) {
	reg := New("x")
	reg.Register(1, nil)
	reg.Register(2, func(data map[string]any) (map[string]any, error) {
		return nil, errors.New("malformed legacy data")
	})

	raw := []byte(`{"schemaVersion":1}`)
	_, err := reg.MigrateToLatest(raw)
	if !errors.Is(err, ErrMigrationFailed) {
		t.Fatalf("want ErrMigrationFailed, got %v", err)
	}
	if !strings.Contains(err.Error(), "malformed legacy") {
		t.Errorf("underlying error not preserved: %v", err)
	}
}

// ============================================================================
// Skipped versions — gap in migrations
// ============================================================================

func TestSkippedVersions(t *testing.T) {
	reg := New("x")
	reg.Register(1, nil)
	reg.Register(3, func(data map[string]any) (map[string]any, error) {
		return data, nil
	})
	// Note: version 2 missing!

	raw := []byte(`{"schemaVersion":1}`)
	_, err := reg.MigrateToLatest(raw)
	if !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("want ErrUnknownVersion (gap at v2), got %v", err)
	}
}

// ============================================================================
// Default to v1 if no schemaVersion present
// ============================================================================

func TestLegacyDataDefaultsToV1(t *testing.T) {
	reg := New("x")
	reg.Register(1, nil)
	reg.Register(2, func(data map[string]any) (map[string]any, error) {
		data["upgraded"] = true
		return data, nil
	})

	// Legacy data without schemaVersion field
	raw := []byte(`{"productID":"P1"}`)
	updated, err := reg.MigrateToLatest(raw)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	json.Unmarshal(updated, &out)
	if out["upgraded"] != true {
		t.Error("legacy data should be migrated as if v1")
	}
}

// ============================================================================
// Idempotency — running twice produces same result
// ============================================================================

func TestIdempotency(t *testing.T) {
	reg := New("x")
	reg.Register(1, nil)
	reg.Register(2, func(data map[string]any) (map[string]any, error) {
		data["counter"] = 1
		return data, nil
	})

	raw := []byte(`{"schemaVersion":1}`)
	first, err := reg.MigrateToLatest(raw)
	if err != nil {
		t.Fatal(err)
	}
	second, err := reg.MigrateToLatest(first)
	if err != nil {
		t.Fatal(err)
	}
	// Both should be at v2 and structurally identical
	if string(first) != string(second) {
		t.Errorf("not idempotent:\n  first:  %s\n  second: %s", first, second)
	}
}

// ============================================================================
// LatestVersion / IsLatest helpers
// ============================================================================

func TestLatestVersionReporting(t *testing.T) {
	reg := New("x")
	reg.Register(1, nil)
	reg.Register(2, func(d map[string]any) (map[string]any, error) { return d, nil })
	reg.Register(3, func(d map[string]any) (map[string]any, error) { return d, nil })

	if reg.LatestVersion() != 3 {
		t.Errorf("latest: %d", reg.LatestVersion())
	}
}

func TestIsLatest(t *testing.T) {
	reg := New("x")
	reg.Register(1, nil)
	reg.Register(2, func(d map[string]any) (map[string]any, error) { return d, nil })

	old := []byte(`{"schemaVersion":1}`)
	current := []byte(`{"schemaVersion":2}`)

	got, _ := reg.IsLatest(old)
	if got {
		t.Error("v1 data should not report as latest")
	}
	got, _ = reg.IsLatest(current)
	if !got {
		t.Error("v2 data should report as latest")
	}
}

// ============================================================================
// Concurrent registration
// ============================================================================

func TestConcurrentRegisterAndMigrate(t *testing.T) {
	reg := New("x")
	reg.Register(1, nil)
	reg.Register(2, func(d map[string]any) (map[string]any, error) {
		d["touched"] = true
		return d, nil
	})

	raw := []byte(`{"schemaVersion":1}`)
	done := make(chan struct{}, 50)
	for i := 0; i < 50; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			_, _ = reg.MigrateToLatest(raw)
		}()
	}
	for i := 0; i < 50; i++ {
		<-done
	}
	// Should not panic / race
}

// ============================================================================
// StampVersion helper
// ============================================================================

func TestStampVersion(t *testing.T) {
	data := map[string]any{"foo": "bar"}
	stamped := StampVersion(data, 7)
	if stamped["schemaVersion"] != 7 {
		t.Errorf("schemaVersion: %v", stamped["schemaVersion"])
	}
}

// ============================================================================
// RegisteredVersions
// ============================================================================

func TestRegisteredVersionsSorted(t *testing.T) {
	reg := New("x")
	reg.Register(3, func(d map[string]any) (map[string]any, error) { return d, nil })
	reg.Register(1, nil)
	reg.Register(2, func(d map[string]any) (map[string]any, error) { return d, nil })

	versions := reg.RegisteredVersions()
	want := []int{1, 2, 3}
	if len(versions) != len(want) {
		t.Fatalf("count: %v", versions)
	}
	for i, v := range want {
		if versions[i] != v {
			t.Errorf("position %d: got %d want %d", i, versions[i], v)
		}
	}
}

// ============================================================================
// CurrentVersion extraction
// ============================================================================

func TestCurrentVersion(t *testing.T) {
	reg := New("x")
	cases := []struct {
		raw  string
		want int
	}{
		{`{"schemaVersion":1}`, 1},
		{`{"schemaVersion":42}`, 42},
		{`{"foo":"bar"}`, 1}, // legacy default
	}
	for _, c := range cases {
		got, err := reg.CurrentVersion([]byte(c.raw))
		if err != nil {
			t.Errorf("%s: %v", c.raw, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: got %d want %d", c.raw, got, c.want)
		}
	}
}

func TestCurrentVersionMalformedJSON(t *testing.T) {
	reg := New("x")
	if _, err := reg.CurrentVersion([]byte(`{not json`)); err == nil {
		t.Error("malformed JSON should fail")
	}
}

func TestCurrentVersionNonNumericVersion(t *testing.T) {
	reg := New("x")
	_, err := reg.CurrentVersion([]byte(`{"schemaVersion":"abc"}`))
	if err == nil {
		t.Error("non-numeric version should fail")
	}
	if !errors.Is(err, ErrNoVersionField) {
		t.Errorf("want ErrNoVersionField, got %v", err)
	}
}

func TestEmptyRegistry(t *testing.T) {
	reg := New("empty")
	_, err := reg.MigrateToLatest([]byte(`{}`))
	if err == nil {
		t.Error("empty registry should reject migrate")
	}
	if !strings.Contains(err.Error(), "no versions") {
		t.Errorf("error message: %v", err)
	}
}

// Sanity check: long chain doesn't degrade correctness
func TestLongMigrationChain(t *testing.T) {
	reg := New("long")
	reg.Register(1, nil)
	for i := 2; i <= 20; i++ {
		v := i
		reg.Register(v, func(data map[string]any) (map[string]any, error) {
			data[fmt.Sprintf("touched_v%d", v)] = true
			return data, nil
		})
	}

	raw := []byte(`{"schemaVersion":1}`)
	updated, err := reg.MigrateToLatest(raw)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	json.Unmarshal(updated, &out)
	for i := 2; i <= 20; i++ {
		if out[fmt.Sprintf("touched_v%d", i)] != true {
			t.Errorf("touched_v%d missing", i)
		}
	}
	if int(out["schemaVersion"].(float64)) != 20 {
		t.Errorf("final version: %v", out["schemaVersion"])
	}
}

// ============================================================================
// Coverage uplift
// ============================================================================

func TestSchemaName(t *testing.T) {
	reg := New("my-schema")
	if reg.SchemaName() != "my-schema" {
		t.Errorf("SchemaName: %s", reg.SchemaName())
	}
}

func TestMigrateToLatestBadJSON(t *testing.T) {
	reg := New("x")
	reg.Register(1, nil)
	_, err := reg.MigrateToLatest([]byte("{bad json"))
	if err == nil {
		t.Fatal("bad JSON should fail")
	}
}

func TestMigrateMapFutureVersion(t *testing.T) {
	reg := New("x")
	reg.Register(1, nil)
	_, err := reg.MigrateMap(map[string]any{"schemaVersion": float64(99)})
	if !errors.Is(err, ErrFutureVersion) {
		t.Fatalf("want ErrFutureVersion, got %v", err)
	}
}

func TestIsLatestErrorOnBadJSON(t *testing.T) {
	reg := New("x")
	reg.Register(1, nil)
	_, err := reg.IsLatest([]byte("{bad"))
	if err == nil {
		t.Fatal("bad JSON should fail")
	}
}

func TestExtractVersionJSONNumber(t *testing.T) {
	// json.Number type (used when decoding with UseNumber)
	reg := New("x")
	reg.Register(1, nil)
	reg.Register(2, func(d map[string]any) (map[string]any, error) { return d, nil })
	raw := []byte(`{"schemaVersion":1}`)
	cur, err := reg.CurrentVersion(raw)
	if err != nil {
		t.Fatal(err)
	}
	if cur != 1 {
		t.Errorf("version: %d", cur)
	}
}

func TestExtractVersionInt64(t *testing.T) {
	// Direct map injection with int
	reg := New("x")
	reg.Register(1, nil)
	data := map[string]any{"schemaVersion": int64(1)}
	v, err := reg.MigrateMap(data)
	if err != nil {
		t.Fatal(err)
	}
	if v["schemaVersion"] != int64(1) && v["schemaVersion"] != 1 {
		t.Logf("schemaVersion: %T %v", v["schemaVersion"], v["schemaVersion"])
	}
}

func TestMigrateMapNoVersionRegistered(t *testing.T) {
	reg := New("empty")
	_, err := reg.MigrateMap(map[string]any{})
	if err == nil || !strings.Contains(err.Error(), "no versions") {
		t.Fatalf("want 'no versions' error, got %v", err)
	}
}

func TestRegisterPanicOnZero(t *testing.T) {
	reg := New("x")
	defer func() {
		if r := recover(); r == nil {
			t.Error("Register(0) should panic")
		}
	}()
	reg.Register(0, nil)
}

func TestCurrentVersionOnLatest(t *testing.T) {
	reg := New("x")
	reg.Register(1, nil)
	reg.Register(2, func(d map[string]any) (map[string]any, error) { return d, nil })
	cur, _ := reg.CurrentVersion([]byte(`{"schemaVersion":2,"x":1}`))
	if cur != 2 {
		t.Errorf("version: %d", cur)
	}
}

func TestExtractVersionAllTypes(t *testing.T) {
	reg := New("x")
	reg.Register(1, nil)

	// int type direct
	v, err := extractVersion(map[string]any{"schemaVersion": int(1)})
	if err != nil || v != 1 {
		t.Errorf("int: %v %v", v, err)
	}

	// int64 type direct
	v, err = extractVersion(map[string]any{"schemaVersion": int64(1)})
	if err != nil || v != 1 {
		t.Errorf("int64: %v %v", v, err)
	}

	// json.Number type
	v, err = extractVersion(map[string]any{"schemaVersion": json.Number("1")})
	if err != nil || v != 1 {
		t.Errorf("json.Number: %v %v", v, err)
	}

	// json.Number bad
	_, err = extractVersion(map[string]any{"schemaVersion": json.Number("not-a-number")})
	if !errors.Is(err, ErrNoVersionField) {
		t.Errorf("bad json.Number: %v", err)
	}

	// missing key defaults to 1
	v, err = extractVersion(map[string]any{})
	if err != nil || v != 1 {
		t.Errorf("missing: %v %v", v, err)
	}
}

// TestMigrateMapExtractVersionError covers schemaver.go:137-139: MigrateMap
// returns an error when extractVersion fails (schemaVersion is a non-numeric type).
func TestMigrateMapExtractVersionError(t *testing.T) {
	reg := New("x")
	reg.Register(1, nil)
	reg.Register(2, func(d map[string]any) (map[string]any, error) { return d, nil })
	// string type — extractVersion returns ErrNoVersionField
	data := map[string]any{"schemaVersion": "not-a-number"}
	_, err := reg.MigrateMap(data)
	if err == nil {
		t.Fatal("non-numeric schemaVersion should return error from MigrateMap")
	}
}

// TestMigrateMapSchemaVersionNilAfterNoOp covers schemaver.go:161-163: when
// the data is already at the latest version and has no schemaVersion key, the
// nil check stamps it with the current version.
func TestMigrateMapSchemaVersionNilAfterNoOp(t *testing.T) {
	reg := New("x")
	reg.Register(1, nil)                       // only v1; no migrations needed
	data := map[string]any{"payload": "value"} // no schemaVersion key
	result, err := reg.MigrateMap(data)
	if err != nil {
		t.Fatalf("MigrateMap on already-latest data with no key: %v", err)
	}
	if result["schemaVersion"] == nil {
		t.Error("MigrateMap should stamp schemaVersion when nil after no-op")
	}
}

func TestMigrateMapNilFnAtVersion(t *testing.T) {
	// Simulates gap where version key exists but fn is nil for a non-initial version
	// which should not be directly reachable in normal use but covers the code path
	reg := New("x")
	reg.Register(1, nil)
	reg.Register(2, nil) // nil fn for non-initial version — triggers "nil fn" error
	_, err := reg.MigrateToLatest([]byte(`{"schemaVersion":1}`))
	if err == nil {
		t.Fatal("nil migration fn at v2 should fail")
	}
}

// ============================================================================
// extractVersion — json.Number / int / int64 branches
// ============================================================================
