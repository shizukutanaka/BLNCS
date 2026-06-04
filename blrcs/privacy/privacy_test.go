package privacy

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// ============================================================================
// Manifest
// ============================================================================

func TestDefaultManifest(t *testing.T) {
	m := BLRCSDefaultManifest("did:web:blrcs.example", "1.0.0")
	if m.SpecVersion != "1.0" {
		t.Errorf("specVersion: %s", m.SpecVersion)
	}
	if m.Controller != "did:web:blrcs.example" {
		t.Errorf("controller: %s", m.Controller)
	}
	if len(m.CollectedData) == 0 {
		t.Error("no declared data categories")
	}
	if m.SubjectRights.ResponseDays != 30 {
		t.Errorf("GDPR response days: %d", m.SubjectRights.ResponseDays)
	}
}

func TestManifestJSONRoundTrip(t *testing.T) {
	m := BLRCSDefaultManifest("did:web:test", "0.1.0")
	b, err := m.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var m2 Manifest
	if err := json.Unmarshal(b, &m2); err != nil {
		t.Fatal(err)
	}
	if m2.Controller != m.Controller {
		t.Errorf("controller roundtrip: %s", m2.Controller)
	}
	if len(m2.CollectedData) != len(m.CollectedData) {
		t.Errorf("declared data count: %d vs %d", len(m2.CollectedData), len(m.CollectedData))
	}
}

func TestManifestNoTrackingByDefault(t *testing.T) {
	m := BLRCSDefaultManifest("did:web:test", "1.0")
	for _, d := range m.CollectedData {
		if d.UsedForTracking {
			t.Errorf("category %s should NOT be used for tracking", d.Category)
		}
	}
}

func TestManifestSensorReadingIsMinimized(t *testing.T) {
	m := BLRCSDefaultManifest("did:web:test", "1.0")
	for _, d := range m.CollectedData {
		if d.Category == DataCategorySensorReading {
			if !d.Minimized {
				t.Error("sensor reading must be minimized (ZK proof)")
			}
			return
		}
	}
	t.Error("SensorReading not declared")
}

func TestManifestSupplierNameIsMinimized(t *testing.T) {
	m := BLRCSDefaultManifest("did:web:test", "1.0")
	for _, d := range m.CollectedData {
		if d.Category == DataCategorySupplierName {
			if !d.Minimized {
				t.Error("supplier name must be minimized (SD-JWT)")
			}
			return
		}
	}
	t.Error("SupplierName not declared")
}

func TestManifestHolderDataIsLinkedAndSession(t *testing.T) {
	m := BLRCSDefaultManifest("did:web:test", "1.0")
	for _, d := range m.CollectedData {
		if d.Category == DataCategoryHolderDID {
			if !d.LinkedToUser {
				t.Error("holder DID must be LinkedToUser")
			}
			if d.Retention != "session" {
				t.Errorf("holder DID retention should be session, got %s", d.Retention)
			}
			return
		}
	}
	t.Error("HolderDID not declared")
}

// ============================================================================
// DataLineage / Tracker
// ============================================================================

func TestTrackerRecordsAccess(t *testing.T) {
	tr := &Tracker{}
	ctx := WithTracker(context.Background(), tr)

	Record(ctx, "compliance.IssueDPP", DataCategoryProductID, DataCategoryProductCarbon)
	Record(ctx, "scitt.Register", DataCategoryPublicKey)

	records := tr.Records()
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	if records[0].Operation != "compliance.IssueDPP" {
		t.Errorf("op: %s", records[0].Operation)
	}
	if len(records[0].Categories) != 2 {
		t.Errorf("categories: %v", records[0].Categories)
	}
}

func TestTrackerNilSafe(t *testing.T) {
	// nil Tracker (no WithTracker) should not panic
	ctx := context.Background()
	Record(ctx, "any", DataCategoryProductID)
	tr := TrackerFromContext(ctx)
	if tr != nil {
		t.Error("should be nil without WithTracker")
	}
}

func TestTrackerCategoriesAccessed(t *testing.T) {
	tr := &Tracker{}
	ctx := WithTracker(context.Background(), tr)
	Record(ctx, "op1", DataCategoryProductID, DataCategoryProductCarbon)
	Record(ctx, "op2", DataCategoryProductID) // duplicate category

	cats := tr.CategoriesAccessed()
	// productID and productCarbon — deduplicated
	found := make(map[DataCategory]bool)
	for _, c := range cats {
		found[c] = true
	}
	if !found[DataCategoryProductID] {
		t.Error("productID missing")
	}
	if !found[DataCategoryProductCarbon] {
		t.Error("productCarbon missing")
	}
	if len(cats) != 2 {
		t.Errorf("expected 2 unique categories, got %d", len(cats))
	}
}

func TestTrackerConcurrentAccess(t *testing.T) {
	tr := &Tracker{}
	ctx := WithTracker(context.Background(), tr)
	done := make(chan struct{})
	for i := 0; i < 50; i++ {
		go func() {
			Record(ctx, "concurrent", DataCategoryProductID)
			done <- struct{}{}
		}()
	}
	for i := 0; i < 50; i++ {
		<-done
	}
	if len(tr.Records()) != 50 {
		t.Errorf("expected 50 records, got %d", len(tr.Records()))
	}
}

// ============================================================================
// MinimizationGuard
// ============================================================================

func TestGuardAllowsDeclaredCategories(t *testing.T) {
	g := NewGuard(BLRCSDefaultPolicy)
	err := g.Check("compliance.IssueDPP", DataCategoryProductID, DataCategoryProductCarbon)
	if err != nil {
		t.Errorf("declared access should be allowed: %v", err)
	}
}

func TestGuardBlocksUndeclaredCategory(t *testing.T) {
	g := NewGuard(BLRCSDefaultPolicy)
	// IssueDPP should NOT access HolderDID
	err := g.Check("compliance.IssueDPP", DataCategoryHolderDID)
	if !errors.Is(err, ErrMinimization) {
		t.Fatalf("want ErrMinimization, got %v", err)
	}
	if !strings.Contains(err.Error(), "undeclared category") {
		t.Errorf("error should mention undeclared: %s", err.Error())
	}
}

func TestGuardBlocksUndeclaredOperation(t *testing.T) {
	g := NewGuard(BLRCSDefaultPolicy)
	err := g.Check("unknown.operation", DataCategoryProductID)
	if !errors.Is(err, ErrMinimization) {
		t.Fatalf("want ErrMinimization, got %v", err)
	}
	if !strings.Contains(err.Error(), "not declared") {
		t.Errorf("error should say 'not declared': %s", err.Error())
	}
}

func TestGuardEmptyCategories(t *testing.T) {
	g := NewGuard(BLRCSDefaultPolicy)
	// Declared op with no categories — should pass (no access)
	if err := g.Check("compliance.IssueDPP"); err != nil {
		t.Errorf("no category access should pass: %v", err)
	}
}

func TestGuardCustomPolicy(t *testing.T) {
	policy := AllowedCategories{
		"myOp": {DataCategoryPublicKey},
	}
	g := NewGuard(policy)
	if err := g.Check("myOp", DataCategoryPublicKey); err != nil {
		t.Errorf("should allow declared: %v", err)
	}
	if err := g.Check("myOp", DataCategoryProductID); err == nil {
		t.Error("should block undeclared")
	}
}
