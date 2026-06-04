package capability

import (
	"context"
	"encoding/json"
	"runtime"
	"testing"
)

// ============================================================================
// Basic Set / Get / Has
// ============================================================================

func TestSetAndHas(t *testing.T) {
	s := New()
	s.Set(CapEd25519, true).Set(CapDPP, true).Set(CapKMS, false)

	if !s.Has(CapEd25519) {
		t.Error("Ed25519 should be true")
	}
	if !s.Has(CapDPP) {
		t.Error("DPP should be true")
	}
	if s.Has(CapKMS) {
		t.Error("KMS should be false")
	}
	if s.Has(CapBulletproofs) {
		t.Error("undeclared should be false")
	}
}

func TestHasAll(t *testing.T) {
	s := New().Set(CapEd25519, true).Set(CapDPP, true).Set(CapKMS, false)

	if !s.HasAll(CapEd25519, CapDPP) {
		t.Error("HasAll true caps should be true")
	}
	if s.HasAll(CapEd25519, CapKMS) {
		t.Error("HasAll with one false should be false")
	}
}

func TestHasAny(t *testing.T) {
	s := New().Set(CapEd25519, true).Set(CapDPP, false)

	if !s.HasAny(CapEd25519, CapDPP) {
		t.Error("HasAny with one true should be true")
	}
	if s.HasAny(CapDPP, CapKMS) {
		t.Error("HasAny with all false should be false")
	}
}

// ============================================================================
// Seal — immutability after production deploy
// ============================================================================

func TestSeal(t *testing.T) {
	s := New().Set(CapEd25519, true)
	if s.Sealed() {
		t.Fatal("not sealed initially")
	}

	s.Seal()
	if !s.Sealed() {
		t.Fatal("should be sealed")
	}

	// Set 後も値は変わらない
	s.Set(CapEd25519, false)
	if !s.Has(CapEd25519) {
		t.Error("CRITICAL: sealed set was modified")
	}
}

func TestSealedDetectIgnored(t *testing.T) {
	s := New().Set(CapDPP, true).Seal()
	called := false
	d := func(ctx context.Context) bool {
		called = true
		return false
	}
	s.Detect(context.Background(), CapDPP, d)
	// Detect is allowed to run, but value can't change
	if !s.Has(CapDPP) {
		t.Error("CRITICAL: sealed value changed via Detect")
	}
	_ = called // detector may have run (impl detail), but result discarded
}

// ============================================================================
// Detector
// ============================================================================

func TestDetectorEd25519(t *testing.T) {
	s := New().Detect(context.Background(), CapEd25519, DetectorEd25519())
	if !s.Has(CapEd25519) {
		t.Error("Ed25519 should always detect true (stdlib)")
	}
}

func TestDetectorHTTPS(t *testing.T) {
	s := New()
	s.Detect(context.Background(), CapHTTPS, DetectorHTTPS("", ""))
	if s.Has(CapHTTPS) {
		t.Error("empty cert/key should yield false")
	}
	s2 := New()
	s2.Detect(context.Background(), CapHTTPS, DetectorHTTPS("/cert.pem", "/key.pem"))
	if !s2.Has(CapHTTPS) {
		t.Error("populated cert/key should yield true")
	}
}

func TestDetectorBulletproofsCurrentlyFalse(t *testing.T) {
	// Apple-style: features not yet implemented are explicitly false
	s := New().Detect(context.Background(), CapBulletproofs, DetectorBulletproofs())
	if s.Has(CapBulletproofs) {
		t.Error("Bulletproofs should be false until implementation lands")
	}
}

func TestDetectorNilSafe(t *testing.T) {
	s := New().Detect(context.Background(), CapKMS, nil)
	if s.Has(CapKMS) {
		t.Error("nil detector should yield false (Apple-style safe default)")
	}
}

// ============================================================================
// Profile satisfaction
// ============================================================================

func TestProfileBasicSatisfied(t *testing.T) {
	s := New().
		Set(CapEd25519, true).
		Set(CapDPP, true)
	ok, missing := ProfileBasic.Satisfies(s)
	if !ok {
		t.Errorf("ProfileBasic should be satisfied: missing %v", missing)
	}
}

func TestProfileBasicMissing(t *testing.T) {
	s := New().Set(CapEd25519, true) // missing DPP
	ok, missing := ProfileBasic.Satisfies(s)
	if ok {
		t.Error("ProfileBasic should NOT be satisfied")
	}
	if len(missing) != 1 || missing[0] != CapDPP {
		t.Errorf("missing should be [DPP], got %v", missing)
	}
}

func TestProfileEUCompliance(t *testing.T) {
	s := New().
		Set(CapEd25519, true).
		Set(CapDPP, true).
		Set(CapSCITT, true).
		Set(CapPersistence, true)
	ok, _ := ProfileEUCompliance.Satisfies(s)
	if !ok {
		t.Error("EU compliance profile should be satisfied")
	}

	// 1つ欠けると失敗
	s2 := New().
		Set(CapEd25519, true).
		Set(CapDPP, true)
	ok, missing := ProfileEUCompliance.Satisfies(s2)
	if ok {
		t.Error("incomplete should fail")
	}
	if len(missing) != 2 {
		t.Errorf("should miss 2: SCITT + Persistence; got %v", missing)
	}
}

func TestProfileBatteryFeb2027(t *testing.T) {
	s := New().
		Set(CapEd25519, true).
		Set(CapDPP, true).
		Set(CapBatteryPass, true).
		Set(CapSCITT, true).
		Set(CapPersistence, true)
	ok, missing := ProfileBatteryFeb2027.Satisfies(s)
	if !ok {
		t.Errorf("Battery 2027 missing: %v", missing)
	}
}

// ============================================================================
// Snapshot
// ============================================================================

func TestSnapshot(t *testing.T) {
	s := New().Set(CapEd25519, true).Set(CapKMS, false).Seal()
	snap := s.Snapshot()

	if !snap.Available[CapEd25519] {
		t.Error("snapshot missing Ed25519")
	}
	if snap.Available[CapKMS] {
		t.Error("snapshot wrong for KMS")
	}
	if !snap.Sealed {
		t.Error("sealed not in snapshot")
	}
	if snap.Runtime.GoVersion != runtime.Version() {
		t.Errorf("runtime version: %s vs %s", snap.Runtime.GoVersion, runtime.Version())
	}
}

func TestSnapshotJSONSerializable(t *testing.T) {
	s := New().
		Set(CapEd25519, true).
		Set(CapDPP, true).
		Set(CapBulletproofs, false).
		Seal()

	snap := s.Snapshot()
	b, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if len(b) < 100 {
		t.Errorf("JSON suspiciously short: %s", b)
	}

	// Round-trip
	var got Snapshot
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if !got.Available[CapEd25519] {
		t.Error("Ed25519 lost in round-trip")
	}
	if !got.Sealed {
		t.Error("Sealed lost in round-trip")
	}
}

// ============================================================================
// Available list
// ============================================================================

func TestAvailable(t *testing.T) {
	s := New().
		Set(CapEd25519, true).
		Set(CapDPP, true).
		Set(CapKMS, false). // false should NOT appear
		Set(CapSCITT, true)

	avail := s.Available()
	if len(avail) != 3 {
		t.Errorf("expected 3 available, got %d: %v", len(avail), avail)
	}
	for _, c := range avail {
		if !s.Has(c) {
			t.Errorf("Available returned non-available: %s", c)
		}
	}
}

// ============================================================================
// Concurrency safety
// ============================================================================

func TestConcurrentAccess(t *testing.T) {
	s := New()
	done := make(chan struct{})
	for i := 0; i < 50; i++ {
		go func(i int) {
			c := Capability(string(rune(i + 'a')))
			s.Set(c, true)
			s.Has(c)
			s.Available()
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < 50; i++ {
		<-done
	}
	// no panic = success
}
