package replay

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// Basic operation
// ============================================================================

func TestFirstCheckPasses(t *testing.T) {
	d := NewDetector(time.Hour, 100)
	defer d.Close()
	if err := d.Check([]byte("payload-1")); err != nil {
		t.Fatalf("first check should pass: %v", err)
	}
}

func TestSecondCheckIsReplay(t *testing.T) {
	d := NewDetector(time.Hour, 100)
	defer d.Close()
	d.Check([]byte("payload-1"))
	err := d.Check([]byte("payload-1"))
	if err != ErrReplay {
		t.Fatalf("want ErrReplay, got %v", err)
	}
}

func TestDifferentPayloadsBothPass(t *testing.T) {
	d := NewDetector(time.Hour, 100)
	defer d.Close()
	for i := 0; i < 100; i++ {
		payload := fmt.Sprintf("payload-%d", i)
		if err := d.Check([]byte(payload)); err != nil {
			t.Errorf("payload-%d: %v", i, err)
		}
	}
	if d.Size() != 100 {
		t.Errorf("size: %d", d.Size())
	}
}

func TestCheckString(t *testing.T) {
	d := NewDetector(time.Hour, 10)
	defer d.Close()
	if err := d.CheckString("token-abc"); err != nil {
		t.Fatal(err)
	}
	if err := d.CheckString("token-abc"); err != ErrReplay {
		t.Fatalf("string replay: %v", err)
	}
}

// ============================================================================
// TTL behavior
// ============================================================================

func TestTTLExpiresEntry(t *testing.T) {
	d := NewDetector(50*time.Millisecond, 10)
	defer d.Close()

	if err := d.Check([]byte("expire-me")); err != nil {
		t.Fatal(err)
	}
	// Within TTL — replay
	if err := d.Check([]byte("expire-me")); err != ErrReplay {
		t.Fatalf("within TTL: %v", err)
	}
	// Wait beyond TTL
	time.Sleep(100 * time.Millisecond)
	// Now allowed again
	if err := d.Check([]byte("expire-me")); err != nil {
		t.Errorf("after TTL: %v", err)
	}
}

func TestGCRemovesExpired(t *testing.T) {
	d := NewDetector(50*time.Millisecond, 1000)
	defer d.Close()

	for i := 0; i < 10; i++ {
		d.Check([]byte(fmt.Sprintf("p-%d", i)))
	}
	if d.Size() != 10 {
		t.Fatalf("initial size: %d", d.Size())
	}
	// Wait for GC to run after TTL
	time.Sleep(200 * time.Millisecond)
	// Force collect to handle borderline timing
	d.collect()
	if d.Size() != 0 {
		t.Errorf("after GC, size: %d", d.Size())
	}
}

// ============================================================================
// Capacity / eviction
// ============================================================================

func TestMaxSizeEvictsOldest(t *testing.T) {
	d := NewDetector(time.Hour, 5)
	defer d.Close()

	for i := 0; i < 5; i++ {
		d.Check([]byte(fmt.Sprintf("entry-%d", i)))
		time.Sleep(1 * time.Millisecond) // ensure distinct timestamps
	}
	if d.Size() != 5 {
		t.Fatalf("size: %d", d.Size())
	}

	// Add 6th — should evict oldest (entry-0)
	d.Check([]byte("entry-5"))
	if d.Size() != 5 {
		t.Errorf("size after eviction: %d", d.Size())
	}
	// entry-0 should now be allowed again (evicted)
	if err := d.Check([]byte("entry-0")); err != nil {
		t.Errorf("evicted entry should be allowed: %v", err)
	}
}

// ============================================================================
// Concurrency
// ============================================================================

func TestConcurrentDifferentPayloads(t *testing.T) {
	d := NewDetector(time.Hour, 10000)
	defer d.Close()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				payload := fmt.Sprintf("worker-%d-msg-%d", n, j)
				if err := d.Check([]byte(payload)); err != nil {
					t.Errorf("%s: %v", payload, err)
				}
			}
		}(i)
	}
	wg.Wait()
	if d.Size() != 1000 {
		t.Errorf("expected 1000, got %d", d.Size())
	}
}

func TestConcurrentSamePayload(t *testing.T) {
	// 100 goroutines try to insert same payload — exactly 1 should succeed
	d := NewDetector(time.Hour, 100)
	defer d.Close()

	var success, replay int64
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := d.Check([]byte("hot-payload"))
			mu.Lock()
			switch err {
			case nil:
				success++
			case ErrReplay:
				replay++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	if success != 1 {
		t.Errorf("exactly 1 should succeed, got %d", success)
	}
	if replay != 99 {
		t.Errorf("99 should be replay, got %d", replay)
	}
}

// ============================================================================
// Forget (test helper)
// ============================================================================

func TestForget(t *testing.T) {
	d := NewDetector(time.Hour, 10)
	defer d.Close()
	d.Check([]byte("x"))
	d.Forget([]byte("x"))
	if err := d.Check([]byte("x")); err != nil {
		t.Errorf("after Forget: %v", err)
	}
}

// ============================================================================
// Defaults
// ============================================================================

func TestZeroTTLBecomesDefault(t *testing.T) {
	d := NewDetector(0, 10)
	defer d.Close()
	if d.ttl <= 0 {
		t.Error("zero ttl should default to non-zero")
	}
}

func TestZeroMaxSizeBecomesDefault(t *testing.T) {
	d := NewDetector(time.Hour, 0)
	defer d.Close()
	if d.maxSize <= 0 {
		t.Error("zero maxSize should default to non-zero")
	}
}

// ============================================================================
// Fingerprint stability
// ============================================================================

func TestFingerprintDeterministic(t *testing.T) {
	a := fingerprint([]byte("hello"))
	b := fingerprint([]byte("hello"))
	if a != b {
		t.Error("fingerprint should be deterministic")
	}
	c := fingerprint([]byte("world"))
	if a == c {
		t.Error("different inputs should produce different fingerprints")
	}
}
