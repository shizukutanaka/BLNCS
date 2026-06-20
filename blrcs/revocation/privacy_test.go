package revocation

import (
	"errors"
	"testing"
)

func TestNewIndexAllocatorValidation(t *testing.T) {
	if _, err := NewIndexAllocator(0); !errors.Is(err, ErrAllocatorCapacity) {
		t.Errorf("capacity 0: want ErrAllocatorCapacity, got %v", err)
	}
	if _, err := NewIndexAllocator(-5); !errors.Is(err, ErrAllocatorCapacity) {
		t.Errorf("negative capacity: want ErrAllocatorCapacity, got %v", err)
	}
	a, err := NewIndexAllocator(128)
	if err != nil {
		t.Fatalf("valid capacity: %v", err)
	}
	if a.Capacity() != 128 {
		t.Errorf("capacity: want 128, got %d", a.Capacity())
	}
	if a.Count() != 0 {
		t.Errorf("fresh allocator count: want 0, got %d", a.Count())
	}
}

func TestIndexAllocatorUniqueAndInRange(t *testing.T) {
	const cap = 512
	a, _ := NewIndexAllocator(cap)
	seen := make(map[int]bool)
	for i := 0; i < cap; i++ {
		n, err := a.Allocate()
		if err != nil {
			t.Fatalf("allocate %d: %v", i, err)
		}
		if n < 0 || n >= cap {
			t.Fatalf("index %d out of range [0,%d)", n, cap)
		}
		if seen[n] {
			t.Fatalf("duplicate index %d at allocation %d", n, i)
		}
		seen[n] = true
	}
	if a.Count() != cap {
		t.Errorf("full allocator count: want %d, got %d", cap, a.Count())
	}
	// The next allocation must fail — the space is exhausted.
	if _, err := a.Allocate(); !errors.Is(err, ErrAllocatorFull) {
		t.Errorf("exhausted allocator: want ErrAllocatorFull, got %v", err)
	}
}

func TestIndexAllocatorReserve(t *testing.T) {
	a, _ := NewIndexAllocator(64)
	if err := a.Reserve(10); err != nil {
		t.Fatalf("reserve 10: %v", err)
	}
	// Reserving the same index again is a no-op (count unchanged).
	if err := a.Reserve(10); err != nil {
		t.Fatalf("re-reserve 10: %v", err)
	}
	if a.Count() != 1 {
		t.Errorf("after reserving one index: want count 1, got %d", a.Count())
	}
	// Out-of-range reservations are rejected.
	if err := a.Reserve(-1); !errors.Is(err, ErrIndexOutOfRange) {
		t.Errorf("reserve -1: want ErrIndexOutOfRange, got %v", err)
	}
	if err := a.Reserve(64); !errors.Is(err, ErrIndexOutOfRange) {
		t.Errorf("reserve 64: want ErrIndexOutOfRange, got %v", err)
	}
	// A reserved index is never handed out by Allocate.
	for i := 0; i < 63; i++ {
		n, err := a.Allocate()
		if err != nil {
			t.Fatalf("allocate %d: %v", i, err)
		}
		if n == 10 {
			t.Fatal("Allocate returned a reserved index")
		}
	}
}

// TestIndexAllocatorRandomness is a statistical sanity check: random assignment
// must NOT cluster allocated indices in a low prefix the way sequential
// assignment would. With sequential assignment the max of a small number of
// allocations from a large space would be tiny; random assignment spreads them.
func TestIndexAllocatorRandomness(t *testing.T) {
	const cap = 100_000
	a, _ := NewIndexAllocator(cap)
	maxIdx := 0
	for i := 0; i < 50; i++ {
		n, err := a.Allocate()
		if err != nil {
			t.Fatalf("allocate %d: %v", i, err)
		}
		if n > maxIdx {
			maxIdx = n
		}
	}
	// Sequential assignment would give maxIdx == 49. Random assignment over a
	// 100k space makes the max of 50 draws almost surely far larger. The
	// expected max is ~cap*50/51 ≈ 98k; require it to clear a conservative
	// threshold so the test is effectively never flaky (P(max < cap/10) for 50
	// uniform draws ≈ 0.9^50 ≈ 0.5%, and we use cap/50 → ~0.36%).
	if maxIdx < cap/50 {
		t.Errorf("indices look clustered (max=%d over 50 draws in [0,%d)) — not random?", maxIdx, cap)
	}
}

// TestIndexAllocatorHighOccupancyFallback drives the allocator near saturation
// to exercise the random-start probe path (past the rejection-sampling tries),
// confirming it still yields unique, in-range indices and eventually fills.
func TestIndexAllocatorHighOccupancyFallback(t *testing.T) {
	const cap = 256
	a, _ := NewIndexAllocator(cap)
	seen := make(map[int]bool)
	for i := 0; i < cap; i++ {
		n, err := a.Allocate()
		if err != nil {
			t.Fatalf("allocate %d near saturation: %v", i, err)
		}
		if n < 0 || n >= cap || seen[n] {
			t.Fatalf("bad index %d at allocation %d", n, i)
		}
		seen[n] = true
	}
	if len(seen) != cap {
		t.Errorf("expected to fill all %d indices, got %d", cap, len(seen))
	}
}

// TestIndexAllocatorWithStatusList wires the allocator into a real status list to
// confirm allocated indices set/read back correctly (correctness preserved).
func TestIndexAllocatorWithStatusList(t *testing.T) {
	list := NewBitstringStatusList(PurposeRevocation, MinBitstringSize)
	a, _ := NewIndexAllocator(list.Capacity())

	idx, err := a.Allocate()
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	// Not revoked initially.
	if on, err := list.GetStatus(idx); err != nil || on {
		t.Fatalf("fresh index: want (false,nil), got (%v,%v)", on, err)
	}
	// Revoke and read back.
	if err := list.SetStatus(idx, true); err != nil {
		t.Fatalf("set status: %v", err)
	}
	if on, err := list.GetStatus(idx); err != nil || !on {
		t.Fatalf("revoked index: want (true,nil), got (%v,%v)", on, err)
	}
}
