// Issuer-metric privacy for Bitstring Status Lists.
//
// A published Bitstring Status List (bitstring.go) is fetched by any verifier,
// so its contents are effectively public. The W3C 16KB minimum (herd privacy,
// §5.3) hides *which* holder a given index belongs to, but it does not hide the
// issuer's aggregate business metrics. The subtle leak is in how indices are
// assigned:
//
//   - In a status list, bit 0 means "not revoked" — which is the status of BOTH
//     an unissued index AND a valid (issued, non-revoked) credential. An observer
//     therefore cannot distinguish "issued & valid" from "never issued": both are 0.
//   - But revoked credentials show a 1 bit. With *sequential* index assignment
//     (0, 1, 2, …) every 1 bit lands in [0, highWaterMark), so the largest revoked
//     index ≈ the number of credentials ever issued, and a credential's index is
//     monotonic in its issuance time. That leaks issuance volume and ordering.
//
// IndexAllocator hands out uniformly-random indices from a fixed-size space
// instead. Revoked bits are then spread across the whole list, so the maximum
// revoked index ≈ the capacity regardless of the true issuance volume, and an
// index reveals nothing about when the credential was issued. Correctness is
// unchanged: every allocated index is unique and in range, so SetStatus/GetStatus
// behave exactly as before.
//
// Residual (out of scope here): the *count* of 1 bits still reveals the absolute
// number of revocations. Hiding that requires an accumulator / Bloom-cascade with
// padding (CRSet, arXiv 2501.17089) rather than a plain bitstring — tracked
// separately. This file delivers the cheap, correctness-preserving first step.
package revocation

import (
	"crypto/rand"
	"errors"
	"math/big"
	"sync"
)

var (
	// ErrAllocatorCapacity — capacity が正でない。
	ErrAllocatorCapacity = errors.New("revocation: allocator capacity must be positive")
	// ErrAllocatorFull — 空き index が無い (全 index 払い出し済み)。
	ErrAllocatorFull = errors.New("revocation: index allocator exhausted")
	// ErrIndexOutOfRange — Reserve に範囲外 index が渡された。
	ErrIndexOutOfRange = errors.New("revocation: index out of range")
)

// IndexAllocator hands out unique, uniformly-random status-list indices from a
// fixed-size space [0, capacity). It is safe for concurrent use.
//
// Pair it with a BitstringStatusList of matching capacity: allocate an index per
// issued credential (store it in the credential's status claim), and call
// SetStatus(index, true) to revoke. Because indices are random, the published
// list leaks neither issuance volume nor issuance order (see file doc).
type IndexAllocator struct {
	mu       sync.Mutex
	capacity int
	used     map[int]bool
}

// NewIndexAllocator constructs an allocator over [0, capacity). capacity SHOULD
// match the BitstringStatusList capacity it feeds. To preserve the volume-hiding
// property, capacity SHOULD be a fixed published size (e.g. MinBitstringSize) and
// the load factor SHOULD stay well below 1 — a nearly-full list re-exposes volume
// (every index is occupied) and makes allocation slow.
func NewIndexAllocator(capacity int) (*IndexAllocator, error) {
	if capacity <= 0 {
		return nil, ErrAllocatorCapacity
	}
	return &IndexAllocator{capacity: capacity, used: make(map[int]bool)}, nil
}

// Capacity — index 空間の大きさ。
func (a *IndexAllocator) Capacity() int { return a.capacity }

// Count — 払い出し済み index 数。
func (a *IndexAllocator) Count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.used)
}

// Allocate returns a fresh uniformly-random index not previously handed out.
//
// It uses CSPRNG rejection sampling while the space is sparse, then falls back to
// a random-start probe once occupancy is high so it still terminates in bounded
// time near saturation. Returns ErrAllocatorFull when every index is taken.
func (a *IndexAllocator) Allocate() (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.used) >= a.capacity {
		return 0, ErrAllocatorFull
	}
	// Rejection sampling: cheap and unbiased while the list is sparse.
	const maxTries = 64
	for i := 0; i < maxTries; i++ {
		n, err := randIndex(a.capacity)
		if err != nil {
			return 0, err
		}
		if !a.used[n] {
			a.used[n] = true
			return n, nil
		}
	}
	// High occupancy: probe forward from a random start so we still terminate.
	start, err := randIndex(a.capacity)
	if err != nil {
		return 0, err
	}
	for off := 0; off < a.capacity; off++ {
		n := (start + off) % a.capacity
		if !a.used[n] {
			a.used[n] = true
			return n, nil
		}
	}
	return 0, ErrAllocatorFull
}

// Reserve marks an index as already used without random selection. Use it to
// rebuild allocator state after a restart from the issued credentials' stored
// indices. Reserving an already-used index is a no-op.
func (a *IndexAllocator) Reserve(index int) error {
	if index < 0 || index >= a.capacity {
		return ErrIndexOutOfRange
	}
	a.mu.Lock()
	a.used[index] = true
	a.mu.Unlock()
	return nil
}

// randIndex returns a uniformly-random int in [0, n) using crypto/rand.
func randIndex(n int) (int, error) {
	bn, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, err
	}
	return int(bn.Int64()), nil
}
