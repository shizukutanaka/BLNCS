package cas

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

// ============================================================================
// Hash determinism
// ============================================================================

func TestComputeHashDeterministic(t *testing.T) {
	h1 := ComputeHash([]byte("hello"))
	h2 := ComputeHash([]byte("hello"))
	if h1 != h2 {
		t.Errorf("non-deterministic: %s != %s", h1, h2)
	}
	h3 := ComputeHash([]byte("world"))
	if h1 == h3 {
		t.Errorf("collision: hello vs world both %s", h1)
	}
	// Length should be 64 hex chars (256 bits / 4 bits per char)
	if len(h1) != 64 {
		t.Errorf("hash length: %d", len(h1))
	}
}

func TestVerify(t *testing.T) {
	payload := []byte("test data")
	h := ComputeHash(payload)
	if !Verify(payload, h) {
		t.Error("Verify should accept matching payload+hash")
	}
	tampered := []byte("evil data")
	if Verify(tampered, h) {
		t.Error("Verify must reject tampered payload")
	}
}

// ============================================================================
// MemoryStore basics
// ============================================================================

func TestPutAndGet(t *testing.T) {
	store := NewMemoryStore()
	payload := []byte(`{"product":"P1","carbon":2.5}`)
	h, err := store.Put(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !store.Has(h) {
		t.Error("Has should return true after Put")
	}
	got, err := store.Get(h)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Errorf("Get: %s != %s", got, payload)
	}
}

func TestGetNonExistentReturnsNotFound(t *testing.T) {
	store := NewMemoryStore()
	_, err := store.Get(Hash("a" + "0000000000000000000000000000000000000000000000000000000000000000"[:63]))
	if err != ErrNotFound {
		t.Errorf("want ErrNotFound, got %v", err)
	}
}

// ============================================================================
// Dedup invariant — Apple Time Machine 同等
// ============================================================================

func TestDeduplicationOnRepeatedPut(t *testing.T) {
	store := NewMemoryStore()
	payload := []byte("identical payload")
	for i := 0; i < 100; i++ {
		h, _ := store.Put(payload)
		if h != ComputeHash(payload) {
			t.Errorf("hash should be stable on Put #%d", i)
		}
	}
	if store.Size() != 1 {
		t.Errorf("dedup violated: size %d (expected 1)", store.Size())
	}
}

func TestDifferentPayloadsStored(t *testing.T) {
	store := NewMemoryStore()
	for i := 0; i < 50; i++ {
		store.Put([]byte(fmt.Sprintf("payload-%d", i)))
	}
	if store.Size() != 50 {
		t.Errorf("expected 50 unique, got %d", store.Size())
	}
}

// ============================================================================
// Defensive copy semantics
// ============================================================================

func TestPutDefensiveCopy(t *testing.T) {
	store := NewMemoryStore()
	payload := []byte("original")
	h, _ := store.Put(payload)
	// Mutate caller's buffer after Put
	for i := range payload {
		payload[i] = 'X'
	}
	got, _ := store.Get(h)
	if string(got) != "original" {
		t.Errorf("Put should defensive-copy, got %s", got)
	}
}

func TestGetDefensiveCopy(t *testing.T) {
	store := NewMemoryStore()
	h, _ := store.Put([]byte("original"))
	got, _ := store.Get(h)
	// Mutate received buffer
	for i := range got {
		got[i] = 'X'
	}
	got2, _ := store.Get(h)
	if string(got2) != "original" {
		t.Errorf("Get should defensive-copy, got %s", got2)
	}
}

// ============================================================================
// Iterate
// ============================================================================

func TestIterate(t *testing.T) {
	store := NewMemoryStore()
	expected := map[Hash]bool{}
	for i := 0; i < 5; i++ {
		h, _ := store.Put([]byte(fmt.Sprintf("p-%d", i)))
		expected[h] = true
	}
	visited := map[Hash]bool{}
	err := store.Iterate(func(h Hash) error {
		visited[h] = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(visited) != len(expected) {
		t.Errorf("visit count: %d vs %d", len(visited), len(expected))
	}
}

func TestIterateAbortOnError(t *testing.T) {
	store := NewMemoryStore()
	for i := 0; i < 10; i++ {
		store.Put([]byte(fmt.Sprintf("p-%d", i)))
	}
	count := 0
	err := store.Iterate(func(h Hash) error {
		count++
		if count == 3 {
			return fmt.Errorf("stop")
		}
		return nil
	})
	if err == nil {
		t.Fatal("Iterate should propagate error")
	}
	if count != 3 {
		t.Errorf("expected to stop at 3, got %d", count)
	}
}

// ============================================================================
// Concurrent access
// ============================================================================

func TestConcurrentPut(t *testing.T) {
	store := NewMemoryStore()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			store.Put([]byte(fmt.Sprintf("concurrent-%d", n)))
		}(i)
	}
	wg.Wait()
	if store.Size() != 100 {
		t.Errorf("concurrent puts: %d (want 100)", store.Size())
	}
}

func TestConcurrentSamePayload(t *testing.T) {
	store := NewMemoryStore()
	var wg sync.WaitGroup
	payload := []byte("hot payload")
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			store.Put(payload)
		}()
	}
	wg.Wait()
	if store.Size() != 1 {
		t.Errorf("dedup under contention: %d (want 1)", store.Size())
	}
}

// ============================================================================
// Provenance — reverse lookup
// ============================================================================

func TestProvenanceRecord(t *testing.T) {
	prov := NewProvenance(NewMemoryStore())
	payload := []byte(`{"id":"prod-1","data":"x"}`)

	h, err := prov.Record("receipt-001", payload)
	if err != nil {
		t.Fatal(err)
	}
	// Lookup by external ID
	got, h2, err := prov.LookupByID("receipt-001")
	if err != nil {
		t.Fatal(err)
	}
	if h != h2 {
		t.Errorf("hash mismatch: %s vs %s", h, h2)
	}
	if string(got) != string(payload) {
		t.Errorf("payload roundtrip failed")
	}
}

func TestProvenanceLookupIDs(t *testing.T) {
	prov := NewProvenance(NewMemoryStore())
	payload := []byte("shared")
	prov.Record("receipt-A", payload)
	prov.Record("receipt-B", payload) // 同じ payload
	prov.Record("receipt-C", []byte("different"))

	h := ComputeHash(payload)
	ids := prov.LookupIDs(h)
	if len(ids) != 2 {
		t.Errorf("expected 2 IDs, got %d: %v", len(ids), ids)
	}
}

func TestProvenanceLookupNonExistent(t *testing.T) {
	prov := NewProvenance(NewMemoryStore())
	_, _, err := prov.LookupByID("never-recorded")
	if err != ErrNotFound {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestProvenanceStats(t *testing.T) {
	prov := NewProvenance(NewMemoryStore())
	prov.Record("a", []byte("x"))
	prov.Record("b", []byte("x")) // same payload
	prov.Record("c", []byte("y"))

	st := prov.Stats()
	if st.UniquePayloads != 2 {
		t.Errorf("unique payloads: %d", st.UniquePayloads)
	}
	if st.UniqueIDs != 3 {
		t.Errorf("unique IDs: %d", st.UniqueIDs)
	}
	if st.TotalMappings != 3 {
		t.Errorf("total mappings: %d", st.TotalMappings)
	}
}

// ============================================================================
// Hash bytes round-trip
// ============================================================================

func TestHashBytesRoundTrip(t *testing.T) {
	h := ComputeHash([]byte("test"))
	b, err := h.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 32 {
		t.Errorf("bytes length: %d", len(b))
	}
}

func TestHashString(t *testing.T) {
	h := ComputeHash([]byte("hello"))
	s := h.String()
	if s == "" {
		t.Error("Hash.String() returned empty string")
	}
	// String() must equal the underlying Hash value
	if s != string(h) {
		t.Errorf("String() mismatch: got %q want %q", s, string(h))
	}
	// fmt.Stringer compliance — the %s verb must route through Hash.String().
	if got := fmt.Sprintf("%s", h); got != s { //nolint:staticcheck // intentionally exercises the fmt.Stringer path
		t.Errorf("fmt.Sprintf: %q vs %q", got, s)
	}
}

// ============================================================================
// Coverage uplift: Record collision remapping + LookupByID store error
// ============================================================================

// failOnGetStore wraps MemoryStore but returns an error for Get calls.
type failOnGetStore struct {
	*MemoryStore
}

func (f *failOnGetStore) Get(_ Hash) ([]byte, error) {
	return nil, fmt.Errorf("simulated store failure")
}

// TestProvenanceRecordCollisionRemapping verifies that recording the same
// externalID with a different payload removes the stale reverse-lookup entry.
func TestProvenanceRecordCollisionRemapping(t *testing.T) {
	prov := NewProvenance(NewMemoryStore())

	h1, _ := prov.Record("id-1", []byte("payload-a"))
	// Same ID, different payload → remapping
	h2, _ := prov.Record("id-1", []byte("payload-b"))
	if h1 == h2 {
		t.Fatal("different payloads should produce different hashes")
	}
	// Old hash should no longer list id-1
	oldIDs := prov.LookupIDs(h1)
	for _, id := range oldIDs {
		if id == "id-1" {
			t.Error("stale id-1 should have been removed from old hash's list")
		}
	}
	// New hash should list id-1
	newIDs := prov.LookupIDs(h2)
	found := false
	for _, id := range newIDs {
		if id == "id-1" {
			found = true
		}
	}
	if !found {
		t.Error("id-1 should be in new hash's list after remapping")
	}
}

// TestProvenanceRecordStoreError exercises the store.Put error path.
func TestProvenanceRecordStoreError(t *testing.T) {
	errStore := &failPutStore{}
	prov := NewProvenance(errStore)
	_, err := prov.Record("x", []byte("data"))
	if err == nil {
		t.Fatal("store.Put failure should propagate from Record")
	}
}

// TestProvenanceLookupByIDStoreError exercises the store.Get error path.
func TestProvenanceLookupByIDStoreError(t *testing.T) {
	inner := NewMemoryStore()
	prov := NewProvenance(inner)
	// Record via inner store directly so we have a mapping.
	prov.Record("my-id", []byte("data"))
	// Now switch to a store that fails Get.
	failProv := NewProvenance(&failOnGetStore{inner})
	// Manually copy the idToHash mapping into failProv.
	failProv.mu.Lock()
	for k, v := range prov.idToHash {
		failProv.idToHash[k] = v
	}
	failProv.mu.Unlock()
	_, _, err := failProv.LookupByID("my-id")
	if err == nil {
		t.Fatal("store.Get failure should propagate from LookupByID")
	}
}

// failPutStore always returns an error from Put.
type failPutStore struct{}

func (f *failPutStore) Put(_ []byte) (Hash, error) { return "", fmt.Errorf("put failed") }
func (f *failPutStore) Get(_ Hash) ([]byte, error) { return nil, fmt.Errorf("get failed") }
func (f *failPutStore) Has(_ Hash) bool            { return false }
func (f *failPutStore) Size() int                  { return 0 }
func (f *failPutStore) Iterate(_ func(h Hash) error) error {
	return nil
}

// ============================================================================
// Axis 87 — read-path integrity verification (GetVerified / ErrCorrupted)
// ============================================================================

// corruptingStore is a pluggable backend that returns bytes which do NOT hash to
// the requested address — modeling disk bitrot, a tampered object store, or a
// backend that ignores the content-addressed contract.
type corruptingStore struct {
	returns []byte
}

func (c *corruptingStore) Put(_ []byte) (Hash, error)         { return "", nil }
func (c *corruptingStore) Get(_ Hash) ([]byte, error)         { return c.returns, nil }
func (c *corruptingStore) Has(_ Hash) bool                    { return true }
func (c *corruptingStore) Size() int                          { return 1 }
func (c *corruptingStore) Iterate(_ func(h Hash) error) error { return nil }

// TestGetVerifiedHappyPath confirms GetVerified returns the payload unchanged when
// the backend honors the content-address contract.
func TestGetVerifiedHappyPath(t *testing.T) {
	store := NewMemoryStore()
	payload := []byte("trusted content")
	h, _ := store.Put(payload)
	got, err := GetVerified(store, h)
	if err != nil {
		t.Fatalf("GetVerified on honest store: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("payload mismatch: %q", got)
	}
}

// TestGetVerifiedDetectsCorruption is the core defense: a backend returning bytes
// that do not match the requested hash must surface as ErrCorrupted, not silently
// hand back wrong content.
func TestGetVerifiedDetectsCorruption(t *testing.T) {
	// Address of the *expected* content.
	want := ComputeHash([]byte("original"))
	// Backend hands back different bytes.
	store := &corruptingStore{returns: []byte("tampered")}
	_, err := GetVerified(store, want)
	if !errors.Is(err, ErrCorrupted) {
		t.Fatalf("want ErrCorrupted for hash mismatch, got %v", err)
	}
}

// TestGetVerifiedPropagatesNotFound confirms a backend Get error (e.g. not found)
// propagates unchanged rather than being masked as ErrCorrupted.
func TestGetVerifiedPropagatesNotFound(t *testing.T) {
	store := NewMemoryStore()
	_, err := GetVerified(store, ComputeHash([]byte("never stored")))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

// TestProvenanceLookupByIDDetectsCorruption verifies the audit-lookup path is now
// integrity-checked end to end: a corrupted backend behind Provenance yields
// ErrCorrupted from LookupByID.
func TestProvenanceLookupByIDDetectsCorruption(t *testing.T) {
	// Establish a mapping id → hash(original) using an honest store, then swap to
	// a corrupting backend that returns tampered bytes for that hash.
	honest := NewMemoryStore()
	prov := NewProvenance(honest)
	h, _ := prov.Record("audit-1", []byte("original"))

	tampered := NewProvenance(&corruptingStore{returns: []byte("tampered")})
	tampered.mu.Lock()
	tampered.idToHash["audit-1"] = h
	tampered.mu.Unlock()

	_, _, err := tampered.LookupByID("audit-1")
	if !errors.Is(err, ErrCorrupted) {
		t.Fatalf("LookupByID against corrupted backend: want ErrCorrupted, got %v", err)
	}
}
