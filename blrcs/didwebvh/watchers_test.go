package didwebvh

import (
	"testing"
	"time"
)

// strsPtr is a small test helper — Parameters.Watchers is *[]string so the
// spec's "omitted (retain) vs. explicit set/clear" distinction is representable.
func strsPtr(s ...string) *[]string {
	out := append([]string(nil), s...)
	return &out
}

// TestWatchersGenesisExposedInResolution proves a genesis-declared watcher list
// is verified and surfaced in Resolution.Watchers (spec: resolvers MUST expose
// the active watcher list in resolution metadata).
func TestWatchersGenesisExposedInResolution(t *testing.T) {
	updateKey, _ := genKey(t)
	genesis, _, err := Create(CreateParams{
		DIDPath:   "example.com:dids:w",
		UpdateKey: updateKey,
		Watchers:  strsPtr("https://watcher1.example", "https://watcher2.example"),
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := Verify([]LogEntry{*genesis})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(res.Watchers) != 2 || res.Watchers[0] != "https://watcher1.example" {
		t.Errorf("watchers not surfaced: %v", res.Watchers)
	}
}

// TestWatchersDefaultEmpty proves a log that never declares watchers resolves
// with an empty active list.
func TestWatchersDefaultEmpty(t *testing.T) {
	updateKey, _ := genKey(t)
	genesis, _, err := Create(CreateParams{DIDPath: "example.com:dids:w", UpdateKey: updateKey})
	if err != nil {
		t.Fatal(err)
	}
	res, err := Verify([]LogEntry{*genesis})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Watchers) != 0 {
		t.Errorf("watchers should default to empty, got %v", res.Watchers)
	}
}

// TestWatchersRetainedWhenOmitted proves a later entry that omits watchers
// retains the most recent prior value.
func TestWatchersRetainedWhenOmitted(t *testing.T) {
	updateKey, _ := genKey(t)
	genesis, did, err := Create(CreateParams{
		DIDPath:   "example.com:dids:w",
		UpdateKey: updateKey,
		Watchers:  strsPtr("https://watcher.example"),
	})
	if err != nil {
		t.Fatal(err)
	}
	upd, err := Update(UpdateParams{
		Log:         []LogEntry{*genesis},
		SignKey:     updateKey,
		NewState:    map[string]any{"id": did, "v": "2"},
		VersionTime: time.Now().Add(time.Second),
		// Watchers omitted → retain.
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := Verify([]LogEntry{*genesis, *upd})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Watchers) != 1 || res.Watchers[0] != "https://watcher.example" {
		t.Errorf("watchers should be retained across an omitting entry, got %v", res.Watchers)
	}
}

// TestWatchersReplacedAndCleared proves a later entry replaces the active list,
// and an explicit empty slice clears it.
func TestWatchersReplacedAndCleared(t *testing.T) {
	updateKey, _ := genKey(t)
	genesis, did, err := Create(CreateParams{
		DIDPath:   "example.com:dids:w",
		UpdateKey: updateKey,
		Watchers:  strsPtr("https://old.example"),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Entry 2 replaces the list.
	upd2, err := Update(UpdateParams{
		Log:         []LogEntry{*genesis},
		SignKey:     updateKey,
		NewState:    map[string]any{"id": did, "v": "2"},
		Watchers:    strsPtr("https://new.example"),
		VersionTime: time.Now().Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	log := []LogEntry{*genesis, *upd2}
	res, err := Verify(log)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Watchers) != 1 || res.Watchers[0] != "https://new.example" {
		t.Fatalf("watchers should be replaced, got %v", res.Watchers)
	}

	// Entry 3 clears the list with an explicit empty slice.
	upd3, err := Update(UpdateParams{
		Log:         log,
		SignKey:     updateKey,
		NewState:    map[string]any{"id": did, "v": "3"},
		Watchers:    strsPtr(), // explicit empty → clear
		VersionTime: time.Now().Add(2 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err = Verify(append(log, *upd3))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Watchers) != 0 {
		t.Errorf("watchers should be cleared by an explicit empty slice, got %v", res.Watchers)
	}
}

// TestWatchersRoundTripInEntryJSON proves the watchers value survives the entry's
// self-referential hash (i.e. it is part of Parameters and does not invalidate
// the entry) — a genesis with watchers must still verify its own SCID.
func TestWatchersRoundTripDoesNotBreakSCID(t *testing.T) {
	updateKey, _ := genKey(t)
	genesis, _, err := Create(CreateParams{
		DIDPath:   "example.com:dids:w",
		UpdateKey: updateKey,
		Watchers:  strsPtr("https://watcher.example"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify([]LogEntry{*genesis}); err != nil {
		t.Fatalf("genesis with watchers must verify its own SCID: %v", err)
	}
	if genesis.Parameters.Watchers == nil || len(*genesis.Parameters.Watchers) != 1 {
		t.Errorf("watchers not stored on the entry parameters: %v", genesis.Parameters.Watchers)
	}
}
