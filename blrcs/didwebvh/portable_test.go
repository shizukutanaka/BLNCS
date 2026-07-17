package didwebvh

import (
	"errors"
	"testing"
	"time"
)

// boolPtr is a small test helper — Parameters.Portable is *bool so the spec's
// "omitted vs. explicit false" distinction (§DID Portability, "Retains value
// if omitted in later entries") is representable.
func boolPtr(b bool) *bool { return &b }

// TestPortableDefaultRejectsDomainChange proves the core security property
// the audit flagged as missing: without portable declared (the spec default,
// false), a log that silently moves state.id to a different domain/path MUST
// be rejected — previously Verify never inspected state.id on any entry after
// the genesis, so this rewrite went undetected.
func TestPortableDefaultRejectsDomainChange(t *testing.T) {
	updateKey, _ := genKey(t)
	genesis, did, err := Create(CreateParams{DIDPath: "example.com:dids:p", UpdateKey: updateKey})
	if err != nil {
		t.Fatal(err)
	}
	log := []LogEntry{*genesis}

	movedID := replaceRest(t, did, "attacker.example:dids:p")
	upd, err := Update(UpdateParams{
		Log:         log,
		SignKey:     updateKey,
		NewState:    map[string]any{"id": movedID},
		VersionTime: time.Now().Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	log = append(log, *upd)

	if _, err := Verify(log); !errors.Is(err, ErrPortableViolation) {
		t.Fatalf("domain change without portability: want ErrPortableViolation, got %v", err)
	}
}

// TestPortableTrueAllowsDomainChange proves the flip side: a DID whose
// genesis explicitly opts into portability CAN move domain/path while
// retaining its SCID, and Verify resolves the moved DID.
func TestPortableTrueAllowsDomainChange(t *testing.T) {
	updateKey, _ := genKey(t)
	genesis, did, err := Create(CreateParams{
		DIDPath:   "example.com:dids:p",
		UpdateKey: updateKey,
		Portable:  boolPtr(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	log := []LogEntry{*genesis}

	movedID := replaceRest(t, did, "new-home.example:dids:p")
	upd, err := Update(UpdateParams{
		Log:         log,
		SignKey:     updateKey,
		NewState:    map[string]any{"id": movedID},
		VersionTime: time.Now().Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	log = append(log, *upd)

	res, err := Verify(log)
	if err != nil {
		t.Fatalf("portable DID should allow domain move: %v", err)
	}
	if res.DID != movedID {
		t.Errorf("resolved DID should reflect the move: got %s want %s", res.DID, movedID)
	}
}

// TestPortableSCIDChangeAlwaysRejected proves the SCID segment of state.id
// can NEVER change across entries — not even when portable=true, since only
// the host/path portion may move (spec: "the SCID segment is immutable for
// the life of the DID"). This is the attack the audit specifically called
// out: a malicious log silently rewriting a DID's SCID.
func TestPortableSCIDChangeAlwaysRejected(t *testing.T) {
	updateKey, _ := genKey(t)
	genesis, did, err := Create(CreateParams{
		DIDPath:   "example.com:dids:p",
		UpdateKey: updateKey,
		Portable:  boolPtr(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	log := []LogEntry{*genesis}

	forgedID := "did:" + Method + ":QmForgedForgedForgedForgedForgedForgedForge:example.com:dids:p"
	_ = did
	upd, err := Update(UpdateParams{
		Log:         log,
		SignKey:     updateKey,
		NewState:    map[string]any{"id": forgedID},
		VersionTime: time.Now().Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	log = append(log, *upd)

	if _, err := Verify(log); !errors.Is(err, ErrPortableViolation) {
		t.Fatalf("SCID rewrite should always be rejected, even under portable=true: got %v", err)
	}
}

// TestPortableLaterEntrySettingTrueRejected proves only the genesis entry may
// enable portability — a later entry attempting to turn it on for the first
// time must be rejected regardless of whether it also tries to move.
func TestPortableLaterEntrySettingTrueRejected(t *testing.T) {
	updateKey, _ := genKey(t)
	genesis, did, err := Create(CreateParams{DIDPath: "example.com:dids:p", UpdateKey: updateKey})
	if err != nil {
		t.Fatal(err)
	}
	log := []LogEntry{*genesis}

	upd, err := Update(UpdateParams{
		Log:         log,
		SignKey:     updateKey,
		NewState:    map[string]any{"id": did, "v": "2"},
		Portable:    boolPtr(true),
		VersionTime: time.Now().Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	log = append(log, *upd)

	if _, err := Verify(log); !errors.Is(err, ErrPortableViolation) {
		t.Fatalf("later entry setting portable=true: want ErrPortableViolation, got %v", err)
	}
}

// TestPortableExplicitFalseDisablesFurtherMoves proves that once a later
// entry explicitly sets portable=false, subsequent entries can no longer
// move domain/path even though the DID started out portable.
func TestPortableExplicitFalseDisablesFurtherMoves(t *testing.T) {
	updateKey, _ := genKey(t)
	genesis, did, err := Create(CreateParams{
		DIDPath:   "example.com:dids:p",
		UpdateKey: updateKey,
		Portable:  boolPtr(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	log := []LogEntry{*genesis}

	// Entry 2: moves domain (allowed, portable in effect from genesis) AND
	// disables portability from here on.
	movedID := replaceRest(t, did, "second-home.example:dids:p")
	upd2, err := Update(UpdateParams{
		Log:         log,
		SignKey:     updateKey,
		NewState:    map[string]any{"id": movedID},
		Portable:    boolPtr(false),
		VersionTime: time.Now().Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	log = append(log, *upd2)
	if _, err := Verify(log); err != nil {
		t.Fatalf("entry 2 move + disable should verify: %v", err)
	}

	// Entry 3: attempts another move — must fail, portability was disabled.
	movedAgainID := replaceRest(t, movedID, "third-home.example:dids:p")
	upd3, err := Update(UpdateParams{
		Log:         log,
		SignKey:     updateKey,
		NewState:    map[string]any{"id": movedAgainID},
		VersionTime: time.Now().Add(2 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	log = append(log, *upd3)
	if _, err := Verify(log); !errors.Is(err, ErrPortableViolation) {
		t.Fatalf("move after portable=false disabled: want ErrPortableViolation, got %v", err)
	}
}

// TestPortableOmittedRetainsPriorValue proves that a later entry which omits
// the portable parameter entirely retains whatever value was previously in
// effect (spec: "Retains value if omitted in later entries") — an omitted
// entry after a portable=true genesis can still move domain/path.
func TestPortableOmittedRetainsPriorValue(t *testing.T) {
	updateKey, _ := genKey(t)
	genesis, did, err := Create(CreateParams{
		DIDPath:   "example.com:dids:p",
		UpdateKey: updateKey,
		Portable:  boolPtr(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	log := []LogEntry{*genesis}

	// Entry 2: omits portable, but still moves — must succeed (retains true).
	movedID := replaceRest(t, did, "second-home.example:dids:p")
	upd2, err := Update(UpdateParams{
		Log:         log,
		SignKey:     updateKey,
		NewState:    map[string]any{"id": movedID},
		VersionTime: time.Now().Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	log = append(log, *upd2)

	res, err := Verify(log)
	if err != nil {
		t.Fatalf("omitted portable should retain prior true value: %v", err)
	}
	if res.DID != movedID {
		t.Errorf("resolved DID should reflect the move: got %s want %s", res.DID, movedID)
	}
}

// replaceRest builds a new did:webvh identifier with the same SCID segment as
// `did` but a different host/path segment.
func replaceRest(t *testing.T, did, newRest string) string {
	t.Helper()
	scid, _, err := splitWebVHMethodSpecificID(did)
	if err != nil {
		t.Fatal(err)
	}
	return "did:" + Method + ":" + scid + ":" + newRest
}
