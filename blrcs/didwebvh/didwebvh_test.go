package didwebvh

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"blrcs/multiformats"
)

func genKey(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, multiformats.EncodeEd25519Multikey(pub)
}

// ============================================================================
// genesis create + verify
// ============================================================================

func TestCreateAndVerify(t *testing.T) {
	updateKey, updateMK := genKey(t)

	entry, did, err := Create(CreateParams{
		DIDPath:   "example.com:dids:product-42",
		UpdateKey: updateKey,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// DID embeds the SCID.
	if !strings.HasPrefix(did, "did:webvh:") {
		t.Errorf("unexpected DID: %s", did)
	}
	if !strings.Contains(did, entry.Parameters.SCID) {
		t.Errorf("DID %s does not contain SCID %s", did, entry.Parameters.SCID)
	}
	if entry.Parameters.SCID == SCIDPlaceholder || entry.Parameters.SCID == "" {
		t.Errorf("SCID not resolved: %q", entry.Parameters.SCID)
	}
	if entry.Parameters.UpdateKeys[0] != updateMK {
		t.Errorf("updateKey mismatch")
	}
	if !strings.HasPrefix(entry.VersionID, "1-") {
		t.Errorf("genesis versionId should start 1-: %s", entry.VersionID)
	}

	res, err := Verify([]LogEntry{*entry})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.SCID != entry.Parameters.SCID {
		t.Errorf("resolved SCID mismatch")
	}
	if res.DID != did {
		t.Errorf("resolved DID %s != %s", res.DID, did)
	}
	if res.Deactivated {
		t.Error("should not be deactivated")
	}
}

// ============================================================================
// SCID self-certification — tamper detection
// ============================================================================

func TestSCIDTamperDetected(t *testing.T) {
	updateKey, _ := genKey(t)
	entry, _, _ := Create(CreateParams{DIDPath: "example.com:dids:x", UpdateKey: updateKey})

	// Tamper the genesis DID document after issuance: inject an extra field.
	entry.State["evilKey"] = "attacker-controlled"

	if _, err := Verify([]LogEntry{*entry}); err == nil {
		t.Fatal("tampered genesis state should fail SCID/entryHash check")
	}
}

func TestSCIDMismatchDirect(t *testing.T) {
	updateKey, _ := genKey(t)
	entry, _, _ := Create(CreateParams{DIDPath: "example.com:dids:x", UpdateKey: updateKey})
	entry.Parameters.SCID = "QmFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake"
	if _, err := Verify([]LogEntry{*entry}); err == nil {
		t.Fatal("forged SCID should be rejected")
	}
}

// ============================================================================
// update chain
// ============================================================================

func TestUpdateChain(t *testing.T) {
	updateKey, _ := genKey(t)
	genesis, did, err := Create(CreateParams{DIDPath: "example.com:dids:p", UpdateKey: updateKey})
	if err != nil {
		t.Fatal(err)
	}

	log := []LogEntry{*genesis}

	// Append an update signed by the same update key (no rotation).
	newState := map[string]any{
		"id":              did,
		"assertionMethod": []any{did + "#key-1"},
	}
	upd, err := Update(UpdateParams{
		Log:         log,
		SignKey:     updateKey,
		NewState:    newState,
		VersionTime: time.Now().Add(time.Second),
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !strings.HasPrefix(upd.VersionID, "2-") {
		t.Errorf("second entry versionId should start 2-: %s", upd.VersionID)
	}
	log = append(log, *upd)

	res, err := Verify(log)
	if err != nil {
		t.Fatalf("Verify chain: %v", err)
	}
	if res.VersionID != upd.VersionID {
		t.Errorf("latest versionId mismatch")
	}
	if _, ok := res.Document["assertionMethod"]; !ok {
		t.Error("updated document not resolved")
	}
}

func TestChainTamperBreaksLink(t *testing.T) {
	updateKey, _ := genKey(t)
	genesis, did, _ := Create(CreateParams{DIDPath: "ex:p", UpdateKey: updateKey})
	log := []LogEntry{*genesis}
	upd, _ := Update(UpdateParams{
		Log: log, SignKey: updateKey,
		NewState:    map[string]any{"id": did, "v": "2"},
		VersionTime: time.Now().Add(time.Second),
	})
	log = append(log, *upd)

	// Tamper the genesis entry after the chain is built → breaks entry 2's link.
	log[0].VersionTime = "2000-01-01T00:00:00Z"
	if _, err := Verify(log); err == nil {
		t.Fatal("tampering genesis must break the chain")
	}
}

func TestTruncationDetected(t *testing.T) {
	updateKey, _ := genKey(t)
	genesis, did, _ := Create(CreateParams{DIDPath: "ex:p", UpdateKey: updateKey})
	log := []LogEntry{*genesis}
	upd, _ := Update(UpdateParams{
		Log: log, SignKey: updateKey,
		NewState:    map[string]any{"id": did, "v": "2"},
		VersionTime: time.Now().Add(time.Second),
	})
	log = append(log, *upd)

	// Drop the genesis → version sequence starts at 2.
	if _, err := Verify(log[1:]); err == nil {
		t.Fatal("truncated log (missing genesis) should fail")
	}
}

// ============================================================================
// update-key authorization
// ============================================================================

func TestUnauthorizedKeyRejected(t *testing.T) {
	updateKey, _ := genKey(t)
	attackerKey, _ := genKey(t)
	genesis, did, _ := Create(CreateParams{DIDPath: "ex:p", UpdateKey: updateKey})
	log := []LogEntry{*genesis}

	// Attacker signs an update with a key NOT in the genesis updateKeys, and
	// does not change updateKeys (so authorized set is still the genesis key).
	upd, err := Update(UpdateParams{
		Log:         log,
		SignKey:     attackerKey,
		NewState:    map[string]any{"id": did, "v": "evil"},
		UpdateKeys:  effectiveUpdateKeys(log), // keep genesis keys in force
		VersionTime: time.Now().Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	log = append(log, *upd)

	if _, err := Verify(log); err == nil {
		t.Fatal("update signed by unauthorized key must be rejected")
	}
}

// ============================================================================
// key pre-rotation
// ============================================================================

func TestPreRotationHappyPath(t *testing.T) {
	updateKey, _ := genKey(t)
	_, rotMK := genKey(t)

	// Genesis commits to the next key's hash.
	genesis, did, err := Create(CreateParams{
		DIDPath:       "ex:p",
		UpdateKey:     updateKey,
		NextKeyHashes: []string{KeyHash(rotMK)},
	})
	if err != nil {
		t.Fatal(err)
	}
	log := []LogEntry{*genesis}

	// Rotate: the new entry's updateKeys = [rotMK], signed by rotKey.
	upd, err := Update(UpdateParams{
		Log:         log,
		SignKey:     updateKey, // authorized by genesis to make THIS entry
		NewState:    map[string]any{"id": did, "v": "2"},
		UpdateKeys:  []string{rotMK},
		VersionTime: time.Now().Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	log = append(log, *upd)

	if _, err := Verify(log); err != nil {
		t.Fatalf("valid pre-rotation should verify: %v", err)
	}
}

func TestPreRotationViolation(t *testing.T) {
	updateKey, _ := genKey(t)
	_, committedMK := genKey(t)
	uncommittedKey, uncommittedMK := genKey(t)

	// Genesis commits to committedMK, but the rotation introduces uncommittedMK.
	genesis, did, _ := Create(CreateParams{
		DIDPath:       "ex:p",
		UpdateKey:     updateKey,
		NextKeyHashes: []string{KeyHash(committedMK)},
	})
	log := []LogEntry{*genesis}

	upd, _ := Update(UpdateParams{
		Log:         log,
		SignKey:     updateKey,
		NewState:    map[string]any{"id": did, "v": "2"},
		UpdateKeys:  []string{uncommittedMK}, // not pre-committed!
		VersionTime: time.Now().Add(time.Second),
	})
	log = append(log, *upd)
	_ = uncommittedKey

	if _, err := Verify(log); err == nil {
		t.Fatal("rotation to a non-pre-committed key must be rejected")
	}
}

// ============================================================================
// deactivation
// ============================================================================

func TestDeactivation(t *testing.T) {
	updateKey, _ := genKey(t)
	genesis, did, _ := Create(CreateParams{DIDPath: "ex:p", UpdateKey: updateKey})
	log := []LogEntry{*genesis}

	upd, err := Update(UpdateParams{
		Log:         log,
		SignKey:     updateKey,
		NewState:    map[string]any{"id": did},
		Deactivate:  true,
		VersionTime: time.Now().Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	log = append(log, *upd)

	res, err := Verify(log)
	if err != nil {
		t.Fatalf("deactivated DID should still verify: %v", err)
	}
	if !res.Deactivated {
		t.Error("expected Deactivated=true")
	}
}

// ============================================================================
// empty / malformed
// ============================================================================

func TestVerifyEmptyLog(t *testing.T) {
	if _, err := Verify(nil); err != ErrEmptyLog {
		t.Errorf("want ErrEmptyLog, got %v", err)
	}
}

func TestParseVersionIDBad(t *testing.T) {
	for _, bad := range []string{"", "abc", "-hash", "1-", "0-hash", "x-hash"} {
		if _, _, err := parseVersionID(bad); err == nil {
			t.Errorf("parseVersionID(%q) should fail", bad)
		}
	}
}

// TestPreRotationBypassByOmittingUpdateKeys ensures an attacker who controls the
// current update key cannot bypass a nextKeyHashes commitment by omitting
// updateKeys in the next entry (which would otherwise silently keep the
// compromised key authorized).
func TestPreRotationBypassByOmittingUpdateKeys(t *testing.T) {
	updateKey, _ := genKey(t)
	_, rotMK := genKey(t)

	// Genesis commits: the next entry MUST rotate to rotMK.
	genesis, did, err := Create(CreateParams{
		DIDPath:       "ex:p",
		UpdateKey:     updateKey,
		NextKeyHashes: []string{KeyHash(rotMK)},
	})
	if err != nil {
		t.Fatal(err)
	}
	log := []LogEntry{*genesis}

	// Craft entry 2 with NO updateKeys (bypass attempt), signed by the old key.
	// Build it manually so Update's back-fill of updateKeys doesn't mask the bug.
	prev := log[0]
	entry := &LogEntry{
		VersionTime: time.Now().Add(time.Second).UTC().Format(time.RFC3339),
		Parameters:  Parameters{SCID: prev.Parameters.SCID}, // updateKeys intentionally nil
		State:       map[string]any{"id": did, "v": "2"},
	}
	eh, err := computeEntryHash(entry, prev.VersionID)
	if err != nil {
		t.Fatal(err)
	}
	entry.VersionID = "2-" + eh
	vm := did + "#" + genesis.Parameters.UpdateKeys[0]
	proof, err := signEntry(entry, prev.VersionID, updateKey, vm, entry.VersionTime)
	if err != nil {
		t.Fatal(err)
	}
	entry.Proof = []Proof{proof}
	log = append(log, *entry)

	if _, err := Verify(log); err == nil {
		t.Fatal("omitting updateKeys after a nextKeyHashes commitment must be rejected")
	}
}

// TestSCIDPlaceholderInjectionRejected ensures a hand-crafted genesis whose
// state embeds the {SCID} placeholder literal is rejected (it would make SCID
// derivation non-invertible / forgeable). The attack vector is a forged log, so
// the entry is built directly rather than via Create (which substitutes it away).
func TestSCIDPlaceholderInjectionRejected(t *testing.T) {
	forged := LogEntry{
		VersionID:   "1-Qmforged",
		VersionTime: time.Now().UTC().Format(time.RFC3339),
		Parameters:  Parameters{SCID: "QmSomeLongEnoughScidValue"},
		State:       map[string]any{"id": "did:webvh:x:ex", "note": "embeds {SCID} here"},
	}
	if _, err := Verify([]LogEntry{forged}); err == nil {
		t.Fatal("genesis state containing the {SCID} placeholder must be rejected")
	}
}

// ============================================================================
// versionTime monotonicity — backward time and proof tampering
// ============================================================================

// TestVersionTimeBackwardDetected verifies that an update whose versionTime
// precedes the genesis entry is rejected with ErrMalformedEntry.
func TestVersionTimeBackwardDetected(t *testing.T) {
	updateKey, _ := genKey(t)
	genesisTime := time.Now().UTC()
	genesis, did, err := Create(CreateParams{
		DIDPath:     "ex:p",
		UpdateKey:   updateKey,
		VersionTime: genesisTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	log := []LogEntry{*genesis}

	// Build an update whose VersionTime is one hour before genesis — must fail.
	upd, err := Update(UpdateParams{
		Log:         log,
		SignKey:     updateKey,
		NewState:    map[string]any{"id": did, "v": "2"},
		VersionTime: genesisTime.Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("Update itself should not fail (time is not checked at write): %v", err)
	}
	log = append(log, *upd)

	_, err = Verify(log)
	if !errors.Is(err, ErrMalformedEntry) {
		t.Fatalf("backward versionTime: want ErrMalformedEntry, got %v", err)
	}
}

// TestProofInvalidDetected verifies that an entry with no proof is rejected
// with ErrProofInvalid, guarding against log entries that lack a data integrity
// proof (e.g. truncated or hand-crafted entries).
func TestProofInvalidDetected(t *testing.T) {
	updateKey, _ := genKey(t)
	genesis, _, err := Create(CreateParams{DIDPath: "ex:p", UpdateKey: updateKey})
	if err != nil {
		t.Fatal(err)
	}
	// Strip the cryptographic proof from the genesis entry.
	genesis.Proof = nil

	_, err = Verify([]LogEntry{*genesis})
	if !errors.Is(err, ErrProofInvalid) {
		t.Fatalf("missing proof: want ErrProofInvalid, got %v", err)
	}
}

func TestSHA256Hex(t *testing.T) {
	// sha256Hex is a debugging helper; this test ensures it stays reachable.
	h := sha256Hex([]byte("hello"))
	if len(h) != 64 {
		t.Errorf("sha256Hex: expected 64 hex chars, got %d", len(h))
	}
}

// ============================================================================
// Internal helper coverage
// ============================================================================

func TestContainsPlaceholderVariants(t *testing.T) {
	// string with placeholder
	if !containsPlaceholder(SCIDPlaceholder) {
		t.Error("placeholder string should match")
	}
	// []any slice containing placeholder
	if !containsPlaceholder([]any{"other", SCIDPlaceholder}) {
		t.Error("slice containing placeholder should match")
	}
	// []any slice without placeholder
	if containsPlaceholder([]any{"no", "placeholder"}) {
		t.Error("slice without placeholder should not match")
	}
	// map[string]any containing placeholder value
	if !containsPlaceholder(map[string]any{"k": SCIDPlaceholder}) {
		t.Error("map with placeholder value should match")
	}
	// map[string]any without placeholder
	if containsPlaceholder(map[string]any{"k": "safe"}) {
		t.Error("map without placeholder should not match")
	}
	// non-string/slice/map type
	if containsPlaceholder(42) {
		t.Error("integer should not match")
	}
}

func TestProofNamesKeyVariants(t *testing.T) {
	mk := "z6Mk1234"
	// Exact match
	if !proofNamesKey(mk, mk) {
		t.Error("exact match should return true")
	}
	// DID#multikey form
	if !proofNamesKey("did:webvh:example#"+mk, mk) {
		t.Error("did#multikey form should match")
	}
	// No hash in VM at all → fragment extraction fails → false
	if proofNamesKey("did:webvh:example", mk) {
		t.Error("VM with no fragment should not match")
	}
	// Wrong multikey after #
	if proofNamesKey("did:webvh:example#wrongkey", mk) {
		t.Error("wrong multikey should not match")
	}
}

func TestLastHashVariants(t *testing.T) {
	if lastHash("a#b#c") != 3 {
		t.Error("last # should be at index 3")
	}
	if lastHash("nohash") != -1 {
		t.Error("no # should return -1")
	}
}

func TestEffectiveSCIDEmptyLog(t *testing.T) {
	if s := effectiveSCID(nil); s != "" {
		t.Errorf("empty log: want empty SCID, got %q", s)
	}
}

func TestDIDFromStateNil(t *testing.T) {
	if s := didFromState(nil); s != "" {
		t.Errorf("nil state: want empty, got %q", s)
	}
}

func TestSubstituteSCIDPassthrough(t *testing.T) {
	// integer → pass through unchanged
	result := substituteSCID(42, "from", "to")
	if result != 42 {
		t.Error("non-string/slice/map should pass through")
	}
	// empty from → string value unchanged
	result = substituteSCID("hello", "", "to")
	if result != "hello" {
		t.Error("empty from → no substitution")
	}
}
