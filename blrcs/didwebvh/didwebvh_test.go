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

// TestSCIDPlaceholderInjectionInParametersRejected is the parameters-side analog
// of the state injection test. It is a *discriminating* test: Create does not
// substitute the placeholder inside nextKeyHashes, so a genesis carrying the
// {SCID} literal there still self-certifies (the derived SCID matches, because
// the verify-time real→placeholder substitution reproduces the create-time hash
// input). Such a non-canonical entry must nonetheless be rejected — an earlier
// deriveSCID scanned only state, leaving the more security-sensitive parameters
// half unguarded, and this entry would have verified successfully.
func TestSCIDPlaceholderInjectionInParametersRejected(t *testing.T) {
	updateKey, _ := genKey(t)
	genesis, _, err := Create(CreateParams{
		DIDPath:       "ex:p",
		UpdateKey:     updateKey,
		NextKeyHashes: []string{SCIDPlaceholder},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify([]LogEntry{*genesis}); err == nil {
		t.Fatal("genesis with {SCID} placeholder in parameters must be rejected")
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

// TestProofPurposeWrongRejected verifies that a validly-signed log entry is
// rejected when its proof carries proofPurpose != "assertionMethod". The
// signature is cryptographically correct (produced by an authorized update key),
// so the only defence is the purpose check required by W3C Data Integrity §2.1.
// Before the fix, the verifier accepted any purpose — a key-purpose confusion
// attack where an "authentication" proof from an unrelated protocol flow could
// masquerade as an authoritative DID-update proof.
func TestProofPurposeWrongRejected(t *testing.T) {
	updateKey, updateMK := genKey(t)
	genesis, did, err := Create(CreateParams{DIDPath: "ex:p", UpdateKey: updateKey})
	if err != nil {
		t.Fatal(err)
	}

	// Build update entry body (no proof yet).
	entry := &LogEntry{
		VersionTime: time.Now().Add(time.Second).UTC().Format(time.RFC3339),
		Parameters:  Parameters{SCID: genesis.Parameters.SCID, UpdateKeys: genesis.Parameters.UpdateKeys},
		State:       map[string]any{"id": did, "v": "2"},
	}
	eh, err := computeEntryHash(entry, genesis.VersionID)
	if err != nil {
		t.Fatal(err)
	}
	entry.VersionID = "2-" + eh

	// Build a proof with the WRONG proofPurpose but a VALID signature.
	// hashData commits proofPurpose into the signing input, so the signature
	// below is genuinely valid for purpose "authentication" — the only thing
	// that correctly rejects it is the proofPurpose guard.
	badProof := Proof{
		Type:               "DataIntegrityProof",
		Cryptosuite:        Cryptosuite,
		Created:            entry.VersionTime,
		VerificationMethod: did + "#" + updateMK,
		ProofPurpose:       "authentication", // must be "assertionMethod"
	}
	data, err := hashData(entry, genesis.VersionID, &badProof)
	if err != nil {
		t.Fatal(err)
	}
	badProof.ProofValue = multiformats.EncodeMultibaseBase58(ed25519.Sign(updateKey, data))
	entry.Proof = []Proof{badProof}

	_, err = Verify([]LogEntry{*genesis, *entry})
	if !errors.Is(err, ErrProofInvalid) {
		t.Fatalf("wrong proofPurpose must yield ErrProofInvalid, got %v", err)
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

// ============================================================================
// Coverage uplift: parseVersionID, containsPlaceholder, substituteSCID,
// deriveSCID error paths, verifyEntryProof ErrNoUpdateKeys
// ============================================================================

func TestParseVersionIDErrors(t *testing.T) {
	// No dash → bad format
	if _, _, err := parseVersionID("nodash"); err == nil {
		t.Error("no dash should fail")
	}
	// Dash at position 0 → bad (dash <= 0)
	if _, _, err := parseVersionID("-hash"); err == nil {
		t.Error("dash at position 0 should fail")
	}
	// Dash at last position → empty hash (dash == len-1)
	if _, _, err := parseVersionID("1-"); err == nil {
		t.Error("trailing dash should fail")
	}
	// Non-numeric version number
	if _, _, err := parseVersionID("abc-hash"); err == nil {
		t.Error("non-numeric version should fail")
	}
	// Version < 1 (zero)
	if _, _, err := parseVersionID("0-hash"); err == nil {
		t.Error("version 0 should fail")
	}
	// Valid version
	num, hash, err := parseVersionID("3-entryhash")
	if err != nil {
		t.Fatalf("valid versionId: %v", err)
	}
	if num != 3 || hash != "entryhash" {
		t.Errorf("got num=%d hash=%q", num, hash)
	}
}

func TestSubstituteSCIDRecursion(t *testing.T) {
	// Array recursion
	result := substituteSCID([]any{"old", "old", 42}, "old", "new")
	arr, ok := result.([]any)
	if !ok || arr[0] != "new" || arr[1] != "new" || arr[2] != 42 {
		t.Errorf("array recursion: %v", result)
	}
	// Map recursion
	m := map[string]any{"a": "old", "b": "keep"}
	result = substituteSCID(m, "old", "new")
	mm, ok := result.(map[string]any)
	if !ok || mm["a"] != "new" || mm["b"] != "keep" {
		t.Errorf("map recursion: %v", result)
	}
}

func TestDeriveSCIDShortSCID(t *testing.T) {
	entry := &LogEntry{
		Parameters: Parameters{SCID: "short"}, // < 8 chars
		State:      map[string]any{"id": "did:webvh:xxx"},
	}
	_, err := deriveSCID(entry)
	if err == nil {
		t.Fatal("short SCID should fail")
	}
}

func TestDeriveSCIDPlaceholderInState(t *testing.T) {
	entry := &LogEntry{
		Parameters: Parameters{SCID: "z6Mkabcdefghijklmno"}, // >= 8 chars
		State:      map[string]any{"id": "did:webvh:" + SCIDPlaceholder},
	}
	_, err := deriveSCID(entry)
	if err == nil {
		t.Fatal("state with SCID placeholder should fail")
	}
}

func TestVerifyEntryProofNoUpdateKeys(t *testing.T) {
	updateKey, _ := genKey(t)
	entry, _, _ := Create(CreateParams{
		DIDPath:   "example.com:dids:nokeys",
		UpdateKey: updateKey,
	})
	// Replace authorized keys with all-malformed entries → ErrNoUpdateKeys
	_, err := verifyEntryProof(entry, SCIDPlaceholder, []string{"not-a-multikey"})
	if err != ErrNoUpdateKeys {
		t.Fatalf("want ErrNoUpdateKeys, got %v", err)
	}
}

// ============================================================================
// Guard-clause paths: Create/Update nil-key, Update empty log, Verify no SCID
// ============================================================================

func TestCreateNilUpdateKey(t *testing.T) {
	_, _, err := Create(CreateParams{DIDPath: "example.com:p", UpdateKey: nil})
	if err == nil {
		t.Fatal("Create with nil UpdateKey should return an error")
	}
}

func TestUpdateEmptyLog(t *testing.T) {
	updateKey, _ := genKey(t)
	_, err := Update(UpdateParams{Log: nil, SignKey: updateKey})
	if !errors.Is(err, ErrEmptyLog) {
		t.Fatalf("Update with empty log: want ErrEmptyLog, got %v", err)
	}
}

func TestUpdateNilSignKey(t *testing.T) {
	updateKey, _ := genKey(t)
	genesis, _, err := Create(CreateParams{DIDPath: "example.com:p", UpdateKey: updateKey})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Update(UpdateParams{Log: []LogEntry{*genesis}, SignKey: nil})
	if err == nil {
		t.Fatal("Update with nil SignKey should return an error")
	}
}

func TestVerifyGenesisNoSCID(t *testing.T) {
	entry := LogEntry{
		VersionID:   "1-somehash",
		VersionTime: time.Now().UTC().Format(time.RFC3339),
		Parameters:  Parameters{SCID: ""}, // empty SCID
		State:       map[string]any{"id": "did:webvh:x:example.com"},
	}
	_, err := Verify([]LogEntry{entry})
	if !errors.Is(err, ErrMalformedEntry) {
		t.Fatalf("genesis with empty SCID: want ErrMalformedEntry, got %v", err)
	}
}

func TestVerifyProofTamperedValue(t *testing.T) {
	updateKey, _ := genKey(t)
	genesis, did, err := Create(CreateParams{DIDPath: "example.com:p", UpdateKey: updateKey})
	if err != nil {
		t.Fatal(err)
	}
	// Tamper the proof value so it becomes invalid base58/signature.
	genesis.Proof[0].ProofValue = "zBADBADBADBADBADBADBAD"
	log := []LogEntry{*genesis}
	upd, _ := Update(UpdateParams{
		Log:         log,
		SignKey:     updateKey,
		NewState:    map[string]any{"id": did},
		VersionTime: time.Now().Add(time.Second),
	})
	// Build a fresh log with the tampered genesis; the hash chain is already broken.
	if _, err := Verify([]LogEntry{*genesis, *upd}); err == nil {
		t.Fatal("tampered proof value should fail Verify")
	}
}

func TestUpdateWithNoUpdateKeysParam(t *testing.T) {
	updateKey, updateMK := genKey(t)
	genesis, did, err := Create(CreateParams{DIDPath: "example.com:p", UpdateKey: updateKey})
	if err != nil {
		t.Fatal(err)
	}
	log := []LogEntry{*genesis}
	// UpdateKeys nil → should inherit effective keys from log.
	upd, err := Update(UpdateParams{
		Log:         log,
		SignKey:     updateKey,
		NewState:    map[string]any{"id": did, "v": "2"},
		UpdateKeys:  nil, // back-fill from log
		VersionTime: time.Now().Add(time.Second),
	})
	if err != nil {
		t.Fatalf("Update with nil UpdateKeys should back-fill: %v", err)
	}
	log = append(log, *upd)
	res, err := Verify(log)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// The inherited key must still be in effect.
	if len(res.Document) == 0 {
		t.Error("document should be resolved")
	}
	_ = updateMK
}

// ============================================================================
// Coverage uplift: StateExtra, zero VersionTime, verifyEntryProof wrong
// cryptosuite, and Verify error branches.
// ============================================================================

func TestCreateStateExtra(t *testing.T) {
	updateKey, _ := genKey(t)
	genesis, _, err := Create(CreateParams{
		DIDPath:    "example.com:p",
		UpdateKey:  updateKey,
		StateExtra: map[string]any{"service": "did-endpoint"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if genesis.State["service"] != "did-endpoint" {
		t.Errorf("StateExtra not merged into state: %v", genesis.State)
	}
	// The DID should still verify correctly.
	if _, err := Verify([]LogEntry{*genesis}); err != nil {
		t.Fatalf("genesis with StateExtra should verify: %v", err)
	}
}

func TestUpdateZeroVersionTime(t *testing.T) {
	updateKey, _ := genKey(t)
	genesis, did, err := Create(CreateParams{DIDPath: "example.com:p", UpdateKey: updateKey})
	if err != nil {
		t.Fatal(err)
	}
	// VersionTime zero → Update should default to time.Now().UTC()
	upd, err := Update(UpdateParams{
		Log:         []LogEntry{*genesis},
		SignKey:     updateKey,
		NewState:    map[string]any{"id": did, "v": "2"},
		VersionTime: time.Time{},
	})
	if err != nil {
		t.Fatalf("Update with zero VersionTime should succeed: %v", err)
	}
	if upd.VersionTime == "" {
		t.Error("VersionTime should have been filled from time.Now()")
	}
}

func TestVerifyEntryProofWrongCryptosuite(t *testing.T) {
	updateKey, _ := genKey(t)
	entry, _, err := Create(CreateParams{DIDPath: "example.com:p", UpdateKey: updateKey})
	if err != nil {
		t.Fatal(err)
	}
	// Prepend a proof with wrong cryptosuite; the real proof follows.
	bogusProof := Proof{
		Type:               "DataIntegrityProof",
		Cryptosuite:        "wrong-suite",
		VerificationMethod: entry.Proof[0].VerificationMethod,
		ProofValue:         entry.Proof[0].ProofValue,
		ProofPurpose:       "assertionMethod",
	}
	entry.Proof = append([]Proof{bogusProof}, entry.Proof...)
	// verifyEntryProof should skip the bogus proof and accept the valid one.
	if _, err := Verify([]LogEntry{*entry}); err != nil {
		t.Fatalf("should skip wrong-cryptosuite proof: %v", err)
	}
}

func TestVerifyEntryProofEmptyProofValue(t *testing.T) {
	updateKey, _ := genKey(t)
	entry, _, err := Create(CreateParams{DIDPath: "example.com:p", UpdateKey: updateKey})
	if err != nil {
		t.Fatal(err)
	}
	// Insert a proof with empty ProofValue; the real proof follows.
	emptyProof := Proof{
		Type:               "DataIntegrityProof",
		Cryptosuite:        Cryptosuite,
		VerificationMethod: entry.Proof[0].VerificationMethod,
		ProofValue:         "",
		ProofPurpose:       "assertionMethod",
	}
	entry.Proof = append([]Proof{emptyProof}, entry.Proof...)
	if _, err := Verify([]LogEntry{*entry}); err != nil {
		t.Fatalf("should skip empty-proofValue proof: %v", err)
	}
}

func TestVerifyVersionSequenceError(t *testing.T) {
	updateKey, _ := genKey(t)
	genesis, did, err := Create(CreateParams{DIDPath: "example.com:p", UpdateKey: updateKey})
	if err != nil {
		t.Fatal(err)
	}
	upd, err := Update(UpdateParams{
		Log:         []LogEntry{*genesis},
		SignKey:     updateKey,
		NewState:    map[string]any{"id": did, "v": "2"},
		VersionTime: time.Now().Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Change version number to 3 while keeping the real hash → ErrVersionSequence.
	parts := strings.SplitN(upd.VersionID, "-", 2)
	upd.VersionID = "3-" + parts[1]
	_, err = Verify([]LogEntry{*genesis, *upd})
	if !errors.Is(err, ErrVersionSequence) {
		t.Fatalf("wrong version sequence: want ErrVersionSequence, got %v", err)
	}
}

func TestVerifyEntryHashMismatch(t *testing.T) {
	updateKey, _ := genKey(t)
	genesis, did, err := Create(CreateParams{DIDPath: "example.com:p", UpdateKey: updateKey})
	if err != nil {
		t.Fatal(err)
	}
	upd, err := Update(UpdateParams{
		Log:         []LogEntry{*genesis},
		SignKey:     updateKey,
		NewState:    map[string]any{"id": did, "v": "2"},
		VersionTime: time.Now().Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Keep version number correct but replace hash → ErrEntryHashMismatch.
	parts := strings.SplitN(upd.VersionID, "-", 2)
	_ = parts[1]
	upd.VersionID = parts[0] + "-FAKEHASHFAKEHASHFAKEHASH"
	_, err = Verify([]LogEntry{*genesis, *upd})
	if !errors.Is(err, ErrEntryHashMismatch) {
		t.Fatalf("hash mismatch: want ErrEntryHashMismatch, got %v", err)
	}
}

func TestVerifyBadVersionTimeFormat(t *testing.T) {
	updateKey, _ := genKey(t)
	genesis, did, err := Create(CreateParams{DIDPath: "example.com:p", UpdateKey: updateKey})
	if err != nil {
		t.Fatal(err)
	}
	upd, err := Update(UpdateParams{
		Log:         []LogEntry{*genesis},
		SignKey:     updateKey,
		NewState:    map[string]any{"id": did, "v": "2"},
		VersionTime: time.Now().Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Set a malformed VersionTime and recompute the entryHash so the hash chain
	// still validates — the ErrMalformedEntry check comes before proof verification.
	upd.VersionTime = "not-a-valid-rfc3339-time"
	newHash, err := computeEntryHash(upd, genesis.VersionID)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(upd.VersionID, "-", 2)
	upd.VersionID = parts[0] + "-" + newHash
	_, err = Verify([]LogEntry{*genesis, *upd})
	if !errors.Is(err, ErrMalformedEntry) {
		t.Fatalf("bad versionTime format: want ErrMalformedEntry, got %v", err)
	}
}

func TestVerifyBadVersionIDInLog(t *testing.T) {
	updateKey, _ := genKey(t)
	genesis, _, err := Create(CreateParams{DIDPath: "example.com:p", UpdateKey: updateKey})
	if err != nil {
		t.Fatal(err)
	}
	// Set a non-parseable VersionID on the genesis entry (after SCID derivation).
	genesis.VersionID = "malformed"
	_, err = Verify([]LogEntry{*genesis})
	if err == nil {
		t.Fatal("malformed versionId should cause Verify to fail")
	}
}

func TestUpdatePrevMalformedVersionID(t *testing.T) {
	// Update with a log whose last entry has a malformed VersionID → parseVersionID error.
	updateKey, _ := genKey(t)
	_, err := Update(UpdateParams{
		Log:      []LogEntry{{VersionID: "bad-format-no-number"}},
		SignKey:  updateKey,
		NewState: map[string]any{"id": "did:webvh:x:example.com"},
	})
	if err == nil {
		t.Fatal("malformed prev VersionID should fail")
	}
}

// ============================================================================
// Error-path coverage: non-serializable State triggers json/JCS failures
// ============================================================================

func TestComputeHashCanonicalizeError(t *testing.T) {
	// Passing a value with an unsupported type (channel) → Canonicalize fails.
	_, err := computeHash(map[string]any{"ch": make(chan int)})
	if err == nil {
		t.Error("computeHash with non-canonicalizable value must return error")
	}
}

func TestEntryHashInputMarshalError(t *testing.T) {
	// State containing a channel → json.Marshal fails inside entryHashInput.
	entry := &LogEntry{
		VersionTime: time.Now().UTC().Format(time.RFC3339),
		Parameters:  Parameters{SCID: "QmFakeScid12345"},
		State:       map[string]any{"bad": make(chan int)},
	}
	_, err := entryHashInput(entry, "prev")
	if err == nil {
		t.Error("entryHashInput with non-serializable state must return error")
	}
}

func TestHashDataEntryHashInputError(t *testing.T) {
	// hashData propagates entryHashInput failure when state is non-serializable.
	entry := &LogEntry{
		VersionTime: time.Now().UTC().Format(time.RFC3339),
		Parameters:  Parameters{SCID: "QmFakeScid12345"},
		State:       map[string]any{"bad": make(chan int)},
	}
	p := &Proof{
		Type:               "DataIntegrityProof",
		Cryptosuite:        Cryptosuite,
		VerificationMethod: "did:webvh:x:ex#z6MkTest",
		ProofPurpose:       "assertionMethod",
	}
	_, err := hashData(entry, "prev", p)
	if err == nil {
		t.Error("hashData with non-serializable entry state must return error")
	}
}

func TestSignEntryHashDataError(t *testing.T) {
	// signEntry propagates hashData failure.
	updateKey, _ := genKey(t)
	entry := &LogEntry{
		VersionTime: time.Now().UTC().Format(time.RFC3339),
		Parameters:  Parameters{SCID: "QmFakeScid12345"},
		State:       map[string]any{"bad": make(chan int)},
	}
	_, err := signEntry(entry, "prev", updateKey, "did:webvh:x:ex#key", "")
	if err == nil {
		t.Error("signEntry with non-serializable entry state must return error")
	}
}

func TestVerifyEntryProofHashDataError(t *testing.T) {
	// verifyEntryProof propagates hashData failure when state is non-serializable.
	updateKey, updateMK := genKey(t)
	// Build a probe entry: proof fields are valid enough to pass the skip-checks
	// (right cryptosuite, right-length ProofValue) so hashData is actually called.
	entry := &LogEntry{
		VersionTime: time.Now().UTC().Format(time.RFC3339),
		Parameters:  Parameters{SCID: "QmFakeScid12345"},
		State:       map[string]any{"bad": make(chan int)},
		Proof: []Proof{{
			Type:               "DataIntegrityProof",
			Cryptosuite:        Cryptosuite,
			VerificationMethod: "did:webvh:x:ex#" + updateMK,
			ProofValue:         multiformats.EncodeMultibaseBase58(make([]byte, ed25519.SignatureSize)),
			ProofPurpose:       "assertionMethod",
		}},
	}
	_ = updateKey
	_, err := verifyEntryProof(entry, "prev", []string{updateMK})
	if err == nil {
		t.Error("verifyEntryProof with non-serializable state must return error")
	}
}

// TestVerifyGenesisEmptyUpdateKeys builds a structurally valid genesis entry
// (valid SCID + entryHash) but with no UpdateKeys, so Verify reaches the
// ErrNoUpdateKeys guard before proof verification.
func TestVerifyGenesisEmptyUpdateKeys(t *testing.T) {
	entry := &LogEntry{
		VersionTime: time.Now().UTC().Format(time.RFC3339),
		Parameters: Parameters{
			Method:     "did:" + Method + ":1.0",
			SCID:       SCIDPlaceholder,
			UpdateKeys: nil, // intentionally empty
		},
		State: map[string]any{"id": "did:" + Method + ":" + SCIDPlaceholder + ":ex"},
	}
	// Compute SCID from the placeholder entry.
	scidInput, err := entryHashInput(entry, SCIDPlaceholder)
	if err != nil {
		t.Fatal(err)
	}
	scid, err := computeHash(scidInput)
	if err != nil {
		t.Fatal(err)
	}
	entry.Parameters.SCID = scid
	entry.State = substituteSCID(entry.State, SCIDPlaceholder, scid).(map[string]any)
	// Compute entryHash; predecessor for genesis is the SCID itself.
	eh, err := computeEntryHash(entry, scid)
	if err != nil {
		t.Fatal(err)
	}
	entry.VersionID = "1-" + eh

	_, err = Verify([]LogEntry{*entry})
	if !errors.Is(err, ErrNoUpdateKeys) {
		t.Fatalf("genesis with empty UpdateKeys: want ErrNoUpdateKeys, got %v", err)
	}
}
