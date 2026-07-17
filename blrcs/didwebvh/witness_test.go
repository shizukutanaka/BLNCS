package didwebvh

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

// genWitnessKey returns (privateKey, did:key DID) for a witness.
func genWitnessKey(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	priv, multikey := genKey(t)
	return priv, "did:key:" + multikey
}

// witnessedGenesis builds a genesis entry declaring a witness threshold and
// returns it plus the witness keys/DIDs, so tests can independently produce
// (or withhold) witness proofs.
func witnessedGenesis(t *testing.T, threshold int, numWitnesses int) (*LogEntry, string, []ed25519.PrivateKey, []string) {
	t.Helper()
	updatePriv, _ := genKey(t)

	witnessPrivs := make([]ed25519.PrivateKey, numWitnesses)
	witnessDIDs := make([]string, numWitnesses)
	witnessEntries := make([]WitnessEntry, numWitnesses)
	for i := 0; i < numWitnesses; i++ {
		priv, did := genWitnessKey(t)
		witnessPrivs[i] = priv
		witnessDIDs[i] = did
		witnessEntries[i] = WitnessEntry{ID: did}
	}

	genesis, did, err := Create(CreateParams{
		DIDPath:   "example.com:dids:witnessed",
		UpdateKey: updatePriv,
		Witness:   &Witness{Threshold: threshold, Witnesses: witnessEntries},
	})
	if err != nil {
		t.Fatal(err)
	}
	return genesis, did, witnessPrivs, witnessDIDs
}

func TestWitnessThresholdMetVerifies(t *testing.T) {
	genesis, _, privs, dids := witnessedGenesis(t, 2, 3)
	log := []LogEntry{*genesis}

	// 2 of 3 declared witnesses sign — meets threshold.
	var witnessLog WitnessLog
	var proofs []Proof
	for i := 0; i < 2; i++ {
		p, err := SignWitnessProof(genesis, "", privs[i], dids[i])
		if err != nil {
			t.Fatal(err)
		}
		proofs = append(proofs, p)
	}
	witnessLog = append(witnessLog, WitnessLogEntry{VersionID: genesis.VersionID, Proof: proofs})

	if _, err := VerifyWithWitnesses(log, witnessLog); err != nil {
		t.Fatalf("threshold met should verify: %v", err)
	}
}

func TestWitnessThresholdUnmetRejected(t *testing.T) {
	genesis, _, privs, dids := witnessedGenesis(t, 2, 3)
	log := []LogEntry{*genesis}

	// Only 1 of 2 required witnesses signs.
	p, err := SignWitnessProof(genesis, "", privs[0], dids[0])
	if err != nil {
		t.Fatal(err)
	}
	witnessLog := WitnessLog{{VersionID: genesis.VersionID, Proof: []Proof{p}}}

	_, err = VerifyWithWitnesses(log, witnessLog)
	if !errors.Is(err, ErrWitnessThreshold) {
		t.Errorf("want ErrWitnessThreshold, got %v", err)
	}
}

func TestWitnessNoProofsAtAllRejected(t *testing.T) {
	genesis, _, _, _ := witnessedGenesis(t, 1, 2)
	log := []LogEntry{*genesis}

	// No did-witness.json entry at all for this versionId.
	_, err := VerifyWithWitnesses(log, nil)
	if !errors.Is(err, ErrWitnessThreshold) {
		t.Errorf("want ErrWitnessThreshold, got %v", err)
	}
}

func TestWitnessUndeclaredWitnessDoesNotCount(t *testing.T) {
	genesis, _, _, _ := witnessedGenesis(t, 1, 1)
	log := []LogEntry{*genesis}

	// An outsider (not in the declared witness list) signs instead.
	outsiderPriv, outsiderDID := genWitnessKey(t)
	p, err := SignWitnessProof(genesis, "", outsiderPriv, outsiderDID)
	if err != nil {
		t.Fatal(err)
	}
	witnessLog := WitnessLog{{VersionID: genesis.VersionID, Proof: []Proof{p}}}

	_, err = VerifyWithWitnesses(log, witnessLog)
	if !errors.Is(err, ErrWitnessThreshold) {
		t.Errorf("an undeclared witness's proof should not count toward threshold, got %v", err)
	}
}

func TestWitnessDuplicateProofFromSameWitnessNotDoubleCounted(t *testing.T) {
	genesis, _, privs, dids := witnessedGenesis(t, 2, 2)
	log := []LogEntry{*genesis}

	// The SAME witness signs twice (e.g. resubmission); only 1 distinct witness
	// total, threshold is 2 — must still fail.
	p1, err := SignWitnessProof(genesis, "", privs[0], dids[0])
	if err != nil {
		t.Fatal(err)
	}
	p2, err := SignWitnessProof(genesis, "", privs[0], dids[0])
	if err != nil {
		t.Fatal(err)
	}
	witnessLog := WitnessLog{{VersionID: genesis.VersionID, Proof: []Proof{p1, p2}}}

	_, err = VerifyWithWitnesses(log, witnessLog)
	if !errors.Is(err, ErrWitnessThreshold) {
		t.Errorf("duplicate proofs from one witness must not satisfy a 2-witness threshold, got %v", err)
	}
}

func TestWitnessTamperedProofRejected(t *testing.T) {
	genesis, _, privs, dids := witnessedGenesis(t, 1, 1)
	log := []LogEntry{*genesis}

	p, err := SignWitnessProof(genesis, "", privs[0], dids[0])
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the signature.
	p.ProofValue = p.ProofValue[:len(p.ProofValue)-4] + "0000"
	witnessLog := WitnessLog{{VersionID: genesis.VersionID, Proof: []Proof{p}}}

	_, err = VerifyWithWitnesses(log, witnessLog)
	if !errors.Is(err, ErrWitnessThreshold) {
		t.Errorf("tampered witness signature should not verify, got %v", err)
	}
}

func TestVerifyWithWitnessesNoRequirementBehavesLikeVerify(t *testing.T) {
	updatePriv, _ := genKey(t)
	genesis, did, err := Create(CreateParams{DIDPath: "example.com:dids:no-witness", UpdateKey: updatePriv})
	if err != nil {
		t.Fatal(err)
	}
	log := []LogEntry{*genesis}

	res, err := VerifyWithWitnesses(log, nil)
	if err != nil {
		t.Fatalf("no witness requirement declared should verify without any witnessLog: %v", err)
	}
	if res.DID != did {
		t.Errorf("did mismatch: %s vs %s", res.DID, did)
	}
}

func TestVerifyIgnoresWitnessRequirement(t *testing.T) {
	// The plain Verify (no witnesses) must NOT enforce witness thresholds —
	// that enforcement is opt-in via VerifyWithWitnesses, matching every other
	// *Tx / *WithX backward-compatible variant added this session.
	genesis, _, _, _ := witnessedGenesis(t, 5, 5) // impossible threshold to meet
	log := []LogEntry{*genesis}

	if _, err := Verify(log); err != nil {
		t.Errorf("plain Verify should not enforce witness threshold, got %v", err)
	}
}

func TestSignWitnessProofRejectsMismatchedKey(t *testing.T) {
	priv, _ := genKey(t)
	genesis, _, err := Create(CreateParams{DIDPath: "example.com:dids:x", UpdateKey: priv})
	if err != nil {
		t.Fatal(err)
	}

	_, wrongDID := genWitnessKey(t)
	rightPriv, _ := genWitnessKey(t) // different key than wrongDID
	_, err = SignWitnessProof(genesis, "", rightPriv, wrongDID)
	if !errors.Is(err, ErrProofInvalid) {
		t.Errorf("mismatched witnessDID/witnessPriv should error, got %v", err)
	}
}

func TestSignWitnessProofRejectsNonDIDKey(t *testing.T) {
	priv, _ := genKey(t)
	genesis, _, err := Create(CreateParams{DIDPath: "example.com:dids:x", UpdateKey: priv})
	if err != nil {
		t.Fatal(err)
	}
	_, witnessPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = SignWitnessProof(genesis, "", witnessPriv, "not-a-did-key")
	if !errors.Is(err, ErrMalformedEntry) {
		t.Errorf("non-did:key witnessDID should error, got %v", err)
	}
}

func TestWitnessOnUpdateEntry(t *testing.T) {
	// Witness requirement declared on an UPDATE entry (not just genesis) —
	// proves the threshold check iterates every entry in the log, not just
	// entry 0.
	updatePriv, _ := genKey(t)
	genesis, did, err := Create(CreateParams{DIDPath: "example.com:dids:upd", UpdateKey: updatePriv})
	if err != nil {
		t.Fatal(err)
	}
	witnessPriv, witnessDID := genWitnessKey(t)

	upd, err := Update(UpdateParams{
		Log:      []LogEntry{*genesis},
		SignKey:  updatePriv,
		NewState: map[string]any{"id": did},
		Witness:  &Witness{Threshold: 1, Witnesses: []WitnessEntry{{ID: witnessDID}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	log := []LogEntry{*genesis, *upd}

	// No witness proof yet for the update entry -> must fail.
	if _, err := VerifyWithWitnesses(log, nil); !errors.Is(err, ErrWitnessThreshold) {
		t.Fatalf("unwitnessed update entry should fail, got %v", err)
	}

	// Witness signs the update entry (predecessor = genesis.VersionID).
	p, err := SignWitnessProof(upd, genesis.VersionID, witnessPriv, witnessDID)
	if err != nil {
		t.Fatal(err)
	}
	witnessLog := WitnessLog{{VersionID: upd.VersionID, Proof: []Proof{p}}}
	if _, err := VerifyWithWitnesses(log, witnessLog); err != nil {
		t.Errorf("witnessed update entry should verify: %v", err)
	}
}
