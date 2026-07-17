package didwebvh

import (
	"crypto/ed25519"
	"fmt"
	"strings"
	"time"

	"blrcs/multiformats"
)

// ============================================================================
// Witnesses — did:webvh v1.0 §Witnesses
//
// A witness is a third party (identified by its own did:key DID) that
// co-signs a log entry, independent of the DID's own update-key authority.
// Unlike the controller's own proof (embedded in LogEntry.Proof), witness
// proofs live in a SEPARATE file — did-witness.json — keyed by versionId,
// per spec:
//
//	"witness": {"threshold": n, "witnesses": [{"id": "<did:key DID>"}]}
//
//	did-witness.json:
//	[{"versionId": "1-Qm...", "proof": [{...}, {...}]}, ...]
//
// This mirrors the update-key model (Multikey-based Ed25519 signatures,
// eddsa-jcs-2022 cryptosuite, same hashData construction as the controller's
// own proof) but with an independent trust root and an "any N of M" threshold
// rather than "the single currently-authorized key".
// ============================================================================

// WitnessEntry — one witness's did:key identifier.
type WitnessEntry struct {
	ID string `json:"id"` // e.g. "did:key:z6Mk..."
}

// Witness declares which DIDs must co-sign updates from an entry on, and how
// many of them are required. A nil *Witness (the Parameters.Witness zero
// value) means no witness requirement is in effect.
type Witness struct {
	Threshold int            `json:"threshold"`
	Witnesses []WitnessEntry `json:"witnesses"`
}

// WitnessLogEntry is one line of a did-witness.json file: the proofs a set of
// witnesses produced for one specific log entry, referenced by versionId.
type WitnessLogEntry struct {
	VersionID string  `json:"versionId"`
	Proof     []Proof `json:"proof"`
}

// WitnessLog is the full did-witness.json content: witness proofs for
// however many entries have been witnessed so far.
type WitnessLog []WitnessLogEntry

// didKeyToMultikey extracts the Multikey portion of a did:key DID
// ("did:key:z6Mk..." -> "z6Mk..."). Witnesses are identified by did:key DID
// per spec; the DID's own identifier IS the Multikey-encoded public key, so
// no network resolution is needed (unlike did:web) — this is a pure string
// operation, and the caller can independently confirm authenticity by
// checking the resulting key actually produces valid signatures.
func didKeyToMultikey(didKey string) (string, error) {
	const prefix = "did:key:"
	if !strings.HasPrefix(didKey, prefix) {
		return "", fmt.Errorf("%w: witness id is not a did:key DID: %q", ErrMalformedEntry, didKey)
	}
	mk := strings.TrimPrefix(didKey, prefix)
	if mk == "" {
		return "", fmt.Errorf("%w: empty did:key identifier", ErrMalformedEntry)
	}
	return mk, nil
}

// SignWitnessProof creates one witness's Data Integrity proof for a log
// entry, to be appended to that witness's WitnessLogEntry in did-witness.json
// — NOT to the entry's own Proof field, which is reserved for the DID
// controller's own signature (see the package doc above for why these are
// separate files).
//
// witnessDID is this witness's own did:key identifier; its embedded public
// key must correspond to witnessPriv, or this returns an error rather than
// silently producing a proof no one can verify against the declared witness
// list. predecessorVersionID is the prior entry's versionId (empty for the
// genesis entry) — the same hashData construction the controller's own proof
// uses, so a witness is independently attesting to the exact same entry
// content, not a different view of it.
func SignWitnessProof(entry *LogEntry, predecessorVersionID string, witnessPriv ed25519.PrivateKey, witnessDID string) (Proof, error) {
	if len(witnessPriv) != ed25519.PrivateKeySize {
		return Proof{}, fmt.Errorf("%w: witness signing key required", ErrProofInvalid)
	}
	mk, err := didKeyToMultikey(witnessDID)
	if err != nil {
		return Proof{}, err
	}
	decodedPub, err := multiformats.DecodeEd25519Multikey(mk)
	if err != nil {
		return Proof{}, fmt.Errorf("%w: witnessDID: %v", ErrMalformedEntry, err)
	}
	signPub := witnessPriv.Public().(ed25519.PublicKey)
	if !decodedPub.Equal(signPub) {
		return Proof{}, fmt.Errorf("%w: witnessDID's embedded key does not match witnessPriv", ErrProofInvalid)
	}
	// did:key's own verification method convention: "<did:key DID>#<multikey>".
	vm := witnessDID + "#" + mk
	return signEntry(entry, predecessorVersionID, witnessPriv, vm, time.Now().UTC().Format(time.RFC3339))
}

// VerifyWithWitnesses is Verify plus witness-threshold enforcement: for every
// log entry whose Parameters.Witness declares a threshold, at least that many
// valid, DISTINCT witness proofs (from the declared witness list) must be
// present in witnessLog for that entry's versionId, or the whole log is
// rejected — an entry cannot silently take effect without its required
// witnessing, per spec.
//
// witnessLog may be nil if no log entry declares a witness requirement (the
// common case); this is equivalent to calling Verify directly in that case.
func VerifyWithWitnesses(log []LogEntry, witnessLog WitnessLog) (*Resolution, error) {
	res, err := Verify(log)
	if err != nil {
		return nil, err
	}
	byVersion := make(map[string][]Proof, len(witnessLog))
	for _, w := range witnessLog {
		byVersion[w.VersionID] = w.Proof
	}
	for i := range log {
		entry := &log[i]
		wc := entry.Parameters.Witness
		if wc == nil || wc.Threshold <= 0 {
			continue
		}
		predecessor := ""
		if i > 0 {
			predecessor = log[i-1].VersionID
		}
		valid, verr := countValidWitnessProofs(entry, predecessor, byVersion[entry.VersionID], wc.Witnesses)
		if verr != nil {
			return nil, verr
		}
		if valid < wc.Threshold {
			return nil, fmt.Errorf("%w: entry %s has %d valid witness proof(s), need %d",
				ErrWitnessThreshold, entry.VersionID, valid, wc.Threshold)
		}
	}
	return res, nil
}

// countValidWitnessProofs verifies proofs against the declared witness list
// and returns how many DISTINCT witnesses produced a valid signature (a
// witness that submits multiple proofs, or whose proof happens to verify
// against more than one declared witness key, is only counted once — the
// threshold is about how many independent parties attested, not how many
// bytes of signature exist).
func countValidWitnessProofs(entry *LogEntry, predecessorVersionID string, proofs []Proof, witnesses []WitnessEntry) (int, error) {
	authorized := make(map[string]bool, len(witnesses))
	for _, w := range witnesses {
		mk, err := didKeyToMultikey(w.ID)
		if err != nil {
			continue // a malformed declared witness id just can't ever be satisfied
		}
		authorized[mk] = true
	}
	seen := make(map[string]bool, len(authorized))
	for i := range proofs {
		p := &proofs[i]
		if p.Cryptosuite != Cryptosuite || p.ProofValue == "" || p.ProofPurpose != "assertionMethod" {
			continue
		}
		sig, err := multiformats.DecodeMultibaseBase58(p.ProofValue)
		if err != nil || len(sig) != ed25519.SignatureSize {
			continue
		}
		data, err := hashData(entry, predecessorVersionID, p)
		if err != nil {
			return 0, err
		}
		for mk := range authorized {
			if seen[mk] || !proofNamesKey(p.VerificationMethod, mk) {
				continue
			}
			pub, derr := multiformats.DecodeEd25519Multikey(mk)
			if derr != nil {
				continue
			}
			if ed25519.Verify(pub, data, sig) {
				seen[mk] = true
				break
			}
		}
	}
	return len(seen), nil
}
