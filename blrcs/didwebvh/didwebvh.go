// Package didwebvh — did:webvh ("did:web + Verifiable History") DID method.
//
// Implements the did:webvh verifiable-history model: an append-only DID log
// whose entries are cryptographically chained and self-certifying, defending
// against the key-substitution and silent-history-rewrite attacks that plain
// did:web is exposed to. It follows the spec algorithm
// (https://identity.foundation/didwebvh/):
//
//   - SCID  = base58btc(multihash(sha-256(JCS(genesis with {SCID} placeholders))))
//   - entryHash = base58btc(multihash(sha-256(JCS(entry without proof,
//     versionId = predecessor versionId))))
//   - versionId = "<version-number>-<entryHash>"
//   - each entry carries a Data Integrity proof (eddsa-jcs-2022) by an
//     authorized updateKey; key pre-rotation is enforced via nextKeyHashes.
//
// Security model implemented and tested here: SCID self-certification, entry
// hash-chaining (tamper / reorder / truncation detection), update-key
// authorization, and pre-rotation commitment enforcement. The wire format
// (JCS, multihash, base58btc, Multikey) is built on the KAT-validated
// blrcs/multiformats primitives.
//
// Note: full byte-for-byte interop should be validated against the official
// did:webvh test vectors. Witness cosigning and did:web fallback resolution are
// not implemented here.
package didwebvh

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"blrcs/multiformats"
)

// Method is the DID method name.
const Method = "webvh"

// SCIDPlaceholder is the literal substituted into the genesis entry before the
// SCID is known (spec uses "{SCID}").
const SCIDPlaceholder = "{SCID}"

// Cryptosuite is the Data Integrity cryptosuite used for log-entry proofs.
const Cryptosuite = "eddsa-jcs-2022"

// Errors.
var (
	ErrEmptyLog          = errors.New("didwebvh: empty DID log")
	ErrSCIDMismatch      = errors.New("didwebvh: SCID does not match genesis entry")
	ErrEntryHashMismatch = errors.New("didwebvh: entryHash does not match versionId")
	ErrVersionSequence   = errors.New("didwebvh: version numbers not sequential")
	ErrProofInvalid      = errors.New("didwebvh: entry proof invalid")
	ErrUnauthorizedKey   = errors.New("didwebvh: entry signed by unauthorized update key")
	ErrPreRotation       = errors.New("didwebvh: update key not committed by predecessor nextKeyHashes")
	ErrDeactivated       = errors.New("didwebvh: DID is deactivated")
	ErrMalformedEntry    = errors.New("didwebvh: malformed log entry")
	ErrNoUpdateKeys      = errors.New("didwebvh: no update keys in effect")
	// ErrWitnessThreshold is returned by VerifyWithWitnesses when an entry
	// declares a witness requirement (Parameters.Witness) but the supplied
	// WitnessLog does not contain enough valid, distinct witness proofs to
	// meet the declared threshold. Per spec: "If a DID Controller has opted
	// to use witnesses for the DID, the required proofs from the DID's
	// witnesses must be collected and published in the did-witness.json file
	// before the DID with the new version is published" — so an insufficiently
	// witnessed entry must be rejected, not silently accepted.
	ErrWitnessThreshold = errors.New("didwebvh: insufficient valid witness proofs for declared threshold")
)

// Parameters are the did:webvh log-entry parameters (spec §parameters).
type Parameters struct {
	Method        string   `json:"method,omitempty"`
	SCID          string   `json:"scid,omitempty"`
	UpdateKeys    []string `json:"updateKeys,omitempty"`    // Multikey (z6Mk…)
	NextKeyHashes []string `json:"nextKeyHashes,omitempty"` // base58btc(multihash) commitments
	Portable      bool     `json:"portable,omitempty"`
	Deactivated   bool     `json:"deactivated,omitempty"`
	TTL           int      `json:"ttl,omitempty"`
	// Witness declares the did:key witnesses required to co-sign updates from
	// this entry on, and how many of them (threshold) — see witness.go. nil
	// means no witness requirement is in effect for this entry.
	Witness *Witness `json:"witness,omitempty"`
}

// Proof is a W3C Data Integrity proof (eddsa-jcs-2022) on a log entry.
type Proof struct {
	Type               string `json:"type"`               // "DataIntegrityProof"
	Cryptosuite        string `json:"cryptosuite"`        // "eddsa-jcs-2022"
	Created            string `json:"created,omitempty"`  // RFC 3339
	VerificationMethod string `json:"verificationMethod"` // did:key:<multikey>#<multikey>
	ProofPurpose       string `json:"proofPurpose"`       // "assertionMethod"
	ProofValue         string `json:"proofValue"`         // multibase base58btc signature
}

// LogEntry is one entry in a did:webvh DID log.
type LogEntry struct {
	VersionID   string         `json:"versionId"`
	VersionTime string         `json:"versionTime"`
	Parameters  Parameters     `json:"parameters"`
	State       map[string]any `json:"state"` // the DID document
	Proof       []Proof        `json:"proof,omitempty"`
}

// ============================================================================
// SCID / entryHash
// ============================================================================

// computeHash returns base58btc(multihash(sha-256(JCS(v)))).
func computeHash(v any) (string, error) {
	canon, err := multiformats.Canonicalize(v)
	if err != nil {
		return "", err
	}
	return multiformats.HashThenBase58(canon), nil
}

// entryHashInput builds the hash input map for an entry: the entry without its
// proof, with versionId replaced by the predecessor versionId.
func entryHashInput(entry *LogEntry, predecessorVersionID string) (map[string]any, error) {
	// Round-trip through JSON to get the canonical decoded-JSON value model
	// (so Parameters/State serialize exactly as they would on the wire).
	noProof := struct {
		VersionID   string         `json:"versionId"`
		VersionTime string         `json:"versionTime"`
		Parameters  Parameters     `json:"parameters"`
		State       map[string]any `json:"state"`
	}{
		VersionID:   predecessorVersionID,
		VersionTime: entry.VersionTime,
		Parameters:  entry.Parameters,
		State:       entry.State,
	}
	raw, err := json.Marshal(noProof)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// computeEntryHash computes the entryHash for an entry given its predecessor.
func computeEntryHash(entry *LogEntry, predecessorVersionID string) (string, error) {
	in, err := entryHashInput(entry, predecessorVersionID)
	if err != nil {
		return "", err
	}
	return computeHash(in)
}

// deriveSCID computes the SCID from a genesis entry, by substituting the actual
// SCID back to the placeholder in the hash input (the inverse of issuance).
//
// It rejects a genesis that already contains the placeholder literal ("{SCID}")
// anywhere, since that would make the substitution non-invertible and let a
// crafted entry forge a matching SCID. It also requires a non-trivial SCID.
func deriveSCID(entry *LogEntry) (string, error) {
	if len(entry.Parameters.SCID) < 8 {
		return "", fmt.Errorf("%w: scid too short", ErrSCIDMismatch)
	}
	in, err := entryHashInput(entry, SCIDPlaceholder)
	if err != nil {
		return "", err
	}
	// The genesis entry — its parameters AND state — must not itself contain the
	// placeholder literal at verify time: at creation the real SCID replaced every
	// placeholder, so a legitimate entry has none left. If a crafted entry smuggles
	// a raw "{SCID}" into any field (e.g. nextKeyHashes, updateKeys, or a state
	// value), the real→placeholder inverse substitution below would be
	// non-invertible and could be used to forge a matching SCID. We scan the whole
	// hash input rather than just state (an earlier version checked only state,
	// leaving the parameters — the more security-sensitive half — unguarded).
	// versionId is excluded because we deliberately set it to the placeholder here.
	scanInput := make(map[string]any, len(in))
	for k, v := range in {
		if k == "versionId" {
			continue
		}
		scanInput[k] = v
	}
	if containsPlaceholder(scanInput) {
		return "", fmt.Errorf("%w: genesis entry contains the SCID placeholder literal", ErrSCIDMismatch)
	}
	withPlaceholder := substituteSCID(in, entry.Parameters.SCID, SCIDPlaceholder)
	return computeHash(withPlaceholder)
}

// containsPlaceholder reports whether any string in a decoded-JSON structure
// contains the SCID placeholder literal.
func containsPlaceholder(v any) bool {
	switch val := v.(type) {
	case string:
		return strings.Contains(val, SCIDPlaceholder)
	case []any:
		for _, e := range val {
			if containsPlaceholder(e) {
				return true
			}
		}
	case map[string]any:
		for _, e := range val {
			if containsPlaceholder(e) {
				return true
			}
		}
	}
	return false
}

// substituteSCID recursively replaces every occurrence of `from` with `to` in
// string values within a decoded-JSON structure.
func substituteSCID(v any, from, to string) any {
	switch val := v.(type) {
	case string:
		if from == "" {
			return val
		}
		return strings.ReplaceAll(val, from, to)
	case []any:
		out := make([]any, len(val))
		for i, e := range val {
			out[i] = substituteSCID(e, from, to)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, e := range val {
			out[k] = substituteSCID(e, from, to)
		}
		return out
	default:
		return v
	}
}

// parseVersionID splits "<n>-<entryHash>" into its parts.
func parseVersionID(versionID string) (num int, hash string, err error) {
	dash := strings.IndexByte(versionID, '-')
	if dash <= 0 || dash == len(versionID)-1 {
		return 0, "", fmt.Errorf("%w: bad versionId %q", ErrMalformedEntry, versionID)
	}
	num, err = strconv.Atoi(versionID[:dash])
	if err != nil || num < 1 {
		return 0, "", fmt.Errorf("%w: bad version number in %q", ErrMalformedEntry, versionID)
	}
	return num, versionID[dash+1:], nil
}

// ============================================================================
// nextKeyHashes (pre-rotation)
// ============================================================================

// KeyHash returns base58btc(multihash(sha-256(multikey-string))) — the
// pre-rotation commitment form stored in nextKeyHashes. Callers use it to
// pre-commit the next update key(s) when creating or updating a DID.
func KeyHash(multikey string) string {
	return multiformats.HashThenBase58([]byte(multikey))
}

// keyHash is the internal alias used by verification.
func keyHash(multikey string) string { return KeyHash(multikey) }

// sha256Hex is a small helper for tests/debugging (unused in hot paths).
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum[:])
}

var _ = sha256Hex // retained for diagnostic use

var _ = ed25519.PublicKeySize
