// COSE_Sign1 receipt encoding for IETF SCITT transparency log.
//
// Provides COSE_Sign1 (RFC 9052) encoding of SCITT receipts as an alternative
// to the default JSON+Ed25519 format. The COSE receipt is interoperable with
// IETF SCITT-compliant verifiers; the existing JSON receipt format remains the
// default for backward compatibility.
//
// COSE Receipt payload map (integer keys, CBOR):
//
//	1: leaf_index  (uint)
//	2: tree_size   (uint)
//	3: root_hash   (bstr, 32 bytes, SHA-256)
//	4: audit_path  ([bstr])
//	5: ts_id       (tstr)
//	6: reg_at      (uint, Unix epoch)
package scitt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"blrcs/cbor"
)

// Payload map keys for COSE receipts.
const (
	cbrLeafIndex  = 1
	cbrTreeSize   = 2
	cbrRootHash   = 3
	cbrAuditPath  = 4
	cbrTSID       = 5
	cbrRegistered = 6
)

// ErrCOSEReceiptInvalid is returned when COSE receipt verification fails.
var ErrCOSEReceiptInvalid = errors.New("scitt: COSE receipt invalid")

// IssueCOSEReceipt encodes a Receipt as a COSE_Sign1 structure signed by the
// Transparency Service Ed25519 private key (COSE alg EdDSA, -8).
//
// The returned bytes are self-contained and verifiable by any IETF
// SCITT-compatible verifier via VerifyCOSEReceipt.
//
// For P-256 transparency services, see IssueCOSEReceiptES256.
func IssueCOSEReceipt(r *Receipt, tsPriv ed25519.PrivateKey, tsID string) ([]byte, error) {
	payload, err := coseReceiptPayload(r, tsID)
	if err != nil {
		return nil, err
	}
	protected := cbor.Header{
		cbor.HeaderAlg: cbor.AlgEdDSA,
		cbor.HeaderKid: []byte(tsID),
	}
	return cbor.Sign1(protected, nil, payload, nil, tsPriv)
}

// IssueCOSEReceiptES256 encodes a Receipt as a COSE_Sign1 structure signed by
// the Transparency Service P-256 private key (COSE alg ES256, -7, raw R||S per
// RFC 9053 section 2.1).
//
// ES256 is the algorithm the EUDI ecosystem and most IETF SCITT deployments
// actually speak; this is the interoperable counterpart to IssueCOSEReceipt.
// cbor.Sign1ES256 rejects a protected header that declares any other
// algorithm, so the declared alg cannot diverge from the key that signed.
//
// Verify with VerifyCOSEReceipt, passing the SEC1 encoding of the public key
// (see ecdsakey.MarshalP256PublicKey).
func IssueCOSEReceiptES256(r *Receipt, tsPriv *ecdsa.PrivateKey, tsID string) ([]byte, error) {
	payload, err := coseReceiptPayload(r, tsID)
	if err != nil {
		return nil, err
	}
	protected := cbor.Header{
		cbor.HeaderAlg: cbor.AlgES256,
		cbor.HeaderKid: []byte(tsID),
	}
	return cbor.Sign1ES256(protected, nil, payload, nil, tsPriv)
}

// coseReceiptPayload builds the CBOR receipt payload shared by every signing
// algorithm. One definition means an ES256 receipt and an EdDSA receipt cover
// exactly the same bytes.
func coseReceiptPayload(r *Receipt, tsID string) ([]byte, error) {
	rootBytes, err := hexDecode(r.RootHash)
	if err != nil {
		return nil, fmt.Errorf("scitt: bad root hash: %w", err)
	}

	pathAny := make([]any, len(r.AuditPath))
	for i, h := range r.AuditPath {
		b, err := hexDecode(h)
		if err != nil {
			return nil, fmt.Errorf("scitt: bad audit_path[%d]: %w", i, err)
		}
		pathAny[i] = b
	}

	payload, err := cbor.Marshal(map[int]any{
		cbrLeafIndex:  r.LeafIndex,
		cbrTreeSize:   r.TreeSize,
		cbrRootHash:   rootBytes,
		cbrAuditPath:  pathAny,
		cbrTSID:       tsID,
		cbrRegistered: uint64(r.RegisteredAt.Unix()),
	})
	if err != nil {
		return nil, fmt.Errorf("scitt: marshal COSE receipt payload: %w", err)
	}
	return payload, nil
}

// VerifyCOSEReceipt verifies a COSE_Sign1 receipt against the given Statement.
//
// It checks:
//  1. COSE_Sign1 signature using tsPub.
//  2. Merkle inclusion proof for stmt in the recorded tree.
//
// tsPub is the raw public key, encoded to match the algorithm the receipt's
// protected header declares: 32 raw bytes for EdDSA (-8), or SEC1 P-256 for
// ES256 (-7) — 65-byte uncompressed or 33-byte compressed. A key whose length
// or curve does not match the declared algorithm makes verification fail; it
// never panics.
//
// The algorithm is taken from the sender's protected header. A relying party
// that knows which algorithm its transparency service uses should pin it with
// VerifyCOSEReceiptWithAlgs rather than accepting whatever arrives.
func VerifyCOSEReceipt(data []byte, stmt Statement, tsPub []byte) error {
	return VerifyCOSEReceiptWithAlgs(data, stmt, tsPub, nil)
}

// VerifyCOSEReceiptWithAlgs is VerifyCOSEReceipt with an optional per-call COSE
// algorithm allowlist (see cbor.Verify1WithAlgs), e.g. []int{cbor.AlgES256}. A
// nil/empty allowedAlgs accepts any registered algorithm, identical to
// VerifyCOSEReceipt.
func VerifyCOSEReceiptWithAlgs(data []byte, stmt Statement, tsPub []byte, allowedAlgs []int) error {
	res, err := cbor.Verify1WithAlgs(data, tsPub, nil, allowedAlgs)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCOSEReceiptInvalid, err)
	}
	fields, err := decodeReceiptPayload(res.Payload)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCOSEReceiptInvalid, err)
	}

	// Leaf hash = hashLeaf(json.Marshal(stmt)) — same as Register()
	raw, err := json.Marshal(stmt)
	if err != nil {
		return err
	}
	leaf := hashLeaf(raw)

	if !VerifyInclusion(leaf, fields.rootHash, fields.leafIndex, fields.treeSize, fields.auditPath) {
		return fmt.Errorf("%w: inclusion proof failed", ErrCOSEReceiptInvalid)
	}
	return nil
}

// ============================================================================
// internal helpers
// ============================================================================

type receiptPayload struct {
	leafIndex uint64
	treeSize  uint64
	rootHash  []byte
	auditPath [][]byte
	tsID      string
	regAt     time.Time
}

func decodeReceiptPayload(data []byte) (*receiptPayload, error) {
	v, err := cbor.Unmarshal(data)
	if err != nil {
		return nil, err
	}
	rawMap, ok := v.(map[any]any)
	if !ok {
		return nil, errors.New("payload must be CBOR map")
	}
	m := cbor.IntMap(rawMap)

	leafIdx, ok := cbor.GetInt(m[cbrLeafIndex])
	if !ok {
		return nil, errors.New("missing leaf_index (key 1)")
	}
	treeSize, ok := cbor.GetInt(m[cbrTreeSize])
	if !ok {
		return nil, errors.New("missing tree_size (key 2)")
	}
	rootHash, ok := cbor.GetBytes(m[cbrRootHash])
	if !ok {
		return nil, errors.New("missing root_hash (key 3)")
	}

	rawPath, ok := m[cbrAuditPath].([]any)
	if !ok {
		return nil, errors.New("missing audit_path (key 4)")
	}
	auditPath := make([][]byte, len(rawPath))
	for i, elem := range rawPath {
		b, ok := cbor.GetBytes(elem)
		if !ok {
			return nil, fmt.Errorf("audit_path[%d] not bstr", i)
		}
		auditPath[i] = b
	}

	var tsID string
	if s, ok := m[cbrTSID].(string); ok {
		tsID = s
	}
	var regAt time.Time
	if n, ok := cbor.GetInt(m[cbrRegistered]); ok && n >= 0 {
		regAt = time.Unix(n, 0).UTC()
	}

	return &receiptPayload{
		leafIndex: uint64(leafIdx),
		treeSize:  uint64(treeSize),
		rootHash:  rootHash,
		auditPath: auditPath,
		tsID:      tsID,
		regAt:     regAt,
	}, nil
}
