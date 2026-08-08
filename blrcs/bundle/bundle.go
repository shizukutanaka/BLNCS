// Package bundle — self-contained, long-term-verifiable Digital Product Passport.
//
// # Why (first principles, then the literature that corrects it)
//
// A DPP must stay verifiable for the PRODUCT's lifetime — 10-25 years for an EV
// battery — at the places it is actually scanned: recycling facilities, ports,
// customs, warehouses. Two physical facts follow: those verifiers are frequently
// OFFLINE, and the issuer's server will not outlive the product (ESPR
// contemplates DPP data surviving the economic operator). Every other
// verification path in this repo fetches something at verify time — the issuer
// key (didresolver HTTP), the status list (URL), the receipt — so none of them
// survive either condition.
//
// The naive fix ("staple the evidence next to the credential") is not enough,
// and the long-term-signature literature says exactly why:
//
//   - ETSI Long-Term Validation (LTV / AdES-A, TS 101 733 / TS 103 172 family)
//     requires THREE things to validate a signature years later: (a) a trusted
//     TIMESTAMP, (b) the full key/certificate chain, and (c) revocation data
//     captured at a point in time. (b) and (c) alone are insufficient: without
//     (a), a verifier in 2045 looking at a rotated or expired issuer key cannot
//     distinguish "legitimately signed in 2026 while that key was valid" from
//     "forged in 2045 with a long-dead key". The timestamp is what anchors the
//     signature's existence inside the key's validity window.
//
//   - IETF RFC 4998 (Evidence Record Syntax) goes further: over an archival
//     horizon the ARCHIVE's own cryptography ages too. ERS therefore renews
//     archive timestamps as a CHAIN, where each new archive timestamp is taken
//     over the previous evidence, "preserv[ing] non-repudiation of the previous
//     chains, even after the hash algorithm used within the previous Archive
//     Timestamp's hash tree became weak". Renewal must happen BEFORE the old
//     algorithms weaken, not after.
//
// This package applies both. BLRCS already operates a timestamping authority —
// the SCITT transparency ledger, whose Receipt carries RegisteredAt plus a TS
// signature over the tree head. So a receipt is not merely "nice extra
// transparency evidence"; it is the LTV timestamp, and it is what makes the
// bundle a long-term artifact rather than a convenience wrapper. Anchors are
// held as an ERS-style ordered chain, and Renew re-anchors the WHOLE current
// bundle (evidence included) so the new anchor vouches for the old ones.
//
// # What this package does not do
//
// It adds no cryptography. Every check delegates to primitives already verified
// elsewhere in this repo, each of which already accepts its key/token as an
// argument (i.e. is already offline-capable):
//
//	compliance.VerifySDJWTWithBinding — credential signature + temporal bounds
//	compliance.CheckRevokedToken      — revocation against a signed snapshot
//	revocation.VerifyStatusListTokenAt— snapshot authenticity + freshness
//	didwebvh.Verify                   — issuer-key provenance from an embedded log
//	scitt.VerifyReceipt               — timestamp/inclusion proof
//
// # Honest reporting
//
// An offline verifier must never read silence as success: "no status snapshot
// in the bundle" is NOT "not revoked". Result records which checks actually ran,
// and Verify fails closed when the caller requires a check the bundle cannot
// support.
package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"blrcs/compliance"
	"blrcs/didwebvh"
	"blrcs/multiformats"
	"blrcs/revocation"
	"blrcs/scitt"
)

// Version identifies the bundle wire format.
const Version = "blrcs-dpp-bundle/1"

// AnchorContentType labels the payload a renewal anchor timestamps: the hash of
// the bundle's evidence as it stood when the anchor was taken.
const AnchorContentType = "application/vnd.blrcs.bundle-digest"

var (
	ErrMalformed = errors.New("bundle: malformed bundle")
	// ErrIssuerKeyNotInLog: the bundle staples a did:webvh log that does not
	// authorize the key which signed the credential. Without this check an
	// attacker could attach any valid-looking log to a credential signed by an
	// unrelated key and claim provenance.
	ErrIssuerKeyNotInLog = errors.New("bundle: issuer key not authorized by the embedded DID log")
	ErrRevoked           = errors.New("bundle: credential is revoked")
	ErrStatusStale       = errors.New("bundle: status snapshot is stale")
	// ErrCheckUnavailable: the caller required a check for which the bundle
	// carries no evidence. Failing closed is the point — silence must not read
	// as "check passed".
	ErrCheckUnavailable = errors.New("bundle: required check has no evidence in the bundle")
	// ErrAnchorChainBroken: an anchor does not attest the evidence that preceded
	// it, so the ERS-style chain does not actually carry the older evidence
	// forward.
	ErrAnchorChainBroken = errors.New("bundle: anchor chain broken")
)

// Anchor is one archive timestamp over the bundle's evidence at a point in time
// (RFC 4998's "Archive Timestamp"). Statement.PayloadHash commits to the
// evidence digest; Receipt carries the Transparency Service's signature and
// RegisteredAt, which together are the trusted timestamp ETSI LTV requires.
type Anchor struct {
	Statement scitt.Statement `json:"statement"`
	Receipt   scitt.Receipt   `json:"receipt"`
	// TSKey is the Transparency Service public key that signed Receipt
	// (base64-std, as carried in the receipt itself but pinned here so the
	// bundle stays self-contained).
	TSKey []byte `json:"tsKey"`
	// EvidenceDigest is the hex SHA-256 over the evidence this anchor attests.
	EvidenceDigest string `json:"evidenceDigest"`
}

// Bundle is the portable artifact. Credential + IssuerKey are required; each
// optional member enables one more check.
type Bundle struct {
	Version string `json:"version"`
	// Credential is the SD-JWT-VC (issuer JWT + disclosures).
	Credential string `json:"credential"`
	// IssuerKey is the Ed25519 public key that signed Credential.
	IssuerKey []byte `json:"issuerKey"`
	// IssuerDIDLog optionally proves IssuerKey's provenance without resolving
	// the DID over the network (ETSI LTV component (b): the key chain).
	IssuerDIDLog []didwebvh.LogEntry `json:"issuerDidLog,omitempty"`
	// StatusToken/StatusKey optionally carry a signed revocation snapshot
	// (ETSI LTV component (c): revocation data captured at a point in time).
	StatusToken string `json:"statusToken,omitempty"`
	StatusKey   []byte `json:"statusKey,omitempty"`
	// Anchors is the ERS-style archive-timestamp chain (ETSI LTV component
	// (a)). Index 0 is the original anchor; each later anchor attests the
	// bundle evidence INCLUDING all earlier anchors, so renewing before the old
	// algorithms weaken carries the old evidence forward.
	Anchors   []Anchor  `json:"anchors,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

// Options configures what Verify demands. The zero value verifies whatever
// evidence is present and honestly reports the rest as not-checked. A caller
// making a compliance decision should set the Require* flags so that missing
// evidence fails instead of passing quietly.
type Options struct {
	Now                    time.Time
	RequireProvenance      bool
	RequireRevocationCheck bool
	// RequireTimestamp demands at least one verifiable archive anchor — the
	// ETSI LTV timestamp. Set this for any decision made after the issuer key
	// could plausibly have rotated or expired.
	RequireTimestamp bool
	// MaxStatusAge bounds how old the revocation snapshot may be. A 10-year-old
	// "not revoked" snapshot is not evidence of anything.
	MaxStatusAge time.Duration
}

// Result reports what was actually verified. Each Checked* field separates
// "verified" from "no evidence present" so absence can never be mistaken for
// success.
type Result struct {
	Claims *compliance.VerifiedClaims

	CheckedProvenance bool
	IssuerDID         string

	CheckedRevocation bool
	Revoked           bool
	StatusIssuedAt    time.Time
	StatusStale       bool

	CheckedTimestamp bool
	// AnchorTimes are the RegisteredAt of each verified anchor, oldest first.
	// AnchorTimes[0] is the earliest proof that the credential existed.
	AnchorTimes []time.Time
	AnchorCount int
}

// BuildOptions carries the optional evidence to embed.
type BuildOptions struct {
	IssuerDIDLog []didwebvh.LogEntry
	StatusToken  string
	StatusKey    ed25519.PublicKey
	Now          time.Time
}

// Build assembles an un-anchored bundle. Call Anchor to add the LTV timestamp.
func Build(credential string, issuerKey ed25519.PublicKey, opts BuildOptions) (*Bundle, error) {
	if credential == "" {
		return nil, fmt.Errorf("%w: credential required", ErrMalformed)
	}
	if len(issuerKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: issuer key must be %d bytes", ErrMalformed, ed25519.PublicKeySize)
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	b := &Bundle{
		Version:      Version,
		Credential:   credential,
		IssuerKey:    append([]byte(nil), issuerKey...),
		IssuerDIDLog: opts.IssuerDIDLog,
		StatusToken:  opts.StatusToken,
		CreatedAt:    now.UTC(),
	}
	if len(opts.StatusKey) > 0 {
		b.StatusKey = append([]byte(nil), opts.StatusKey...)
	}
	return b, nil
}

// evidenceDigest hashes everything the next anchor must attest: the credential,
// the keys, the provenance log, the revocation snapshot, and every anchor taken
// so far. Including prior anchors is what makes the chain an ERS-style chain
// rather than a bag of independent timestamps — a renewal vouches for the older
// evidence, so it survives the older algorithms weakening.
func (b *Bundle) evidenceDigest() (string, error) {
	snapshot := struct {
		Version      string              `json:"version"`
		Credential   string              `json:"credential"`
		IssuerKey    []byte              `json:"issuerKey"`
		IssuerDIDLog []didwebvh.LogEntry `json:"issuerDidLog,omitempty"`
		StatusToken  string              `json:"statusToken,omitempty"`
		StatusKey    []byte              `json:"statusKey,omitempty"`
		Anchors      []Anchor            `json:"anchors,omitempty"`
	}{b.Version, b.Credential, b.IssuerKey, b.IssuerDIDLog, b.StatusToken, b.StatusKey, b.Anchors}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// TimestampAuthority is the subset of a SCITT ledger this package needs to take
// an archive timestamp. *scitt.Ledger satisfies it.
type TimestampAuthority interface {
	Register(stmt scitt.Statement) (*scitt.Receipt, error)
	PublicKey() ed25519.PublicKey
}

// Anchor takes an archive timestamp over the bundle's current evidence and
// appends it to the chain. Call it once at issuance (the ETSI LTV timestamp),
// and again — via Renew — before the in-use algorithms are expected to weaken.
//
// signerPriv/issuerID identify who submits the anchor statement to the ledger;
// the security property comes from the ledger's countersignature (Receipt), not
// from the submitter.
func (b *Bundle) Anchor(ta TimestampAuthority, signerPriv ed25519.PrivateKey, issuerID string) error {
	if ta == nil {
		return fmt.Errorf("%w: timestamp authority required", ErrMalformed)
	}
	digest, err := b.evidenceDigest()
	if err != nil {
		return err
	}
	stmt, err := scitt.SignStatement(signerPriv, issuerID, digest, AnchorContentType, []byte(digest))
	if err != nil {
		return fmt.Errorf("bundle: anchor statement: %w", err)
	}
	receipt, err := ta.Register(stmt)
	if err != nil {
		return fmt.Errorf("bundle: anchor registration: %w", err)
	}
	b.Anchors = append(b.Anchors, Anchor{
		Statement:      stmt,
		Receipt:        *receipt,
		TSKey:          append([]byte(nil), ta.PublicKey()...),
		EvidenceDigest: digest,
	})
	return nil
}

// Renew adds a fresh archive timestamp over the whole current bundle, including
// every previous anchor (RFC 4998 timestamp renewal). Perform this while the
// existing anchors' algorithms are still trusted; renewing afterwards proves
// nothing about the interval that already elapsed.
func (b *Bundle) Renew(ta TimestampAuthority, signerPriv ed25519.PrivateKey, issuerID string) error {
	if len(b.Anchors) == 0 {
		return fmt.Errorf("%w: nothing to renew (bundle has no anchor)", ErrMalformed)
	}
	return b.Anchor(ta, signerPriv, issuerID)
}

// Marshal serializes the bundle — this byte string is the portable artifact.
func (b *Bundle) Marshal() ([]byte, error) { return json.Marshal(b) }

// Parse deserializes a bundle and checks structural invariants.
func Parse(data []byte) (*Bundle, error) {
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if b.Version != Version {
		return nil, fmt.Errorf("%w: unsupported version %q", ErrMalformed, b.Version)
	}
	if b.Credential == "" || len(b.IssuerKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: credential and a 32-byte issuerKey are required", ErrMalformed)
	}
	return &b, nil
}

// Verify validates the bundle performing NO network calls.
//
// Order matters: provenance first (every later check is only meaningful if the
// key that signed the credential is the key the DID authorizes), then the
// credential itself, then revocation, then the archive-timestamp chain.
func Verify(b *Bundle, opts Options) (*Result, error) {
	if b == nil {
		return nil, ErrMalformed
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	res := &Result{}

	// (b) Key chain: issuer-key provenance from the embedded did:webvh log.
	if len(b.IssuerDIDLog) > 0 {
		resolution, err := didwebvh.Verify(b.IssuerDIDLog)
		if err != nil {
			return nil, fmt.Errorf("bundle: issuer DID log: %w", err)
		}
		if !logAuthorizesKey(b.IssuerDIDLog, b.IssuerKey) {
			return nil, ErrIssuerKeyNotInLog
		}
		res.CheckedProvenance = true
		res.IssuerDID = resolution.DID
	} else if opts.RequireProvenance {
		return nil, fmt.Errorf("%w: provenance (no issuerDidLog)", ErrCheckUnavailable)
	}

	// The credential itself: signature + temporal bounds.
	claims, err := compliance.VerifySDJWTWithBinding(b.Credential, b.IssuerKey, compliance.VerifyOptions{Now: now})
	if err != nil {
		return nil, fmt.Errorf("bundle: credential: %w", err)
	}
	res.Claims = claims

	// (c) Revocation against the embedded signed snapshot.
	switch {
	case b.StatusToken != "" && len(b.StatusKey) == ed25519.PublicKeySize:
		_, meta, err := revocation.VerifyStatusListTokenAt(b.StatusToken, b.StatusKey, revocation.PurposeRevocation, now)
		if err != nil {
			return nil, fmt.Errorf("bundle: status token: %w", err)
		}
		revoked, err := compliance.CheckRevokedToken(claims, b.StatusToken, b.StatusKey)
		if err != nil {
			return nil, fmt.Errorf("bundle: revocation check: %w", err)
		}
		res.CheckedRevocation = true
		res.Revoked = revoked
		res.StatusIssuedAt = time.Unix(meta.IssuedAt, 0).UTC()
		if opts.MaxStatusAge > 0 && now.Sub(res.StatusIssuedAt) > opts.MaxStatusAge {
			res.StatusStale = true
			return res, ErrStatusStale
		}
		if revoked {
			return res, ErrRevoked
		}
	case opts.RequireRevocationCheck:
		return nil, fmt.Errorf("%w: revocation (no statusToken/statusKey)", ErrCheckUnavailable)
	}

	// (a) The archive-timestamp chain.
	if len(b.Anchors) > 0 {
		times, err := verifyAnchorChain(b)
		if err != nil {
			return nil, err
		}
		res.CheckedTimestamp = true
		res.AnchorTimes = times
		res.AnchorCount = len(times)
	} else if opts.RequireTimestamp {
		return nil, fmt.Errorf("%w: timestamp (no anchors)", ErrCheckUnavailable)
	}

	return res, nil
}

// verifyAnchorChain checks every archive timestamp and that the chain actually
// chains: anchor i must attest the evidence digest computed over the bundle as
// it stood with only anchors[0:i] present. A chain that fails this is a bag of
// unrelated timestamps, not an ERS-style renewal chain, and must not be
// presented as long-term evidence.
func verifyAnchorChain(b *Bundle) ([]time.Time, error) {
	times := make([]time.Time, 0, len(b.Anchors))
	for i := range b.Anchors {
		a := b.Anchors[i]
		if len(a.TSKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: anchor %d has no TS key", ErrMalformed, i)
		}
		if err := scitt.VerifyReceipt(&a.Receipt, a.Statement, a.TSKey); err != nil {
			return nil, fmt.Errorf("bundle: anchor %d receipt: %w", i, err)
		}
		// Recompute what this anchor should have attested.
		prefix := &Bundle{
			Version:      b.Version,
			Credential:   b.Credential,
			IssuerKey:    b.IssuerKey,
			IssuerDIDLog: b.IssuerDIDLog,
			StatusToken:  b.StatusToken,
			StatusKey:    b.StatusKey,
			Anchors:      b.Anchors[:i],
		}
		want, err := prefix.evidenceDigest()
		if err != nil {
			return nil, err
		}
		if a.EvidenceDigest != want {
			return nil, fmt.Errorf("%w: anchor %d attests %s, evidence hashes to %s",
				ErrAnchorChainBroken, i, short(a.EvidenceDigest), short(want))
		}
		// The statement must actually commit to that digest, else the ledger
		// countersigned something unrelated to this bundle.
		if a.Statement.Subject != want {
			return nil, fmt.Errorf("%w: anchor %d statement subject does not match the evidence digest", ErrAnchorChainBroken, i)
		}
		times = append(times, a.Receipt.RegisteredAt.UTC())
	}
	return times, nil
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// logAuthorizesKey reports whether pub appears among the update keys any entry
// of the log puts in force. did:webvh update keys are Multikey-encoded, so each
// is decoded and compared as raw bytes.
func logAuthorizesKey(log []didwebvh.LogEntry, pub []byte) bool {
	for i := range log {
		for _, mk := range log[i].Parameters.UpdateKeys {
			decoded, err := multiformats.DecodeEd25519Multikey(mk)
			if err != nil {
				continue
			}
			if bytes.Equal(decoded, pub) {
				return true
			}
		}
	}
	return false
}
