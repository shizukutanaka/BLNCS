package didwebvh

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"blrcs/multiformats"
)

// eddsa-jcs-2022 signing input (W3C Data Integrity):
//
//	hashData = SHA-256(JCS(proofConfig)) || SHA-256(JCS(document-without-proof))
//	signature = Ed25519(hashData)
//	proofValue = multibase-base58btc(signature)
//
// For did:webvh the "document" is the log entry with versionId set to the
// predecessor versionId and the proof removed.

// proofConfig is the proof object without proofValue (the "proof options").
func proofConfig(p *Proof) map[string]any {
	cfg := map[string]any{
		"type":               p.Type,
		"cryptosuite":        p.Cryptosuite,
		"verificationMethod": p.VerificationMethod,
		"proofPurpose":       p.ProofPurpose,
	}
	if p.Created != "" {
		cfg["created"] = p.Created
	}
	return cfg
}

// hashData builds the eddsa-jcs-2022 signing input over the entry + proof config.
func hashData(entry *LogEntry, predecessorVersionID string, p *Proof) ([]byte, error) {
	cfgCanon, err := multiformats.Canonicalize(proofConfig(p))
	if err != nil {
		return nil, fmt.Errorf("didwebvh: canonicalize proof config: %w", err)
	}
	doc, err := entryHashInput(entry, predecessorVersionID)
	if err != nil {
		return nil, err
	}
	docCanon, err := multiformats.Canonicalize(doc)
	if err != nil {
		return nil, fmt.Errorf("didwebvh: canonicalize document: %w", err)
	}
	cfgHash := sha256.Sum256(cfgCanon)
	docHash := sha256.Sum256(docCanon)
	return append(cfgHash[:], docHash[:]...), nil
}

// signEntry creates a Data Integrity proof for an entry using the given key.
// verificationMethod is the full "<vm>#<multikey>" identifier.
func signEntry(entry *LogEntry, predecessorVersionID string, priv ed25519.PrivateKey, verificationMethod, created string) (Proof, error) {
	p := Proof{
		Type:               "DataIntegrityProof",
		Cryptosuite:        Cryptosuite,
		Created:            created,
		VerificationMethod: verificationMethod,
		ProofPurpose:       "assertionMethod",
	}
	data, err := hashData(entry, predecessorVersionID, &p)
	if err != nil {
		return Proof{}, err
	}
	sig := ed25519.Sign(priv, data)
	p.ProofValue = multiformats.EncodeMultibaseBase58(sig)
	return p, nil
}

// verifyEntryProof verifies a single entry's proof against the authorized update
// keys (Multikey strings). It returns the Multikey that produced a valid
// signature, or an error.
func verifyEntryProof(entry *LogEntry, predecessorVersionID string, authorizedKeys []string) (string, error) {
	if len(entry.Proof) == 0 {
		return "", fmt.Errorf("%w: no proof", ErrProofInvalid)
	}
	// Build a quick lookup of authorized public keys.
	type vk struct {
		multikey string
		pub      ed25519.PublicKey
	}
	var keys []vk
	for _, mk := range authorizedKeys {
		pub, err := multiformats.DecodeEd25519Multikey(mk)
		if err != nil {
			continue // skip non-Ed25519 / malformed authorized entries
		}
		keys = append(keys, vk{multikey: mk, pub: pub})
	}
	if len(keys) == 0 {
		return "", ErrNoUpdateKeys
	}

	for i := range entry.Proof {
		p := &entry.Proof[i]
		if p.Cryptosuite != Cryptosuite || p.ProofValue == "" {
			continue
		}
		sig, err := multiformats.DecodeMultibaseBase58(p.ProofValue)
		if err != nil || len(sig) != ed25519.SignatureSize {
			continue
		}
		data, err := hashData(entry, predecessorVersionID, p)
		if err != nil {
			return "", err
		}
		// The verificationMethod must name an authorized key; verify against it.
		for _, k := range keys {
			if !proofNamesKey(p.VerificationMethod, k.multikey) {
				continue
			}
			if ed25519.Verify(k.pub, data, sig) {
				return k.multikey, nil
			}
		}
	}
	return "", ErrProofInvalid
}

// proofNamesKey reports whether a verificationMethod references the given
// Multikey (did:webvh uses "...#<multikey>" or a bare multikey).
func proofNamesKey(vm, multikey string) bool {
	if vm == multikey {
		return true
	}
	// "<did>#<multikey>" or "did:key:<multikey>#<multikey>"
	if i := lastHash(vm); i >= 0 {
		return vm[i+1:] == multikey
	}
	return false
}

func lastHash(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '#' {
			return i
		}
	}
	return -1
}

var _ = json.Marshal
