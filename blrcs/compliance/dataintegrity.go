package compliance

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"blrcs/multiformats"
)

// W3C Data Integrity — eddsa-jcs-2022 cryptosuite (W3C EdDSA Cryptosuites v1.0,
// REC 2025-05-15). This is the current Recommendation cryptosuite for Ed25519
// Data Integrity proofs, replacing the pre-Data-Integrity Ed25519Signature2020
// suite still used by the default Issue path. Selected via Issuer.DataIntegrity.
//
// Signing input (identical construction to the did:webvh log-entry proofs in
// didwebvh/proof.go, reusing the same KAT-validated multiformats JCS + base58
// primitives):
//
//	hashData   = SHA-256(JCS(proofConfig)) || SHA-256(JCS(document-without-proof))
//	signature  = Ed25519(hashData)
//	proofValue = multibase-base58btc(signature)     // "z"-prefixed
//
// Unlike the JSON-LD rdfc-2022 suite this uses JCS (RFC 8785) canonicalization,
// so no JSON-LD expansion/URDNA2015 is required — a good fit for this codebase's
// fixed-shape credentials and zero-dependency constraint.

// CryptosuiteEdDSAJCS2022 is the W3C Data Integrity cryptosuite identifier.
const CryptosuiteEdDSAJCS2022 = "eddsa-jcs-2022"

// credentialDocument returns the credential as a decoded-JSON map with the
// `proof` member removed — the "unsecured document" that eddsa-jcs-2022 hashes.
// Round-tripping through JSON yields the exact wire value model (float64 numbers,
// string keys) that multiformats.Canonicalize expects.
func credentialDocument(cred *Credential) (map[string]any, error) {
	raw, err := json.Marshal(cred)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	delete(m, "proof")
	return m, nil
}

// diProofConfig builds the "proof options" object (the proof without its
// proofValue) that eddsa-jcs-2022 hashes alongside the document. `created` is
// serialized as an RFC 3339 timestamp string, matching the wire form.
func diProofConfig(p *Proof) map[string]any {
	cfg := map[string]any{
		"type":               p.Type,
		"cryptosuite":        p.Cryptosuite,
		"verificationMethod": p.VerificationMethod,
		"proofPurpose":       p.ProofPurpose,
	}
	if !p.Created.IsZero() {
		cfg["created"] = p.Created.UTC().Format(time.RFC3339)
	}
	return cfg
}

// diHashData computes the eddsa-jcs-2022 signing input for a credential + proof
// config: SHA-256(JCS(proofConfig)) || SHA-256(JCS(document-without-proof)).
func diHashData(cred *Credential, p *Proof) ([]byte, error) {
	cfgCanon, err := multiformats.Canonicalize(diProofConfig(p))
	if err != nil {
		return nil, fmt.Errorf("compliance: canonicalize proof config: %w", err)
	}
	doc, err := credentialDocument(cred)
	if err != nil {
		return nil, err
	}
	docCanon, err := multiformats.Canonicalize(doc)
	if err != nil {
		return nil, fmt.Errorf("compliance: canonicalize document: %w", err)
	}
	cfgHash := sha256.Sum256(cfgCanon)
	docHash := sha256.Sum256(docCanon)
	return append(cfgHash[:], docHash[:]...), nil
}

// signDataIntegrity fills cred.Proof.ProofValue with an eddsa-jcs-2022 signature
// (multibase base58btc). cred.Proof must already carry the proof options
// (type=DataIntegrityProof, cryptosuite, created, verificationMethod,
// proofPurpose) but not yet a proofValue.
func signDataIntegrity(cred *Credential, priv ed25519.PrivateKey) error {
	data, err := diHashData(cred, cred.Proof)
	if err != nil {
		return err
	}
	cred.Proof.ProofValue = multiformats.EncodeMultibaseBase58(ed25519.Sign(priv, data))
	return nil
}

// verifyDataIntegrity verifies an eddsa-jcs-2022 proof on a credential.
func verifyDataIntegrity(cred *Credential, pub ed25519.PublicKey) error {
	sig, err := multiformats.DecodeMultibaseBase58(cred.Proof.ProofValue)
	if err != nil {
		return fmt.Errorf("compliance: proofValue decode: %w", err)
	}
	data, err := diHashData(cred, cred.Proof)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, data, sig) {
		return ErrInvalidSig
	}
	return nil
}
