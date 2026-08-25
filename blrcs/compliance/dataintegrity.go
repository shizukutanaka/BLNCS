package compliance

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"blrcs/ecdsakey"
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

// CryptosuiteECDSAJCS2019 is the W3C ECDSA Cryptosuites v1.0 suite name for
// P-256 + JCS canonicalization. It shares the ENTIRE hashData construction with
// eddsa-jcs-2022 (see diHashData) — only the signature algorithm differs — which
// is why adding it touches no canonicalization code.
//
// This closes the last interop-relevant Ed25519-only path in the product: a
// P-256-only EUDI ecosystem could already verify every BLRCS format except the
// W3C Verifiable Credential.
const CryptosuiteECDSAJCS2019 = "ecdsa-jcs-2019"

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
	// ed25519.Verify PANICS on a wrong-length public key, and ed25519.PublicKey
	// is a named []byte so the compiler cannot prevent one arriving. A caller
	// passing e.g. a P-256 point would crash the process instead of getting an
	// error — a remote panic on a public verification API.
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("compliance: eddsa-jcs-2022 verification key: %w: want %d bytes, got %d",
			ErrInvalidSig, ed25519.PublicKeySize, len(pub))
	}
	sig, err := multiformats.DecodeMultibaseBase58(cred.Proof.ProofValue)
	if err != nil {
		return fmt.Errorf("compliance: proofValue decode: %w", err)
	}
	data, err := diHashData(cred, cred.Proof)
	if err != nil {
		return err
	}
	// Length-check before verifying. didwebvh/proof.go does this and this path
	// did not; a truncated proofValue should be a clean rejection rather than
	// relying on the primitive to notice.
	if len(sig) != ed25519.SignatureSize {
		return ErrInvalidSig
	}
	if !ed25519.Verify(pub, data, sig) {
		return ErrInvalidSig
	}
	return nil
}

// signDataIntegrityES256 is signDataIntegrity for the ecdsa-jcs-2019 suite.
//
// The 64-byte hashData is NOT a digest — it is SHA-256(JCS(cfg)) ‖
// SHA-256(JCS(doc)). Ed25519 hashes its own input; ECDSA does not, so this must
// hash the 64 bytes with SHA-256 before signing. Signatures are raw fixed-width
// R‖S (never ASN.1 DER), matching RFC 7518 §3.4 and the rest of the codebase.
func signDataIntegrityES256(cred *Credential, priv *ecdsa.PrivateKey) error {
	if priv == nil || priv.Curve != elliptic.P256() {
		return ErrNotP256
	}
	data, err := diHashData(cred, cred.Proof)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	r, sVal, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return fmt.Errorf("compliance: ecdsa sign: %w", err)
	}
	sig := make([]byte, ecdsakey.ES256SignatureSize)
	r.FillBytes(sig[:ecdsakey.P256CoordSize])
	sVal.FillBytes(sig[ecdsakey.P256CoordSize:])
	cred.Proof.ProofValue = multiformats.EncodeMultibaseBase58(sig)
	return nil
}

// verifyDataIntegrityES256 verifies an ecdsa-jcs-2019 proof. pub is an
// uncompressed SEC1 point (0x04‖X‖Y), the form ES256Issuer.PublicKey() returns.
func verifyDataIntegrityES256(cred *Credential, pub []byte) error {
	// Validate the key before touching the signature: a wrong-length or
	// off-curve key must fail as a key error, not as a signature mismatch.
	if _, err := ecdsakey.ParseP256PublicKey(pub); err != nil {
		return fmt.Errorf("compliance: ecdsa-jcs-2019 verification key: %w", err)
	}
	sig, err := multiformats.DecodeMultibaseBase58(cred.Proof.ProofValue)
	if err != nil {
		return fmt.Errorf("compliance: proofValue decode: %w", err)
	}
	if len(sig) != ecdsakey.ES256SignatureSize {
		return ErrInvalidSig
	}
	data, err := diHashData(cred, cred.Proof)
	if err != nil {
		return err
	}
	// VerifyES256 applies SHA-256 internally, mirroring the sign path.
	if !ecdsakey.VerifyES256(pub, data, sig) {
		return ErrInvalidSig
	}
	return nil
}
