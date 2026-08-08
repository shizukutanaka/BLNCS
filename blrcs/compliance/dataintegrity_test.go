package compliance

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// Axis 133: eddsa-jcs-2022 Data Integrity cryptosuite
// ============================================================================

func diIssuer(t *testing.T) *Issuer {
	t.Helper()
	iss, err := NewIssuer("did:web:factory.di.example")
	if err != nil {
		t.Fatal(err)
	}
	iss.DataIntegrity = true
	return iss
}

func TestDataIntegrityIssueVerify(t *testing.T) {
	iss := diIssuer(t)
	cred, err := iss.Issue(PassportClaim{ProductID: "P1", CarbonKgCO2e: 2.4}, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if cred.Proof.Type != "DataIntegrityProof" || cred.Proof.Cryptosuite != CryptosuiteEdDSAJCS2022 {
		t.Fatalf("wrong proof suite: type=%s cryptosuite=%s", cred.Proof.Type, cred.Proof.Cryptosuite)
	}
	// eddsa-jcs-2022 proofValue is multibase base58btc — "z"-prefixed, not base64.
	if !strings.HasPrefix(cred.Proof.ProofValue, "z") {
		t.Errorf("proofValue should be multibase base58btc (z-prefixed): %q", cred.Proof.ProofValue)
	}
	if err := Verify(cred, iss.PublicKey()); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
}

func TestDataIntegrityTamperDetection(t *testing.T) {
	iss := diIssuer(t)
	cred, _ := iss.Issue(PassportClaim{ProductID: "P1", CarbonKgCO2e: 1.0}, 0)
	cred.Subject.CarbonKgCO2e = 0.1 // tamper
	if err := Verify(cred, iss.PublicKey()); err != ErrInvalidSig {
		t.Fatalf("tamper should fail with ErrInvalidSig, got: %v", err)
	}
}

// TestDataIntegrityProofConfigBound proves the proof options are bound: tampering
// the verificationMethod (part of the hashed proof config) breaks verification.
func TestDataIntegrityProofConfigBound(t *testing.T) {
	iss := diIssuer(t)
	cred, _ := iss.Issue(PassportClaim{ProductID: "P1"}, 0)
	cred.Proof.VerificationMethod = "did:web:evil.example#key-1"
	if err := Verify(cred, iss.PublicKey()); err != ErrInvalidSig {
		t.Fatalf("tampered verificationMethod should fail, got: %v", err)
	}
}

func TestDataIntegrityWrongKey(t *testing.T) {
	iss := diIssuer(t)
	other, _ := NewIssuer("did:web:other.example")
	cred, _ := iss.Issue(PassportClaim{ProductID: "P1"}, 0)
	if err := Verify(cred, other.PublicKey()); err != ErrInvalidSig {
		t.Fatalf("wrong key should fail, got: %v", err)
	}
}

func TestDataIntegrityWithStatus(t *testing.T) {
	iss := diIssuer(t)
	cred, err := iss.IssueWithStatus(PassportClaim{ProductID: "P1"}, 0,
		"https://issuer.example/status/1", 7, "revocation")
	if err != nil {
		t.Fatal(err)
	}
	if cred.Proof.Cryptosuite != CryptosuiteEdDSAJCS2022 {
		t.Errorf("status credential should also use eddsa-jcs-2022")
	}
	if err := Verify(cred, iss.PublicKey()); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	// credentialStatus is part of the signed document — tampering it must fail.
	cred.Status.StatusListIndex = "999"
	if err := Verify(cred, iss.PublicKey()); err != ErrInvalidSig {
		t.Fatalf("tampered status should fail, got %v", err)
	}
}

// TestDefaultStillEd25519Signature2020 proves the default issuer path is
// unchanged (byte-compatible with the legacy suite) — a default-issued
// credential carries no cryptosuite and a base64 proofValue.
func TestDefaultStillEd25519Signature2020(t *testing.T) {
	iss, _ := NewIssuer("did:web:default.example") // DataIntegrity=false
	cred, _ := iss.Issue(PassportClaim{ProductID: "P1"}, 0)
	if cred.Proof.Type != "Ed25519Signature2020" || cred.Proof.Cryptosuite != "" {
		t.Fatalf("default should be Ed25519Signature2020 with no cryptosuite: %+v", cred.Proof)
	}
	// Decode rather than sniff the first character: base64-std output legitimately
	// begins with "z" roughly 1 time in 64, so a prefix check here is flaky.
	// A base64-std Ed25519 signature decodes to exactly 64 bytes; a multibase
	// base58btc proofValue does not decode as base64 at all.
	sig, err := base64.StdEncoding.DecodeString(cred.Proof.ProofValue)
	if err != nil || len(sig) != ed25519.SignatureSize {
		t.Errorf("default proofValue should be base64-std over a 64-byte signature, got %q (err=%v)",
			cred.Proof.ProofValue, err)
	}
	if err := Verify(cred, iss.PublicKey()); err != nil {
		t.Fatalf("default verify failed: %v", err)
	}
}

// TestDataIntegrityCrossSuiteRejected proves a DI credential cannot be verified
// as if it were Ed25519Signature2020 and vice versa (the dispatch is real).
func TestDataIntegrityCrossSuiteRejected(t *testing.T) {
	di := diIssuer(t)
	cred, _ := di.Issue(PassportClaim{ProductID: "P1"}, 0)
	// Force the verifier down the legacy branch by stripping the suite markers.
	cred.Proof.Type = "Ed25519Signature2020"
	cred.Proof.Cryptosuite = ""
	if err := Verify(cred, di.PublicKey()); err == nil {
		t.Fatal("a DI proof verified under the legacy branch should fail")
	}
}
