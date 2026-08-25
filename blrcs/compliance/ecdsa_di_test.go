package compliance

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"blrcs/ecdsakey"
	"blrcs/multiformats"
)

// ============================================================================
// Axis 153: ecdsa-jcs-2019 W3C VC proofs (W3C ECDSA Cryptosuites v1.0)
//
// Before this axis, ES256Issuer could issue SD-JWT VCs but not W3C VCs at all.
// The W3C VC was the one format a P-256-only EUDI ecosystem could not consume,
// even after Axes 135-148 made SD-JWT, KB-JWT and mdoc P-256 capable.
//
// The tests that carry the weight are the cross-suite ones: a suite label must
// actually select the verification rules, not merely decorate the proof.
// ============================================================================

func es256VCIssuer(t *testing.T) *ES256Issuer {
	t.Helper()
	iss, err := NewES256Issuer("did:web:factory.p256.example")
	if err != nil {
		t.Fatal(err)
	}
	return iss
}

func TestECDSADataIntegrityRoundTrip(t *testing.T) {
	iss := es256VCIssuer(t)
	cred, err := iss.Issue(PassportClaim{ProductID: "P-256-001", CarbonKgCO2e: 48.5}, 24*time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if cred.Proof.Type != "DataIntegrityProof" || cred.Proof.Cryptosuite != CryptosuiteECDSAJCS2019 {
		t.Fatalf("proof should be DataIntegrityProof/ecdsa-jcs-2019: %+v", cred.Proof)
	}
	if cred.Proof.ProofPurpose != "assertionMethod" || cred.Proof.VerificationMethod != iss.ID+"#key-1" {
		t.Errorf("proof metadata wrong: %+v", cred.Proof)
	}
	if err := Verify(cred, iss.PublicKey()); err != nil {
		t.Fatalf("ES256 W3C VC must verify: %v", err)
	}
	// proofValue is multibase base58btc over a raw 64-byte R||S signature —
	// never ASN.1 DER (RFC 7518 §3.4 / the codebase-wide convention).
	sig, err := multiformats.DecodeMultibaseBase58(cred.Proof.ProofValue)
	if err != nil {
		t.Fatalf("proofValue must be multibase base58btc: %v", err)
	}
	if len(sig) != ecdsakey.ES256SignatureSize {
		t.Errorf("signature should be %d raw bytes, got %d", ecdsakey.ES256SignatureSize, len(sig))
	}
}

func TestECDSADataIntegrityTamperDetected(t *testing.T) {
	iss := es256VCIssuer(t)
	cred, err := iss.Issue(PassportClaim{ProductID: "P1", CarbonKgCO2e: 1.0}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Tamper with a signed claim.
	cred.Subject.CarbonKgCO2e = 999.0
	if err := Verify(cred, iss.PublicKey()); err == nil {
		t.Error("a modified claim must be detected")
	}

	// Tamper with the proof metadata (bound via the hashed proof config).
	fresh, _ := iss.Issue(PassportClaim{ProductID: "P2"}, time.Hour)
	fresh.Proof.VerificationMethod = "did:web:attacker#key-1"
	if err := Verify(fresh, iss.PublicKey()); err == nil {
		t.Error("a rewritten verificationMethod must be detected")
	}
}

func TestECDSADataIntegrityWrongKey(t *testing.T) {
	iss := es256VCIssuer(t)
	other := es256VCIssuer(t)
	cred, err := iss.Issue(PassportClaim{ProductID: "P1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(cred, other.PublicKey()); !errors.Is(err, ErrInvalidSig) {
		t.Fatalf("a different P-256 key must not verify, got %v", err)
	}
}

// TestCryptosuiteConfusionRejected is the core of this axis: the cryptosuite
// label must SELECT the verification rules. If the dispatch were cosmetic, a
// proof could be verified under rules it never claimed.
func TestCryptosuiteConfusionRejected(t *testing.T) {
	edIssuer, err := NewIssuer("did:web:factory.ed.example")
	if err != nil {
		t.Fatal(err)
	}
	p256Issuer := es256VCIssuer(t)

	// An ecdsa-jcs-2019 proof relabelled as eddsa-jcs-2022 must not verify —
	// neither with the P-256 key nor with an Ed25519 one.
	ecCred, _ := p256Issuer.Issue(PassportClaim{ProductID: "P1"}, time.Hour)
	ecCred.Proof.Cryptosuite = CryptosuiteEdDSAJCS2022
	if err := Verify(ecCred, p256Issuer.PublicKey()); err == nil {
		t.Error("an ECDSA proof relabelled eddsa-jcs-2022 must be rejected")
	}
	if err := Verify(ecCred, edIssuer.PublicKey()); err == nil {
		t.Error("an ECDSA proof must not verify under an Ed25519 key")
	}

	// And the reverse: an eddsa-jcs-2022 proof relabelled ecdsa-jcs-2019.
	edCred, err := edIssuer.Issue(PassportClaim{ProductID: "P2"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	edCred.Proof.Cryptosuite = CryptosuiteECDSAJCS2019
	if err := Verify(edCred, edIssuer.PublicKey()); err == nil {
		t.Error("an EdDSA proof relabelled ecdsa-jcs-2019 must be rejected")
	}
}

// TestWrongKeyLengthForSuite: a 32-byte Ed25519 key against the ECDSA suite is
// a KEY error, not a signature mismatch — the distinction matters for
// diagnosing a misconfigured verifier.
func TestWrongKeyLengthForSuite(t *testing.T) {
	iss := es256VCIssuer(t)
	cred, err := iss.Issue(PassportClaim{ProductID: "P1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	edPub := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	err = Verify(cred, edPub)
	if err == nil {
		t.Fatal("a 32-byte key must not verify an ecdsa-jcs-2019 proof")
	}
	if !strings.Contains(err.Error(), "verification key") {
		t.Errorf("want a key error, got %v", err)
	}
}

// TestUnknownCryptosuiteRejected: an unimplemented suite must be refused
// outright, NOT silently verified under the legacy Ed25519Signature2020 rules.
func TestUnknownCryptosuiteRejected(t *testing.T) {
	iss := es256VCIssuer(t)
	cred, err := iss.Issue(PassportClaim{ProductID: "P1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, suite := range []string{"bbs-2023", "ecdsa-rdfc-2019", "", "eddsa-rdfc-2022"} {
		cred.Proof.Cryptosuite = suite
		err := Verify(cred, iss.PublicKey())
		if err == nil {
			t.Errorf("cryptosuite %q must be rejected, not verified", suite)
			continue
		}
		if !strings.Contains(err.Error(), "unsupported cryptosuite") {
			t.Errorf("cryptosuite %q: want an explicit unsupported-suite error, got %v", suite, err)
		}
	}
}

// TestTruncatedProofValueRejected covers the length checks added to BOTH suites.
func TestTruncatedProofValueRejected(t *testing.T) {
	p256 := es256VCIssuer(t)
	ecCred, _ := p256.Issue(PassportClaim{ProductID: "P1"}, time.Hour)
	sig, _ := multiformats.DecodeMultibaseBase58(ecCred.Proof.ProofValue)
	ecCred.Proof.ProofValue = multiformats.EncodeMultibaseBase58(sig[:len(sig)-1])
	if err := Verify(ecCred, p256.PublicKey()); !errors.Is(err, ErrInvalidSig) {
		t.Errorf("a truncated ECDSA signature must be rejected, got %v", err)
	}

	edIssuer, _ := NewIssuer("did:web:ed.example")
	edCred, _ := edIssuer.Issue(PassportClaim{ProductID: "P1"}, time.Hour)
	edSig, _ := multiformats.DecodeMultibaseBase58(edCred.Proof.ProofValue)
	edCred.Proof.ProofValue = multiformats.EncodeMultibaseBase58(edSig[:len(edSig)-1])
	if err := Verify(edCred, edIssuer.PublicKey()); !errors.Is(err, ErrInvalidSig) {
		t.Errorf("a truncated EdDSA signature must be rejected, got %v", err)
	}
}

// TestECDSADataIntegrityWithStatus: the revocation entry must be inside the
// signature, like the Ed25519 path.
func TestECDSADataIntegrityWithStatus(t *testing.T) {
	iss := es256VCIssuer(t)
	cred, err := iss.IssueWithStatus(PassportClaim{ProductID: "P1"}, time.Hour,
		"https://status.example/list", 42, "revocation")
	if err != nil {
		t.Fatalf("issue with status: %v", err)
	}
	if cred.Status == nil || cred.Status.StatusListIndex != "42" {
		t.Fatalf("status entry wrong: %+v", cred.Status)
	}
	if err := Verify(cred, iss.PublicKey()); err != nil {
		t.Fatalf("status-bearing ES256 credential must verify: %v", err)
	}
	cred.Status.StatusListIndex = "43"
	if err := Verify(cred, iss.PublicKey()); err == nil {
		t.Error("tampering with the status index must be detected")
	}
}

// TestES256IssuerRejectsEmptyProductID keeps the shared builder's validation
// reachable from the new path.
func TestES256IssuerRejectsEmptyProductID(t *testing.T) {
	iss := es256VCIssuer(t)
	if _, err := iss.Issue(PassportClaim{}, time.Hour); !errors.Is(err, ErrEmptyProductID) {
		t.Errorf("want ErrEmptyProductID, got %v", err)
	}
	if _, err := iss.IssueWithStatus(PassportClaim{ProductID: "P"}, time.Hour, "", 0, "revocation"); err == nil {
		t.Error("an empty status list URL must be refused")
	}
}

// TestWrongLengthKeyDoesNotPanic is the regression guard for a defect this axis
// uncovered rather than introduced.
//
// ed25519.Verify PANICS on a public key that is not 32 bytes, and
// ed25519.PublicKey is a named []byte — so the compiler happily accepts a
// P-256 point, an empty slice, or garbage. Neither Data Integrity verification
// nor the legacy Ed25519Signature2020 path length-checked the key, so a caller
// passing the wrong key type to the public Verify API crashed the process
// instead of receiving an error. On a verifier service that is a remote panic.
//
// Every one of these must return an error, and none may panic.
func TestWrongLengthKeyDoesNotPanic(t *testing.T) {
	edIssuer, err := NewIssuer("did:web:ed.example")
	if err != nil {
		t.Fatal(err)
	}
	p256Issuer := es256VCIssuer(t)

	diCred, _ := edIssuer.Issue(PassportClaim{ProductID: "P1"}, time.Hour) // eddsa-jcs-2022
	edIssuer.LegacyProofSuite = true
	legacyCred, _ := edIssuer.Issue(PassportClaim{ProductID: "P2"}, time.Hour)
	ecCred, _ := p256Issuer.Issue(PassportClaim{ProductID: "P3"}, time.Hour)

	// Wrong for EVERY suite. (A P-256 SEC1 point is handled separately below:
	// it is the CORRECT key for ecdsa-jcs-2019, so it is only a bad key for the
	// two Ed25519 suites.)
	badKeys := map[string]ed25519.PublicKey{
		"empty":             {},
		"one byte":          {0x01},
		"31 bytes":          make([]byte, 31),
		"33 bytes":          make([]byte, 33),
		"65 bytes of zeros": make([]byte, 65),
	}
	for name, key := range badKeys {
		for credName, cred := range map[string]*Credential{
			"eddsa-jcs-2022":       diCred,
			"Ed25519Signature2020": legacyCred,
			"ecdsa-jcs-2019":       ecCred,
		} {
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						t.Errorf("%s key against %s PANICKED: %v", name, credName, rec)
					}
				}()
				if err := Verify(cred, key); err == nil {
					t.Errorf("%s key against %s must not verify", name, credName)
				}
			}()
		}
	}

	// A real P-256 point against the Ed25519 suites: the exact 65-vs-32 byte
	// mismatch that produced the original panic.
	for credName, cred := range map[string]*Credential{
		"eddsa-jcs-2022":       diCred,
		"Ed25519Signature2020": legacyCred,
	} {
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					t.Errorf("P-256 point against %s PANICKED: %v", credName, rec)
				}
			}()
			if err := Verify(cred, p256Issuer.PublicKey()); err == nil {
				t.Errorf("a P-256 point must not verify %s", credName)
			}
		}()
	}
}

// TestVerifyRangeWrongKeyLengthDoesNotPanic covers the same class in the
// range-proof verifier.
func TestVerifyRangeWrongKeyLengthDoesNotPanic(t *testing.T) {
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("VerifyRange panicked on a short key: %v", rec)
		}
	}()
	if err := VerifyRange(&RangeProof{}, ed25519.PublicKey{0x01}); err == nil {
		t.Error("a wrong-length attester key must not verify")
	}
}
