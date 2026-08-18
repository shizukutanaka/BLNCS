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
	// eddsa-jcs-2022 is now the default; nothing to set.
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

// TestDefaultIsDataIntegrity proves the DEFAULT issuer emits the current W3C
// suite. A compliance product whose zero value ships a suite that is off the
// W3C standards track is itself a conformance defect, so this is the assertion
// that keeps the default honest (Axis 149 inverted it).
func TestDefaultIsDataIntegrity(t *testing.T) {
	iss, _ := NewIssuer("did:web:default.example") // LegacyProofSuite=false
	cred, _ := iss.Issue(PassportClaim{ProductID: "P1"}, 0)
	if cred.Proof.Type != "DataIntegrityProof" || cred.Proof.Cryptosuite != CryptosuiteEdDSAJCS2022 {
		t.Fatalf("default should be DataIntegrityProof/eddsa-jcs-2022: %+v", cred.Proof)
	}
	if err := Verify(cred, iss.PublicKey()); err != nil {
		t.Fatalf("default verify failed: %v", err)
	}
}

// TestLegacyProofSuiteOptIn proves the old suite is still reachable, byte-shape
// unchanged, for operators facing a verifier that accepts only it.
func TestLegacyProofSuiteOptIn(t *testing.T) {
	iss, _ := NewIssuer("did:web:legacy.example")
	iss.LegacyProofSuite = true
	cred, _ := iss.Issue(PassportClaim{ProductID: "P1"}, 0)
	if cred.Proof.Type != "Ed25519Signature2020" || cred.Proof.Cryptosuite != "" {
		t.Fatalf("opt-in should be Ed25519Signature2020 with no cryptosuite: %+v", cred.Proof)
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

// TestBatteryPassportProofMatchesSuite is the regression guard for a latent bug
// the Axis 149 default flip exposed: issueBatteryPassport mutates the subject
// after Issue has already signed, then re-signs. That re-sign hand-rolled
// ed25519 over canonicalPayload — the LEGACY construction — regardless of the
// issuer's suite, so an eddsa-jcs-2022 issuer produced a DataIntegrityProof
// credential carrying a legacy base64 proofValue: signed, returned, and
// permanently unverifiable, with no signal to the caller.
//
// Both suites must round-trip, and the mutated Annex XIII attributes must be
// covered by whichever signature is produced.
func TestBatteryPassportProofMatchesSuite(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		iss, err := NewIssuer("did:web:battery.example")
		if err != nil {
			t.Fatal(err)
		}
		iss.LegacyProofSuite = legacy

		cred, err := iss.IssueBatteryPassport(BatteryPassportClaim{
			BatteryID:                   "BAT-001",
			Category:                    BatteryCategoryEV,
			Chemistry:                   "LFP",
			CarbonFootprintKgCO2ePerKWh: 42.0,
			DueDiligenceReportURL:       "https://example.eu/dd.pdf",
			RenewableContentPct:         30,
		}, 24*time.Hour)
		if err != nil {
			t.Fatalf("legacy=%v issue: %v", legacy, err)
		}
		wantType := "DataIntegrityProof"
		if legacy {
			wantType = "Ed25519Signature2020"
		}
		if cred.Proof.Type != wantType {
			t.Errorf("legacy=%v: proof type = %q want %q", legacy, cred.Proof.Type, wantType)
		}
		if err := Verify(cred, iss.PublicKey()); err != nil {
			t.Fatalf("legacy=%v: battery passport must verify under its own suite: %v", legacy, err)
		}
		// The post-Issue mutation must be inside the signature, not outside it.
		if cred.Subject.Attrs["chemistry"] != "LFP" {
			t.Fatalf("legacy=%v: Annex XIII attrs missing: %v", legacy, cred.Subject.Attrs)
		}
		cred.Subject.Attrs["chemistry"] = "NMC"
		if err := Verify(cred, iss.PublicKey()); err == nil {
			t.Errorf("legacy=%v: tampering with a signed attribute must be detected", legacy)
		}
	}
}
