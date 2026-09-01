package openid4vci

import (
	"errors"
	"strings"
	"testing"
)

// TestS256_RFC7636AppendixB is the conformance anchor. RFC 7636 Appendix B
// publishes a complete worked example of the S256 transformation, including the
// intermediate SHA-256 octets. Reproducing its published challenge byte-for-byte
// proves the digest input and the unpadded base64url encoding are both right.
func TestS256_RFC7636AppendixB(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const wantChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	if got := S256Challenge(verifier); got != wantChallenge {
		t.Fatalf("S256 disagrees with RFC 7636 Appendix B:\n got  %s\n want %s", got, wantChallenge)
	}
	// The Appendix B verifier must itself satisfy the §4.1 ABNF.
	if err := ValidateCodeVerifier(verifier); err != nil {
		t.Errorf("Appendix B verifier should be valid: %v", err)
	}
	if err := VerifyPKCE(verifier, wantChallenge); err != nil {
		t.Errorf("Appendix B pair should verify: %v", err)
	}
}

func TestVerifyPKCEMismatch(t *testing.T) {
	v, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatal(err)
	}
	other, _ := GenerateCodeVerifier()
	if err := VerifyPKCE(v, S256Challenge(other)); !errors.Is(err, ErrPKCEMismatch) {
		t.Fatalf("want ErrPKCEMismatch, got %v", err)
	}
	if err := VerifyPKCE(v, S256Challenge(v)); err != nil {
		t.Fatalf("matching pair must verify: %v", err)
	}
}

// TestCodeVerifierABNF enforces RFC 7636 §4.1: 43-128 unreserved characters.
func TestCodeVerifierABNF(t *testing.T) {
	valid := strings.Repeat("a", 43)
	if err := ValidateCodeVerifier(valid); err != nil {
		t.Errorf("43 chars should be valid: %v", err)
	}
	if err := ValidateCodeVerifier(strings.Repeat("a", 128)); err != nil {
		t.Errorf("128 chars should be valid: %v", err)
	}
	// Every unreserved character must be accepted.
	if err := ValidateCodeVerifier(strings.Repeat("aA0-._~", 7)); err != nil {
		t.Errorf("unreserved set should be accepted: %v", err)
	}
	for name, bad := range map[string]string{
		"too short": strings.Repeat("a", 42),
		"too long":  strings.Repeat("a", 129),
		"empty":     "",
		"plus":      strings.Repeat("a", 42) + "+",
		"slash":     strings.Repeat("a", 42) + "/",
		"equals":    strings.Repeat("a", 42) + "=",
		"space":     strings.Repeat("a", 42) + " ",
		"non-ascii": strings.Repeat("a", 42) + "é",
		"null byte": strings.Repeat("a", 42) + "\x00",
	} {
		if err := ValidateCodeVerifier(bad); !errors.Is(err, ErrPKCEVerifierInvalid) {
			t.Errorf("%s: want ErrPKCEVerifierInvalid, got %v", name, err)
		}
	}
}

// TestPlainMethodRejected: RFC 7636 defines "plain" but it offers no protection
// against the threat PKCE exists for, and OAuth 2.1 forbids it. Accepting it
// would also allow a downgrade attack on the authorization request.
func TestPlainMethodRejected(t *testing.T) {
	challenge := S256Challenge("x")
	for _, method := range []string{"plain", "", "s256", "S512", "PLAIN"} {
		if err := ValidateCodeChallenge(challenge, method); !errors.Is(err, ErrPKCEMethodUnsupported) {
			t.Errorf("method %q must be rejected, got %v", method, err)
		}
	}
	if err := ValidateCodeChallenge(challenge, MethodS256); err != nil {
		t.Errorf("S256 must be accepted: %v", err)
	}
}

// TestChallengeShapeValidated stops a client binding a code to a challenge no
// verifier could ever produce (truncated, wrong alphabet, wrong length).
func TestChallengeShapeValidated(t *testing.T) {
	if err := ValidateCodeChallenge("", MethodS256); !errors.Is(err, ErrPKCERequired) {
		t.Errorf("an absent challenge must be ErrPKCERequired, got %v", err)
	}
	for name, bad := range map[string]string{
		"truncated":     "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw",
		"too long":      S256Challenge("x") + "AA",
		"padded base64": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM=",
		"not base64url": strings.Repeat("!", 43),
	} {
		if err := ValidateCodeChallenge(bad, MethodS256); !errors.Is(err, ErrPKCEChallengeInvalid) {
			t.Errorf("%s: want ErrPKCEChallengeInvalid, got %v", name, err)
		}
	}
}

// TestGeneratedVerifierIsStrong: 43 chars, unreserved, and distinct per call.
func TestGeneratedVerifierIsStrong(t *testing.T) {
	seen := make(map[string]bool, 64)
	for i := 0; i < 64; i++ {
		v, err := GenerateCodeVerifier()
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateCodeVerifier(v); err != nil {
			t.Fatalf("generated verifier must satisfy the ABNF: %v", err)
		}
		if len(v) != 43 {
			t.Fatalf("want 43 chars (256 bits), got %d", len(v))
		}
		if seen[v] {
			t.Fatal("generated verifiers must not repeat")
		}
		seen[v] = true
	}
}
