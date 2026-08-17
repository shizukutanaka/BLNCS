package openid4vci

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
)

// ============================================================================
// Axis 146: PKCE (RFC 7636)
//
// Proof Key for Code Exchange binds an authorization code to the client that
// requested it. Without it, an attacker who intercepts the code — from a
// redirect URI, a browser log, a malicious app registered for the same custom
// scheme — can redeem it themselves. OAuth 2.1 makes PKCE mandatory for every
// authorization-code request, and OpenID4VCI inherits that: a wallet is a public
// client with no client secret, so PKCE is the only thing binding the code.
//
// Only S256 is implemented. RFC 7636 §4.2 permits "plain", but it provides no
// protection whatsoever when the attacker can observe the authorization request
// (which is the threat model), and OAuth 2.1 forbids it. Accepting "plain" would
// also create a downgrade: an attacker who can modify the authorization request
// could switch the method to "plain" and set the challenge to a verifier of
// their choosing. So "plain" is rejected rather than supported.
//
// The S256 transformation is anchored on the fully worked example in RFC 7636
// Appendix B (see pkce_test.go), so the encoding is known to be interoperable
// rather than merely self-consistent.
// ============================================================================

// MethodS256 is the only code_challenge_method this issuer accepts.
const MethodS256 = "S256"

// RFC 7636 §4.1: the code verifier is 43–128 characters from the unreserved
// set. The lower bound is what gives it at least 256 bits of entropy when
// generated correctly; the upper bound keeps the request bounded.
const (
	minVerifierLen = 43
	maxVerifierLen = 128
)

var (
	// ErrPKCERequired is returned when an authorization request omits PKCE.
	ErrPKCERequired = errors.New("vci: code_challenge is required (PKCE, RFC 7636)")
	// ErrPKCEMethodUnsupported is returned for any code_challenge_method other
	// than S256 — including "plain", which OAuth 2.1 forbids.
	ErrPKCEMethodUnsupported = errors.New("vci: only code_challenge_method=S256 is supported")
	// ErrPKCEVerifierInvalid is returned when a code_verifier is absent, is
	// outside the length range, or uses characters outside the unreserved set.
	ErrPKCEVerifierInvalid = errors.New("vci: code_verifier is malformed")
	// ErrPKCEMismatch is returned when the verifier does not transform to the
	// challenge bound at authorization time. Deliberately indistinguishable from
	// a bad code at the token endpoint, so it is not an oracle.
	ErrPKCEMismatch = errors.New("vci: code_verifier does not match code_challenge")
	// ErrPKCEChallengeInvalid is returned when a supplied code_challenge is not a
	// plausible S256 challenge (43 base64url characters, i.e. 32 octets).
	ErrPKCEChallengeInvalid = errors.New("vci: code_challenge is malformed")
)

// S256Challenge computes the RFC 7636 §4.2 S256 transformation:
//
//	BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
//
// The digest is over the verifier's ASCII octets exactly as transmitted, and the
// encoding is base64url WITHOUT padding (§3 "Notation").
func S256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ValidateCodeVerifier enforces RFC 7636 §4.1's ABNF:
//
//	code-verifier = 43*128unreserved
//	unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
//
// A verifier outside this set is rejected rather than hashed: accepting
// arbitrary bytes would let a client use a low-entropy or attacker-chosen
// verifier and still satisfy the S256 check.
func ValidateCodeVerifier(verifier string) error {
	if len(verifier) < minVerifierLen || len(verifier) > maxVerifierLen {
		return fmt.Errorf("%w: length %d outside %d..%d", ErrPKCEVerifierInvalid, len(verifier), minVerifierLen, maxVerifierLen)
	}
	for i := 0; i < len(verifier); i++ {
		if !isUnreserved(verifier[i]) {
			return fmt.Errorf("%w: character %q not in the unreserved set", ErrPKCEVerifierInvalid, verifier[i])
		}
	}
	return nil
}

// ValidateCodeChallenge checks a challenge is a well-formed S256 challenge: the
// base64url (unpadded) encoding of a 32-octet digest, which is always 43
// characters. Rejecting anything else stops a client binding a code to a
// challenge no verifier can ever produce, or to a truncated one.
func ValidateCodeChallenge(challenge, method string) error {
	if challenge == "" {
		return ErrPKCERequired
	}
	// An absent method defaults to "plain" per RFC 7636 §4.3 — which this issuer
	// does not accept, so an absent method is an error rather than a default.
	if method != MethodS256 {
		return fmt.Errorf("%w: got %q", ErrPKCEMethodUnsupported, method)
	}
	raw, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil || len(raw) != sha256.Size {
		return fmt.Errorf("%w: not %d base64url-encoded octets", ErrPKCEChallengeInvalid, sha256.Size)
	}
	return nil
}

// VerifyPKCE checks a code_verifier against the challenge bound at authorization
// time. The comparison is constant-time so response timing does not leak how
// much of a guessed verifier was correct.
func VerifyPKCE(verifier, challenge string) error {
	if err := ValidateCodeVerifier(verifier); err != nil {
		return err
	}
	got := S256Challenge(verifier)
	if subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) != 1 {
		return ErrPKCEMismatch
	}
	return nil
}

// GenerateCodeVerifier produces a wallet-side code verifier with 256 bits of
// entropy, rendered as 43 unreserved characters (base64url of 32 octets, which
// is entirely within the unreserved set).
func GenerateCodeVerifier() (string, error) {
	v, err := randomB64(32)
	if err != nil {
		return "", err
	}
	if err := ValidateCodeVerifier(v); err != nil {
		// Unreachable: base64url of 32 octets is 43 unreserved characters. Checked
		// anyway so a future change to randomB64 cannot silently emit a verifier
		// the issuer would reject.
		return "", err
	}
	return v, nil
}

func isUnreserved(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '-', c == '.', c == '_', c == '~':
		return true
	}
	return false
}
