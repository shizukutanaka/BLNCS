package openid4vp

import (
	"encoding/base64"
	"errors"
	"fmt"

	"blrcs/compliance"
)

// ============================================================================
// Axis 147: DCQL trusted_authorities (OpenID4VP 1.0 §6.1.1)
//
// A DCQL query could say WHAT claims it wanted and from which credential type,
// but not WHOSE credential it would accept. `trusted_authorities` is the
// constraint that says "only a credential whose issuer chains to one of these
// trust anchors" — the difference between "any Battery Passport" and "a Battery
// Passport from an issuer on the EU trusted list". Without it a verifier's only
// issuer control is its own TrustedIssuers map, which the WALLET cannot see, so
// a wallet has no way to pick a credential the verifier will actually accept and
// the user is walked through a disclosure that is then refused.
//
// §6.1.1 defines three authority types, and BLRCS accepts exactly those:
//
//	aki               — the issuing key's X.509 AuthorityKeyIdentifier, base64url
//	etsi_tl           — the URI of an ETSI Trusted List the issuer appears on
//	openid_federation — the Entity Identifier of an OpenID Federation trust anchor
//
// Matching semantics are OR at both levels: a credential satisfies the query if
// it matches ANY entry, and an entry matches if the credential matches ANY of its
// `values` (§6.1.1: "the credential MUST match at least one").
//
// # Why evaluation is delegated, and why it fails closed
//
// Deciding whether a credential actually chains to one of these anchors needs
// evidence this package does not hold and cannot fetch: an X.509 chain for `aki`
// (BLRCS issues bare-key credentials today — see the mdoc PKI gap), a fetched and
// signature-checked ETSI Trusted List for `etsi_tl`, a resolved federation chain
// for `openid_federation`. Each involves network I/O and its own trust
// configuration, and this verifier core is deliberately network-free.
//
// So evaluation goes through Verifier.TrustedAuthorityChecker. If a query
// declares trusted_authorities and no checker is configured, the presentation is
// REFUSED rather than accepted. Accepting would be the worst outcome available:
// the verifier would have advertised an issuer restriction to the wallet, and
// then honoured none of it — a restriction that silently does nothing is more
// dangerous than one that was never claimed. This mirrors Axis 138's handling of
// the mdoc SessionTranscript.
// ============================================================================

// Trusted authority types registered by OpenID4VP 1.0 §6.1.1.
const (
	// AuthorityTypeAKI matches on the X.509 AuthorityKeyIdentifier of the key
	// that signed the credential. Values are base64url-encoded (no padding).
	AuthorityTypeAKI = "aki"
	// AuthorityTypeETSITrustedList matches issuers present on the ETSI Trusted
	// List identified by the value URI.
	AuthorityTypeETSITrustedList = "etsi_tl"
	// AuthorityTypeOpenIDFederation matches issuers whose federation chain
	// terminates at the trust anchor Entity Identifier given as the value.
	AuthorityTypeOpenIDFederation = "openid_federation"
)

var (
	// ErrTrustedAuthorityInvalid is returned by Validate for a structurally
	// invalid trusted_authorities entry (unknown type, empty values, or an `aki`
	// value that is not base64url).
	ErrTrustedAuthorityInvalid = errors.New("openid4vp: invalid trusted_authorities entry")
	// ErrTrustedAuthorityUnverifiable is returned when a query constrains issuers
	// but the verifier has no TrustedAuthorityChecker to evaluate the constraint.
	// Fail-closed: an unenforced issuer restriction is worse than none, because
	// the wallet was told the restriction applied.
	ErrTrustedAuthorityUnverifiable = errors.New("openid4vp: query declares trusted_authorities but no TrustedAuthorityChecker is configured")
	// ErrTrustedAuthorityUnsatisfied is returned when the presented credential's
	// issuer does not match any declared trust anchor.
	ErrTrustedAuthorityUnsatisfied = errors.New("openid4vp: credential issuer does not chain to any trusted authority")
)

// TrustedAuthority is one entry of a §6.1.1 trusted_authorities array.
type TrustedAuthority struct {
	// Type is one of the registered authority types above.
	Type string `json:"type"`
	// Values are the acceptable identifiers for this type. A credential matches
	// this entry if it matches ANY value.
	Values []string `json:"values"`
}

// TrustedAuthorityChecker decides whether a presented credential's issuer
// satisfies one trusted-authority entry. It is called once per entry, in query
// order, until one returns true.
//
// Implementations do the part this package deliberately leaves out: resolve an
// X.509 chain and compare the AuthorityKeyIdentifier, consult a cached and
// signature-verified ETSI Trusted List, or walk an OpenID Federation chain. They
// may perform network I/O; the verifier core does not.
//
// Returning an error aborts evaluation and refuses the presentation, so a
// transient failure (an unreachable trusted list) fails closed rather than
// silently downgrading to "no issuer restriction".
type TrustedAuthorityChecker func(authority TrustedAuthority, vc *compliance.VerifiedClaims) (bool, error)

// validateTrustedAuthorities checks the structure of a trusted_authorities array
// at query-validation time, so a malformed constraint is rejected when the
// verifier builds its request rather than silently failing to match later.
func validateTrustedAuthorities(credentialID string, authorities []TrustedAuthority) error {
	for i, a := range authorities {
		switch a.Type {
		case AuthorityTypeAKI, AuthorityTypeETSITrustedList, AuthorityTypeOpenIDFederation:
		default:
			return fmt.Errorf("%w: credential %q entry %d: unknown type %q", ErrTrustedAuthorityInvalid, credentialID, i, a.Type)
		}
		if len(a.Values) == 0 {
			return fmt.Errorf("%w: credential %q entry %d: values must be non-empty", ErrTrustedAuthorityInvalid, credentialID, i)
		}
		for j, v := range a.Values {
			if v == "" {
				return fmt.Errorf("%w: credential %q entry %d value %d: empty", ErrTrustedAuthorityInvalid, credentialID, i, j)
			}
			// An `aki` value is a base64url-encoded key identifier (§6.1.1). A
			// value that cannot decode can never match anything, so a query
			// carrying one is a configuration error, not a stricter filter.
			if a.Type == AuthorityTypeAKI {
				if _, err := base64.RawURLEncoding.DecodeString(v); err != nil {
					return fmt.Errorf("%w: credential %q entry %d value %d: aki must be base64url (unpadded)", ErrTrustedAuthorityInvalid, credentialID, i, j)
				}
			}
		}
	}
	return nil
}

// checkTrustedAuthorities evaluates a credential query's issuer restriction
// against the presented credential.
//
// A query with no trusted_authorities imposes no restriction and returns nil.
// Otherwise a checker MUST be configured, and at least one entry must match.
func checkTrustedAuthorities(cq *CredentialQuery, vc *compliance.VerifiedClaims, checker TrustedAuthorityChecker) error {
	if len(cq.TrustedAuthorities) == 0 {
		return nil
	}
	if checker == nil {
		return fmt.Errorf("%w (credential query %q)", ErrTrustedAuthorityUnverifiable, cq.ID)
	}
	for _, a := range cq.TrustedAuthorities {
		ok, err := checker(a, vc)
		if err != nil {
			// A checker that cannot reach its trust list must not degrade into
			// "unrestricted": surface the failure and refuse.
			return fmt.Errorf("openid4vp: trusted authority check failed for credential query %q: %w", cq.ID, err)
		}
		if ok {
			return nil
		}
	}
	return fmt.Errorf("%w (credential query %q, issuer %q)", ErrTrustedAuthorityUnsatisfied, cq.ID, vc.Issuer)
}
