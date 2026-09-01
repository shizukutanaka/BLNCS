package mdoc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha1" //nolint:gosec // AKI key identifiers are defined as SHA-1 by RFC 5280 §4.2.1.2; not used as a security hash.
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"blrcs/cbor"
	"blrcs/ecdsakey"
)

// ============================================================================
// Axis 148: mdoc issuer PKI — x5chain and IACA→DSC validation
//
// mdoc issuance was bare-key: Verify took an issuer public key the caller
// already had to know and trust. Every real mdoc ecosystem is X.509 instead.
// ISO/IEC 18013-5 Annex B defines a two-tier PKI — an IACA root per issuing
// authority, and short-lived Document Signer Certificates (DSCs) issued under it
// — and the DSC travels WITH the credential in the COSE `x5chain` header
// (RFC 9360 label 33), so a verifier that holds only the IACA roots can verify a
// document from an issuer it has never seen before. Without it, BLRCS could not
// consume a real mDL, and its own mdocs could not be consumed by one.
//
// # What this adds
//
//	Issue      — attaches the DSC (and any intermediates) as x5chain
//	VerifyChain — validates the chain to caller-configured IACA roots, then
//	              verifies issuerAuth with the key from the validated leaf
//
// # The property that matters
//
// The embedded chain is EVIDENCE, never authority. An attacker can put any
// certificate they like in x5chain, including a self-signed one for a key they
// control. So the leaf's key is used only after the chain validates to a root
// the VERIFIER configured, and the signature is then checked against that
// validated leaf's key — never against a key taken from the document. A
// verifier with no configured roots refuses rather than falling back to trusting
// the embedded chain.
//
// # Deliberately out of scope
//
// VICAL (ISO/IEC 18013-7 / AAMVA) is a separately signed trust-list format for
// distributing IACA roots between ecosystems. It is a distribution mechanism for
// the roots this file consumes, not a different validation rule, and it needs
// its own signed-list parser and freshness policy. Roots are supplied directly
// here; VICAL remains open.
// ============================================================================

// HeaderX5Chain is the COSE header label carrying an X.509 certificate chain
// (RFC 9360 §2). The value is a single certificate as a bstr, or an array of
// bstr for a chain ordered leaf-first.
const HeaderX5Chain = 33

var (
	// ErrNoTrustAnchors is returned when chain verification is requested but the
	// caller configured no IACA roots. Fail-closed: validating against the
	// document's own embedded chain would authenticate nothing.
	ErrNoTrustAnchors = errors.New("mdoc: no IACA trust anchors configured")
	// ErrX5ChainMissing is returned when chain verification is requested but the
	// document carries no x5chain header.
	ErrX5ChainMissing = errors.New("mdoc: issuerAuth carries no x5chain")
	// ErrX5ChainMalformed is returned when the x5chain header is not a bstr or an
	// array of bstr, or a certificate does not parse.
	ErrX5ChainMalformed = errors.New("mdoc: x5chain is malformed")
	// ErrChainUntrusted is returned when the chain does not validate to any
	// configured IACA root.
	ErrChainUntrusted = errors.New("mdoc: certificate chain does not validate to a configured IACA root")
	// ErrDSCKeyMismatch is returned when issuerAuth does not verify under the
	// validated leaf certificate's public key. This is the check that stops an
	// attacker attaching a legitimate DSC to a document signed by a different key.
	ErrDSCKeyMismatch = errors.New("mdoc: issuerAuth was not signed by the key in the document signer certificate")
	// ErrDSCUnsupportedKey is returned for a DSC whose public key is neither
	// Ed25519 nor ECDSA/P-256, the two algorithms this package signs with.
	ErrDSCUnsupportedKey = errors.New("mdoc: document signer certificate key type is not supported")
)

// ChainVerifyOptions configures IACA→DSC validation.
type ChainVerifyOptions struct {
	// Roots are the IACA trust anchors. REQUIRED: with none configured,
	// VerifyChain refuses rather than trusting the embedded chain.
	Roots *x509.CertPool
	// Intermediates may hold additional CA certificates known to the verifier.
	// Intermediates found in x5chain are added to this set automatically.
	Intermediates *x509.CertPool
	// Now is the validation time. Zero means time.Now(). ISO 18013-5 Annex B
	// requires the DSC to be valid at signing time; a verifier checking a stored
	// document may need a historical instant rather than the wall clock.
	Now time.Time
	// AllowedAlgs optionally pins the acceptable COSE algorithms for issuerAuth
	// (downgrade defence), matching VerifyWithAlgs.
	AllowedAlgs []int
}

// VerifyChain verifies an mdoc IssuerSigned structure using the certificate
// chain embedded in its issuerAuth, validated against caller-configured IACA
// roots — the way a real mdoc verifier works, as opposed to Verify, which
// requires the caller to already hold the exact issuer key.
//
// It returns the verified document along with the validated chain, so a caller
// can apply its own additional policy (naming constraints, a specific issuing
// authority) to certificates that have already been cryptographically anchored.
func VerifyChain(issuerSigned []byte, opts ChainVerifyOptions) (*VerifiedDoc, []*x509.Certificate, error) {
	if opts.Roots == nil {
		return nil, nil, ErrNoTrustAnchors
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	chain, err := extractX5Chain(issuerSigned)
	if err != nil {
		return nil, nil, err
	}
	leaf := chain[0]

	// Build the intermediate pool from the caller's set plus anything the
	// document supplied. Intermediates from the document are safe to consider
	// because they still have to chain to a configured ROOT to be of any use.
	inter := x509.NewCertPool()
	if opts.Intermediates != nil {
		inter = opts.Intermediates.Clone()
	}
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}

	verified, err := leaf.Verify(x509.VerifyOptions{
		Roots:         opts.Roots,
		Intermediates: inter,
		CurrentTime:   now,
		// ISO 18013-5 Annex B DSCs carry the id-kp-... document-signing EKU
		// rather than a TLS EKU, and Go's default is ExtKeyUsageServerAuth,
		// which would reject every conforming DSC. Any EKU is accepted here and
		// the caller applies its own EKU policy to the returned chain.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrChainUntrusted, err)
	}

	// Verify issuerAuth under the VALIDATED leaf's key — not under any key taken
	// from the document. Without this the chain would be decorative: an attacker
	// could attach a genuine DSC to a document signed with their own key.
	doc, err := verifyWithCertKey(issuerSigned, leaf, now, opts.AllowedAlgs)
	if err != nil {
		return nil, nil, err
	}
	return doc, verified[0], nil
}

// verifyWithCertKey verifies issuerAuth using the certificate's public key. The
// COSE algorithm registry dispatches on the signed `alg` header, so both key
// types go through one path; only the key encoding differs (raw Ed25519 bytes
// versus an uncompressed SEC1 point).
func verifyWithCertKey(issuerSigned []byte, leaf *x509.Certificate, now time.Time, allowedAlgs []int) (*VerifiedDoc, error) {
	var pubBytes []byte
	switch pub := leaf.PublicKey.(type) {
	case ed25519.PublicKey:
		pubBytes = pub
	case *ecdsa.PublicKey:
		sec1, err := ecdsakey.MarshalP256PublicKey(pub)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrDSCUnsupportedKey, err)
		}
		pubBytes = sec1
	default:
		return nil, fmt.Errorf("%w: %T", ErrDSCUnsupportedKey, leaf.PublicKey)
	}
	doc, err := VerifyWithAlgs(issuerSigned, pubBytes, now, allowedAlgs)
	if err != nil {
		// A chain that validated but a signature that does not verify under its
		// leaf is the attack this whole file exists to stop: a genuine DSC
		// attached to a document signed by some other key.
		if errors.Is(err, ErrIssuerAuth) {
			return nil, ErrDSCKeyMismatch
		}
		return nil, err
	}
	return doc, nil
}

// extractX5Chain pulls the certificate chain out of an issuerAuth COSE_Sign1.
//
// RFC 9360 §2: a single certificate is encoded as a bstr; two or more as an
// array of bstr ordered leaf-first. Both forms are accepted; anything else is
// malformed rather than ignored, since silently proceeding without a chain would
// turn a chain-verifying call into a bare-key one.
func extractX5Chain(issuerSigned []byte) ([]*x509.Certificate, error) {
	hdr, err := issuerAuthHeaders(issuerSigned)
	if err != nil {
		return nil, err
	}
	raw, present := hdr[HeaderX5Chain]
	if !present {
		return nil, ErrX5ChainMissing
	}
	var derList [][]byte
	switch v := raw.(type) {
	case []byte:
		derList = [][]byte{v}
	case []any:
		if len(v) == 0 {
			return nil, fmt.Errorf("%w: empty chain array", ErrX5ChainMalformed)
		}
		for _, el := range v {
			der, ok := el.([]byte)
			if !ok {
				return nil, fmt.Errorf("%w: chain element is not a byte string", ErrX5ChainMalformed)
			}
			derList = append(derList, der)
		}
	default:
		return nil, fmt.Errorf("%w: header is %T, want bstr or array of bstr", ErrX5ChainMalformed, raw)
	}
	certs := make([]*x509.Certificate, 0, len(derList))
	for i, der := range derList {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%w: certificate %d: %v", ErrX5ChainMalformed, i, err)
		}
		certs = append(certs, c)
	}
	return certs, nil
}

// issuerAuthHeaders returns the merged protected+unprotected headers of an
// mdoc's issuerAuth. x5chain may legitimately appear in either (RFC 9360 §2:
// it is not integrity-critical, because the chain is validated to a configured
// root regardless of how it arrived).
func issuerAuthHeaders(issuerSigned []byte) (cbor.Header, error) {
	top, err := cbor.Unmarshal(issuerSigned)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	topMap, ok := top.(map[any]any)
	if !ok {
		return nil, ErrMalformed
	}
	rawAuth, ok := topMap[isIssuerAuth]
	if !ok {
		return nil, fmt.Errorf("%w: missing issuerAuth", ErrMalformed)
	}
	authBytes, err := cbor.Marshal(rawAuth)
	if err != nil {
		return nil, fmt.Errorf("%w: re-encode issuerAuth: %v", ErrMalformed, err)
	}
	protected, unprotected, err := cbor.ParseSign1Headers(authBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	merged := cbor.Header{}
	for k, v := range unprotected {
		merged[k] = v
	}
	// Protected wins: a value the issuer signed over cannot be overridden by an
	// unprotected one an intermediary can rewrite.
	for k, v := range protected {
		merged[k] = v
	}
	return merged, nil
}

// X5ChainHeader builds the unprotected COSE header carrying a certificate chain,
// for use as the `unprotected` argument when issuing. chain must be ordered
// leaf-first (the DSC, then any intermediates).
func X5ChainHeader(chain []*x509.Certificate) (cbor.Header, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("%w: empty chain", ErrX5ChainMalformed)
	}
	if len(chain) == 1 {
		// RFC 9360 §2: a single certificate is a bstr, not a one-element array.
		return cbor.Header{HeaderX5Chain: chain[0].Raw}, nil
	}
	arr := make([]any, 0, len(chain))
	for _, c := range chain {
		arr = append(arr, c.Raw)
	}
	return cbor.Header{HeaderX5Chain: arr}, nil
}

// AuthorityKeyIdentifier returns the base64url (unpadded) SubjectKeyIdentifier
// of a certificate, which is the form OpenID4VP §6.1.1's `aki` trusted-authority
// values use to name an issuing root. When the certificate carries no SKI
// extension, RFC 5280 §4.2.1.2's method-1 SHA-1 of the public key BIT STRING is
// computed instead, which is what CAs conventionally put there.
//
// The SHA-1 here is an identifier derivation defined by RFC 5280, not a security
// hash: it names a key, and the key's authority comes from chain validation.
func AuthorityKeyIdentifier(cert *x509.Certificate) string {
	ski := cert.SubjectKeyId
	if len(ski) == 0 {
		sum := sha1.Sum(cert.RawSubjectPublicKeyInfo) //nolint:gosec // see doc comment
		ski = sum[:]
	}
	return base64.RawURLEncoding.EncodeToString(ski)
}

// ChainMatchesAKI reports whether any certificate in the chain has the given
// base64url key identifier. It lets a verifier evaluate an OpenID4VP
// trusted_authorities `aki` entry against an mdoc's validated chain.
func ChainMatchesAKI(chain []*x509.Certificate, aki string) bool {
	want, err := base64.RawURLEncoding.DecodeString(aki)
	if err != nil || len(want) == 0 {
		return false
	}
	for _, c := range chain {
		ski := c.SubjectKeyId
		if len(ski) == 0 {
			sum := sha1.Sum(c.RawSubjectPublicKeyInfo) //nolint:gosec // RFC 5280 §4.2.1.2 identifier derivation
			ski = sum[:]
		}
		if bytes.Equal(ski, want) {
			return true
		}
	}
	return false
}
