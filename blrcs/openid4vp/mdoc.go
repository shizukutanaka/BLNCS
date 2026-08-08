package openid4vp

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"blrcs/cbor"
	"blrcs/mdoc"
)

// ============================================================================
// Axis 138: mso_mdoc verification dispatch
//
// ProcessResponse previously verified EVERY vp_token as an SD-JWT, whatever
// format the DCQL query asked for. That is worse than an unimplemented feature:
// an mso_mdoc presentation failed at peekIssuer and surfaced as
// "vp_token signature/issuer mismatch", a misleading error that hides the fact
// that the format was never handled. Meanwhile CredentialQuery.DoctypeValue was
// declared but never read, so a wallet could have returned any doctype.
//
// # SessionTranscript: supplied, never invented
//
// ISO 18013-5 binds DeviceAuth to a SessionTranscript, and that binding is the
// entire replay defence — without the right bytes an mdoc presentation captured
// from one session verifies in another. Which bytes are correct depends on the
// transport profile, and the profiles are not equally settled:
//
//   - Over the W3C Digital Credentials API, OpenID4VP Annex C defines
//     SessionTranscript = [null, null, ["dcapi", dcapiInfoHash]] with
//     dcapiInfoHash = SHA-256(CBOR(dcapiInfo)).
//   - For "vanilla" OpenID4VP (direct_post, no DC API) the definition is still
//     being worked out upstream — see openid/OpenID4VP#402 and #519 and
//     openid/OpenID4VC-HAIP#137, which exist precisely because this is
//     under-specified.
//
// Guessing an OID4VPHandover structure here would produce a binding that
// interoperates with nothing and gives false assurance, so this package does not
// construct one. The verifier is configured with the exact bytes both sides
// agreed on (Verifier.MdocSessionTranscript), and an mdoc presentation without
// that configuration is REJECTED rather than verified with device binding
// skipped — failing closed, since an unbound mdoc is replayable.
// ============================================================================

// drDocuments is the DeviceResponse key holding the returned documents
// (ISO 18013-5 §8.3.2.1.2.2). The sibling "version"/"status" fields are not
// read here: neither is authenticated, so acting on them would add attack
// surface without adding assurance.
const drDocuments = "documents"

var (
	// ErrMdocSessionTranscriptMissing is returned when an mso_mdoc presentation
	// arrives but the verifier has no SessionTranscript configured. Verifying
	// without it would leave the presentation unbound to this session and so
	// replayable, which is why this fails instead of degrading.
	ErrMdocSessionTranscriptMissing = errors.New(
		"openid4vp: mso_mdoc presentation requires Verifier.MdocSessionTranscript; refusing to verify device auth unbound")
	// ErrMdocMalformed is returned when the vp_token is not a well-formed
	// base64url-encoded DeviceResponse.
	ErrMdocMalformed = errors.New("openid4vp: malformed mso_mdoc DeviceResponse")
	// ErrMdocDoctypeMismatch is returned when the returned doctype does not match
	// the one the DCQL query demanded.
	ErrMdocDoctypeMismatch = errors.New("openid4vp: mdoc doctype does not match the DCQL query")
	// ErrMdocNoTrustedIssuer is returned when no configured issuer key verifies
	// the credential.
	ErrMdocNoTrustedIssuer = errors.New("openid4vp: mdoc issuerAuth not signed by any acceptable issuer")
)

// verifyMdocPresentation verifies an mso_mdoc vp_token: it decodes the
// DeviceResponse, verifies each document's issuer signature and device
// authentication against the session transcript, and enforces the doctype the
// query asked for.
//
// wantDoctype is the DCQL CredentialQuery.Meta.DoctypeValue; empty means the
// query did not constrain it.
func (v *Verifier) verifyMdocPresentation(vpToken, wantDoctype string, acceptable map[string][]byte, now time.Time) (*mdoc.VerifiedDoc, string, error) {
	if len(v.MdocSessionTranscript) == 0 {
		return nil, "", ErrMdocSessionTranscriptMissing
	}
	raw, err := decodeMdocToken(vpToken)
	if err != nil {
		return nil, "", err
	}
	documents, err := deviceResponseDocuments(raw)
	if err != nil {
		return nil, "", err
	}

	// A DeviceResponse may carry several documents; accept the first that both
	// satisfies the doctype constraint and verifies under an acceptable issuer.
	var lastErr error
	for _, docAny := range documents {
		docBytes, err := cbor.Marshal(docAny)
		if err != nil {
			lastErr = fmt.Errorf("%w: re-encode document: %v", ErrMdocMalformed, err)
			continue
		}
		// Check the doctype BEFORE spending signature verifications on a document
		// the query never asked for.
		if wantDoctype != "" {
			gotDoctype, _ := documentDocType(docAny)
			if gotDoctype != wantDoctype {
				lastErr = fmt.Errorf("%w: got %q want %q", ErrMdocDoctypeMismatch, gotDoctype, wantDoctype)
				continue
			}
		}
		for issuerID, pub := range acceptable {
			vd, err := mdoc.VerifyDocument(docBytes, ed25519.PublicKey(pub), v.MdocSessionTranscript, now)
			if err != nil {
				lastErr = err
				continue
			}
			// Re-check the doctype against the MSO-attested value, not just the
			// envelope: the envelope docType is unauthenticated until the issuer
			// signature is verified.
			if wantDoctype != "" && vd.DocType != wantDoctype {
				lastErr = fmt.Errorf("%w: MSO doctype %q want %q", ErrMdocDoctypeMismatch, vd.DocType, wantDoctype)
				continue
			}
			return vd, issuerID, nil
		}
	}
	if lastErr == nil {
		lastErr = ErrMdocNoTrustedIssuer
	}
	return nil, "", lastErr
}

// decodeMdocToken decodes the base64url vp_token carrying a DeviceResponse.
// Both padded and unpadded encodings are accepted: implementations differ, and
// rejecting one would be an interop failure with no security benefit.
func decodeMdocToken(vpToken string) ([]byte, error) {
	if raw, err := base64.RawURLEncoding.DecodeString(vpToken); err == nil {
		return raw, nil
	}
	raw, err := base64.URLEncoding.DecodeString(vpToken)
	if err != nil {
		return nil, fmt.Errorf("%w: not base64url", ErrMdocMalformed)
	}
	return raw, nil
}

// deviceResponseDocuments extracts the documents array from a DeviceResponse.
func deviceResponseDocuments(raw []byte) ([]any, error) {
	top, err := cbor.Unmarshal(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMdocMalformed, err)
	}
	m, ok := top.(map[any]any)
	if !ok {
		return nil, fmt.Errorf("%w: DeviceResponse must be a CBOR map", ErrMdocMalformed)
	}
	docsAny, ok := m[drDocuments]
	if !ok {
		return nil, fmt.Errorf("%w: no documents", ErrMdocMalformed)
	}
	docs, ok := docsAny.([]any)
	if !ok || len(docs) == 0 {
		return nil, fmt.Errorf("%w: documents must be a non-empty array", ErrMdocMalformed)
	}
	return docs, nil
}

// documentDocType reads the (still unauthenticated) docType from a Document.
func documentDocType(docAny any) (string, bool) {
	m, ok := docAny.(map[any]any)
	if !ok {
		return "", false
	}
	dt, ok := m["docType"].(string)
	return dt, ok
}

// mdocQueryFromDCQL returns the mso_mdoc credential query in a DCQL query, if
// any, together with the doctype it constrains.
func mdocQueryFromDCQL(q *DCQLQuery) (found bool, doctype string) {
	if q == nil {
		return false, ""
	}
	for i := range q.Credentials {
		if q.Credentials[i].Format == FormatMsoMdoc {
			dt := ""
			if q.Credentials[i].Meta != nil {
				dt = q.Credentials[i].Meta.DoctypeValue
			}
			return true, dt
		}
	}
	return false, ""
}

// processMdocResponse is the mso_mdoc branch of ProcessResponse: it verifies the
// DeviceResponse and maps the result onto the same VerifiedPresentation shape
// the SD-JWT branch returns, so relying parties handle one result type.
//
// Session binding differs from the SD-JWT branch by construction: SD-JWT binds
// via the KB-JWT's nonce/audience, whereas mdoc binds via the SessionTranscript
// inside DeviceAuthentication. Both are checked — this branch simply reaches the
// binding through the transcript rather than through KB-JWT options.
func (v *Verifier) processMdocResponse(resp *AuthorizationResponse, req *AuthorizationRequest, acceptable map[string][]byte, wantDoctype string) (*VerifiedPresentation, error) {
	vd, issuerID, err := v.verifyMdocPresentation(resp.VPToken, wantDoctype, acceptable, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	// Flatten the namespaced mdoc elements into the flat claim map the
	// VerifiedPresentation contract uses, keeping the namespace as a prefix so
	// two namespaces cannot collide on an element identifier.
	claims := make(map[string]any, len(vd.NameSpaces))
	for ns, elems := range vd.NameSpaces {
		for id, val := range elems {
			claims[ns+":"+id] = val
		}
	}
	return &VerifiedPresentation{
		State:     resp.State,
		Issuer:    issuerID,
		Subject:   vd.DocType,
		Claims:    claims,
		ExpiresAt: vd.Validity.ValidUntil.Unix(),
		IssuedAt:  vd.Validity.ValidFrom.Unix(),
	}, nil
}
