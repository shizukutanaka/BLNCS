package openid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"blrcs/ecdsakey"
	"blrcs/jwe"
)

// ============================================================================
// OpenID4VP §8.3 / HAIP encrypted Authorization Response
//
// When a Verifier has a ResponseEncryptionKey (P-256), it advertises the key in
// client_metadata and switches response_mode to direct_post.jwt, and the wallet
// returns the response as a JWE (ECDH-ES + A128GCM) instead of a plaintext form.
// This keeps the holder's disclosed claims confidential in transit and at the
// browser/relay boundary — HAIP mandates it and Chrome/Safari's Digital
// Credentials API already emit it. The crypto lives in the jwe package; this
// file is only the OpenID4VP plumbing.
// ============================================================================

// ResponseModeDirectPostJWT is response_mode for an encrypted response.
const ResponseModeDirectPostJWT = "direct_post.jwt"

var (
	// ErrResponseEncryptionKey is returned when a configured ResponseEncryptionKey
	// is not a usable P-256 private key.
	ErrResponseEncryptionKey = errors.New("openid4vp: response encryption key must be P-256")
	// ErrEncryptedResponseUnsupported is returned when a wallet sends an encrypted
	// `response` but the verifier has no ResponseEncryptionKey configured.
	ErrEncryptedResponseUnsupported = errors.New("openid4vp: encrypted response received but no response encryption key configured")
)

// responseEncryptionEnabled reports whether this verifier advertises and accepts
// encrypted responses.
func (v *Verifier) responseEncryptionEnabled() bool {
	return v.ResponseEncryptionKey != nil
}

// applyResponseEncryption decorates a freshly-built request with the response
// encryption advertisement when a ResponseEncryptionKey is set: it flips the
// response_mode to direct_post.jwt and attaches client_metadata carrying the
// verifier's encryption JWK. A no-op (and no error) when encryption is disabled.
func (v *Verifier) applyResponseEncryption(req *AuthorizationRequest) error {
	if !v.responseEncryptionEnabled() {
		return nil
	}
	if v.ResponseEncryptionKey.Curve != elliptic.P256() {
		return ErrResponseEncryptionKey
	}
	jwk, err := jwe.PublicKeyJWK(&v.ResponseEncryptionKey.PublicKey)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrResponseEncryptionKey, err)
	}
	req.ResponseMode = ResponseModeDirectPostJWT
	req.ClientMetadata = map[string]any{
		"jwks": map[string]any{"keys": []any{jwk}},
		// Advertise the single content-encryption algorithm we implement so a
		// wallet negotiates it rather than guessing (OpenID4VP §5.1).
		"encrypted_response_enc_values_supported": []any{jwe.EncA128GCM},
	}
	return nil
}

// DecryptResponse decrypts a compact JWE Authorization Response (the `response`
// parameter of a direct_post.jwt submission) into an AuthorizationResponse. The
// JWE plaintext is the same JSON object the plaintext flow carries
// (vp_token/state/presentation_submission). It does NOT verify the presentation
// — pass the result to ProcessResponse for that.
func (v *Verifier) DecryptResponse(compactJWE string) (*AuthorizationResponse, error) {
	if !v.responseEncryptionEnabled() {
		return nil, ErrEncryptedResponseUnsupported
	}
	if v.ResponseEncryptionKey.Curve != elliptic.P256() {
		return nil, ErrResponseEncryptionKey
	}
	plaintext, err := jwe.Decrypt(compactJWE, v.ResponseEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("openid4vp: decrypt response: %w", err)
	}
	var resp AuthorizationResponse
	if err := json.Unmarshal(plaintext, &resp); err != nil {
		return nil, fmt.Errorf("openid4vp: decrypted response JSON: %w", err)
	}
	if resp.VPToken == "" || resp.State == "" {
		return nil, errors.New("openid4vp: decrypted response missing vp_token or state")
	}
	return &resp, nil
}

// parseSubmission turns a raw wallet POST body into an AuthorizationResponse,
// transparently decrypting a direct_post.jwt submission. A submission is
// encrypted when it carries a `response` parameter (form) or member (JSON)
// holding a compact JWE; otherwise it is the plaintext vp_token form. An
// encrypted submission to a verifier without a ResponseEncryptionKey is refused
// (ErrEncryptedResponseUnsupported) rather than mis-parsed.
func (v *Verifier) parseSubmission(contentType string, body []byte) (*AuthorizationResponse, error) {
	if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		vals, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, fmt.Errorf("openid4vp: parse form: %w", err)
		}
		if enc := vals.Get("response"); enc != "" {
			return v.DecryptResponse(enc)
		}
		return ParseResponseForm(string(body))
	}
	// JSON fallback — some wallet implementations POST application/json.
	var probe struct {
		Response string `json:"response"`
	}
	if err := json.Unmarshal(body, &probe); err == nil && probe.Response != "" {
		return v.DecryptResponse(probe.Response)
	}
	resp := &AuthorizationResponse{}
	if err := json.Unmarshal(body, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// EncryptAuthorizationResponse is the wallet-side counterpart: it encrypts an
// Authorization Response to the verifier's advertised JWK, producing the compact
// JWE a wallet posts as the `response` parameter. apu/apv are optional agreement
// parameters (OpenID4VP does not require them). Exported so an integrator or a
// conformance harness can drive the encrypted flow without re-deriving the JWE
// framing.
func EncryptAuthorizationResponse(resp *AuthorizationResponse, verifierJWK map[string]any, apu, apv []byte) (string, error) {
	pub, err := p256FromJWK(verifierJWK)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(resp)
	if err != nil {
		return "", fmt.Errorf("openid4vp: marshal response: %w", err)
	}
	return jwe.Encrypt(pub, payload, apu, apv)
}

// p256FromJWK reconstructs a P-256 public key from the verifier's advertised
// encryption JWK (the kind PublicKeyJWK emits).
func p256FromJWK(jwk map[string]any) (*ecdsa.PublicKey, error) {
	kty, _ := jwk["kty"].(string)
	crv, _ := jwk["crv"].(string)
	if kty != "EC" || crv != "P-256" {
		return nil, errors.New("openid4vp: verifier JWK is not EC/P-256")
	}
	xs, _ := jwk["x"].(string)
	ys, _ := jwk["y"].(string)
	x, err := base64.RawURLEncoding.DecodeString(xs)
	if err != nil || len(x) != 32 {
		return nil, errors.New("openid4vp: verifier JWK has invalid x")
	}
	y, err := base64.RawURLEncoding.DecodeString(ys)
	if err != nil || len(y) != 32 {
		return nil, errors.New("openid4vp: verifier JWK has invalid y")
	}
	// Marshal to SEC1 and parse so the point is validated on-curve rather than
	// trusted from the wire.
	sec1 := make([]byte, 0, ecdsakey.P256UncompressedSize)
	sec1 = append(sec1, 0x04)
	sec1 = append(sec1, x...)
	sec1 = append(sec1, y...)
	pub, err := ecdsakey.ParseP256PublicKey(sec1)
	if err != nil {
		return nil, fmt.Errorf("openid4vp: verifier JWK point invalid: %w", err)
	}
	return pub, nil
}
