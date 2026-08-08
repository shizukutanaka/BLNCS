package didresolver

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"blrcs/ecdsakey"
	"blrcs/multiformats"
)

// ============================================================================
// Axis 136: algorithm-tagged key resolution (Ed25519 + P-256)
//
// Axis 135 taught the verifiers to check ES256 signatures, but a verifier can
// only use that if it can OBTAIN a P-256 key — and every resolver entry point
// here returns ed25519.PublicKey. Because that type is a named []byte, a 65-byte
// P-256 key would physically fit inside it while the type lied about what it
// held; a caller could then hand it to ed25519.Verify and get a silent false, or
// mis-apply a 32-byte length check. So rather than widen the existing signatures,
// this file adds a PARALLEL, algorithm-tagged API. The Ed25519-typed functions
// keep their exact behaviour and callers are untouched.
// ============================================================================

// Algorithm names, matching the JOSE `alg` values the verifier registries use
// (compliance.RegisterJWSVerifier keys), so a resolved key can be handed
// straight to verification without a translation table.
const (
	AlgEdDSA = "EdDSA"
	AlgES256 = "ES256"
)

// PublicKey is a resolved verification key together with the algorithm it is
// for. Bytes holds the raw form each algorithm's verifier expects:
//   - EdDSA: the 32-byte Ed25519 public key.
//   - ES256: an uncompressed SEC1 point (0x04 || X || Y, 65 bytes). did:key and
//     Multikey carry the COMPRESSED form; it is expanded here so that callers
//     get one consistent representation.
type PublicKey struct {
	Alg   string
	Bytes []byte
}

// Ed25519 returns the key as an ed25519.PublicKey and reports whether it is one.
// Use this at the boundary with the Ed25519-typed APIs instead of converting by
// hand, so a P-256 key can never be mistaken for an Ed25519 one.
func (k PublicKey) Ed25519() (ed25519.PublicKey, bool) {
	if k.Alg != AlgEdDSA || len(k.Bytes) != ed25519.PublicKeySize {
		return nil, false
	}
	return ed25519.PublicKey(k.Bytes), true
}

// ResolveAllKeys resolves a DID to every verification key it publishes, tagged
// with its algorithm. It supports the same DID methods as ResolveAll (did:web,
// did:webvh, did:key, did:jwk) and additionally recognises P-256 keys, which
// ResolveAll necessarily omits because it can only express Ed25519.
//
// Prefer this over ResolveAll for new code; ResolveAll remains for callers that
// are Ed25519-only by construction.
func (r *Resolver) ResolveAllKeys(ctx context.Context, did string) ([]PublicKey, error) {
	switch {
	case strings.HasPrefix(did, "did:key:"):
		return resolveDIDKeyAny(strings.TrimPrefix(did, "did:key:"))
	case strings.HasPrefix(did, "did:jwk:"):
		return resolveDIDJWKAny(strings.TrimPrefix(did, "did:jwk:"))
	}
	// did:web / did:webvh resolve to a DID document; parse it for all algorithms.
	parts := strings.SplitN(did, ":", 3)
	if len(parts) != 3 || parts[0] != "did" {
		return nil, fmt.Errorf("%w: %q", ErrMalformedDID, did)
	}
	method, identifier := parts[1], parts[2]

	var body []byte
	var err error
	switch method {
	case "web":
		body, err = r.HTTPFetcher(ctx, didWebURL(identifier))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrFetchFailed, err)
		}
	case "webvh":
		// Reuses the full did:webvh verification (hash chain + SCID match).
		body, err = r.didWebVHDocument(ctx, identifier)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedMethod, method)
	}
	return parseDIDDocumentKeys(body)
}

// parseDIDDocumentKeys extracts every Ed25519 and P-256 verification key from a
// DID document. Unknown key types are skipped rather than failing the document:
// a DID may legitimately publish keys for algorithms this build cannot verify,
// and rejecting the whole document would deny service over an unrelated entry.
func parseDIDDocumentKeys(body []byte) ([]PublicKey, error) {
	var doc didDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("didresolver: parse DID document: %w", err)
	}
	var keys []PublicKey
	seen := make(map[string]bool)
	add := func(k PublicKey) {
		id := k.Alg + "|" + string(k.Bytes)
		if seen[id] {
			return
		}
		seen[id] = true
		keys = append(keys, k)
	}
	for _, vm := range doc.VerificationMethod {
		if jwk := vm.PublicKeyJwk; jwk != nil {
			if k, err := jwkToPublicKey(jwk); err == nil {
				add(k)
				continue
			}
		}
		if mb := vm.PublicKeyMultibase; mb != "" {
			if k, err := multibaseToPublicKey(mb); err == nil {
				add(k)
			}
		}
	}
	if len(keys) == 0 {
		return nil, ErrNoKey
	}
	return keys, nil
}

// jwkToPublicKey parses an Ed25519 (OKP) or P-256 (EC) JWK.
//
// Per RFC 7518 §6.2.1.2-3, an EC public key carries "x" and "y", each the
// base64url of the coordinate's fixed-length big-endian octet string — 32 octets
// for P-256. A short or long coordinate is rejected rather than left-padded:
// accepting variable widths would let one key have several encodings.
func jwkToPublicKey(jwk map[string]interface{}) (PublicKey, error) {
	kty, _ := jwk["kty"].(string)
	crv, _ := jwk["crv"].(string)

	switch {
	case kty == "OKP" && crv == "Ed25519":
		pub, err := jwkToEd25519(jwk)
		if err != nil {
			return PublicKey{}, err
		}
		return PublicKey{Alg: AlgEdDSA, Bytes: pub}, nil

	case kty == "EC" && crv == "P-256":
		xs, _ := jwk["x"].(string)
		ys, _ := jwk["y"].(string)
		if xs == "" || ys == "" {
			return PublicKey{}, errors.New("didresolver: P-256 JWK missing x or y")
		}
		x, err := base64.RawURLEncoding.DecodeString(xs)
		if err != nil {
			return PublicKey{}, fmt.Errorf("didresolver: P-256 JWK x: %w", err)
		}
		y, err := base64.RawURLEncoding.DecodeString(ys)
		if err != nil {
			return PublicKey{}, fmt.Errorf("didresolver: P-256 JWK y: %w", err)
		}
		if len(x) != ecdsakey.P256CoordSize || len(y) != ecdsakey.P256CoordSize {
			return PublicKey{}, fmt.Errorf("didresolver: P-256 JWK coordinates must be %d octets, got x=%d y=%d",
				ecdsakey.P256CoordSize, len(x), len(y))
		}
		sec1 := make([]byte, 0, ecdsakey.P256UncompressedSize)
		sec1 = append(sec1, 0x04)
		sec1 = append(sec1, x...)
		sec1 = append(sec1, y...)
		// Reject points that are not actually on the curve before publishing the
		// key to callers (invalid-curve defence at the resolution boundary).
		if _, err := ecdsakey.ParseP256PublicKey(sec1); err != nil {
			return PublicKey{}, err
		}
		return PublicKey{Alg: AlgES256, Bytes: sec1}, nil
	}
	return PublicKey{}, fmt.Errorf("didresolver: unsupported JWK kty=%q crv=%q", kty, crv)
}

// multibaseToPublicKey parses an Ed25519 or P-256 Multikey. The two multicodec
// prefixes are distinct (0xed01 vs 0x8024), so there is no ambiguity.
func multibaseToPublicKey(mb string) (PublicKey, error) {
	if pub, err := multibaseToEd25519(mb); err == nil {
		return PublicKey{Alg: AlgEdDSA, Bytes: pub}, nil
	}
	compressed, err := multiformats.DecodeP256Multikey(mb)
	if err != nil {
		return PublicKey{}, err
	}
	return p256FromCompressed(compressed)
}

// p256FromCompressed validates a compressed point and returns it in the
// uncompressed SEC1 form callers receive.
func p256FromCompressed(compressed []byte) (PublicKey, error) {
	key, err := ecdsakey.ParseP256PublicKey(compressed)
	if err != nil {
		return PublicKey{}, err
	}
	sec1, err := ecdsakey.MarshalP256PublicKey(key)
	if err != nil {
		return PublicKey{}, err
	}
	return PublicKey{Alg: AlgES256, Bytes: sec1}, nil
}

// resolveDIDKeyAny resolves a did:key identifier for either supported curve.
func resolveDIDKeyAny(id string) ([]PublicKey, error) {
	// Strip any fragment ("did:key:zDn…#zDn…" self-references the same key).
	if i := strings.IndexByte(id, '#'); i >= 0 {
		id = id[:i]
	}
	if pub, err := resolveDIDKey(id); err == nil {
		return []PublicKey{{Alg: AlgEdDSA, Bytes: pub}}, nil
	}
	compressed, err := multiformats.DecodeP256Multikey(id)
	if err != nil {
		return nil, fmt.Errorf("%w: did:key is neither Ed25519 nor P-256", ErrMalformedDID)
	}
	k, err := p256FromCompressed(compressed)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedDID, err)
	}
	return []PublicKey{k}, nil
}

// resolveDIDJWKAny resolves a did:jwk identifier for either supported curve.
func resolveDIDJWKAny(encoded string) ([]PublicKey, error) {
	if i := strings.IndexByte(encoded, '#'); i >= 0 {
		encoded = encoded[:i]
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: did:jwk base64url: %v", ErrMalformedDID, err)
	}
	var jwk map[string]interface{}
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, fmt.Errorf("%w: did:jwk JSON: %v", ErrMalformedDID, err)
	}
	k, err := jwkToPublicKey(jwk)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedDID, err)
	}
	return []PublicKey{k}, nil
}
