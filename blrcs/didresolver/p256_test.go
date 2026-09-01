package didresolver

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	"blrcs/compliance"
	"blrcs/ecdsakey"
	"blrcs/multiformats"
)

// ============================================================================
// Axis 136: P-256 key resolution (JWK, Multikey, did:key, did:jwk, did:web)
// ============================================================================

func p256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// p256JWK renders a P-256 public key as an RFC 7518 §6.2 EC JWK: x and y are
// each the base64url of the 32-octet big-endian coordinate.
func p256JWK(pub *ecdsa.PublicKey) map[string]any {
	x := make([]byte, 32)
	y := make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	return map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(x),
		"y": base64.RawURLEncoding.EncodeToString(y),
	}
}

func didDocWithJWK(t *testing.T, jwk map[string]any) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"id": "did:web:issuer.example",
		"verificationMethod": []map[string]any{
			{"id": "#key-1", "type": "JsonWebKey2020", "publicKeyJwk": jwk},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestResolveP256JWKFromDIDWeb(t *testing.T) {
	priv := p256Key(t)
	doc := didDocWithJWK(t, p256JWK(&priv.PublicKey))

	r := New()
	r.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) { return doc, nil }

	keys, err := r.ResolveAllKeys(context.Background(), "did:web:issuer.example")
	if err != nil {
		t.Fatalf("ResolveAllKeys: %v", err)
	}
	if len(keys) != 1 || keys[0].Alg != AlgES256 {
		t.Fatalf("want one ES256 key, got %+v", keys)
	}
	want, _ := ecdsakey.MarshalP256PublicKey(&priv.PublicKey)
	if string(keys[0].Bytes) != string(want) {
		t.Error("resolved key bytes do not match the issuer key")
	}
	// The Ed25519-typed API must NOT surface a P-256 key.
	if _, ok := keys[0].Ed25519(); ok {
		t.Error("a P-256 key must not be presented as Ed25519")
	}
	if _, err := r.ResolveAll(context.Background(), "did:web:issuer.example"); err != ErrNoKey {
		t.Errorf("Ed25519-only ResolveAll should find no key, got %v", err)
	}
}

// TestResolvedP256KeyVerifiesRealCredential closes the loop opened by Axis 135:
// resolve a P-256 key from a DID, then verify an actual ES256 SD-JWT with it.
func TestResolvedP256KeyVerifiesRealCredential(t *testing.T) {
	priv := p256Key(t)
	doc := didDocWithJWK(t, p256JWK(&priv.PublicKey))
	r := New()
	r.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) { return doc, nil }

	keys, err := r.ResolveAllKeys(context.Background(), "did:web:issuer.example")
	if err != nil {
		t.Fatal(err)
	}

	// Mint an ES256 SD-JWT the way a conforming issuer would (raw R‖S).
	hdr, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "dc+sd-jwt"})
	pl, _ := json.Marshal(map[string]any{
		"iss": "did:web:issuer.example", "sub": "battery-001", "vct": "DigitalProductPassport",
	})
	si := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(pl)
	d := sha256.Sum256([]byte(si))
	sr, ss, err := ecdsa.Sign(rand.Reader, priv, d[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 64)
	sr.FillBytes(raw[:32])
	ss.FillBytes(raw[32:])
	sdjwt := si + "." + base64.RawURLEncoding.EncodeToString(raw) + "~"

	vc, err := compliance.VerifySDJWTWithBinding(sdjwt, keys[0].Bytes, compliance.VerifyOptions{})
	if err != nil {
		t.Fatalf("credential should verify with the resolved P-256 key: %v", err)
	}
	if vc.Subject != "battery-001" {
		t.Errorf("subject: %q", vc.Subject)
	}
}

func TestResolveP256DIDKey(t *testing.T) {
	priv := p256Key(t)
	compressed := elliptic.MarshalCompressed(elliptic.P256(), priv.X, priv.Y)
	mk, err := multiformats.EncodeP256Multikey(compressed)
	if err != nil {
		t.Fatal(err)
	}
	// P-256 did:key identifiers begin "zDn" (multicodec 0x1200 → varint 0x80 0x24).
	if len(mk) < 3 || mk[:3] != "zDn" {
		t.Errorf("P-256 multikey should start zDn, got %q", mk[:min(4, len(mk))])
	}

	r := New()
	keys, err := r.ResolveAllKeys(context.Background(), "did:key:"+mk)
	if err != nil {
		t.Fatalf("did:key P-256: %v", err)
	}
	if len(keys) != 1 || keys[0].Alg != AlgES256 {
		t.Fatalf("want one ES256 key, got %+v", keys)
	}
	want, _ := ecdsakey.MarshalP256PublicKey(&priv.PublicKey)
	if string(keys[0].Bytes) != string(want) {
		t.Error("did:key resolved to the wrong point")
	}
}

func TestResolveP256DIDJWK(t *testing.T) {
	priv := p256Key(t)
	jwkJSON, err := json.Marshal(p256JWK(&priv.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	did := "did:jwk:" + base64.RawURLEncoding.EncodeToString(jwkJSON)

	r := New()
	keys, err := r.ResolveAllKeys(context.Background(), did)
	if err != nil {
		t.Fatalf("did:jwk P-256: %v", err)
	}
	if len(keys) != 1 || keys[0].Alg != AlgES256 {
		t.Fatalf("want one ES256 key, got %+v", keys)
	}
}

// TestEd25519StillResolvesViaTaggedAPI proves the new API is a superset: the
// existing Ed25519 forms still resolve, and are tagged EdDSA.
func TestEd25519StillResolvesViaTaggedAPI(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	doc := didDocWithJWK(t, map[string]any{
		"kty": "OKP", "crv": "Ed25519",
		"x": base64.RawURLEncoding.EncodeToString(pub),
	})
	r := New()
	r.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) { return doc, nil }

	keys, err := r.ResolveAllKeys(context.Background(), "did:web:issuer.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].Alg != AlgEdDSA {
		t.Fatalf("want one EdDSA key, got %+v", keys)
	}
	got, ok := keys[0].Ed25519()
	if !ok || string(got) != string(pub) {
		t.Error("Ed25519 accessor should return the original key")
	}
	// did:key Ed25519 must still work through the tagged API.
	mk := multiformats.EncodeEd25519Multikey(pub)
	kk, err := r.ResolveAllKeys(context.Background(), "did:key:"+mk)
	if err != nil || len(kk) != 1 || kk[0].Alg != AlgEdDSA {
		t.Fatalf("did:key Ed25519 via tagged API: err=%v keys=%+v", err, kk)
	}
}

// TestMixedAlgorithmDocument proves a DID publishing both curves yields both,
// correctly tagged — the realistic migration case.
func TestMixedAlgorithmDocument(t *testing.T) {
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	priv := p256Key(t)
	body, err := json.Marshal(map[string]any{
		"id": "did:web:issuer.example",
		"verificationMethod": []map[string]any{
			{"id": "#ed", "publicKeyJwk": map[string]any{
				"kty": "OKP", "crv": "Ed25519",
				"x": base64.RawURLEncoding.EncodeToString(edPub)}},
			{"id": "#ec", "publicKeyJwk": p256JWK(&priv.PublicKey)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := New()
	r.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) { return body, nil }

	keys, err := r.ResolveAllKeys(context.Background(), "did:web:issuer.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("want 2 keys, got %d", len(keys))
	}
	algs := map[string]bool{keys[0].Alg: true, keys[1].Alg: true}
	if !algs[AlgEdDSA] || !algs[AlgES256] {
		t.Errorf("want one of each algorithm, got %+v", keys)
	}
	// The legacy Ed25519-only API must still return exactly the Ed25519 key.
	legacy, err := r.ResolveAll(context.Background(), "did:web:issuer.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(legacy) != 1 || string(legacy[0]) != string(edPub) {
		t.Error("legacy ResolveAll must be unchanged: Ed25519 only")
	}
}

// TestOffCurveJWKRejected: the resolution boundary must not hand out a key that
// is not on the curve (invalid-curve defence).
func TestOffCurveJWKRejected(t *testing.T) {
	priv := p256Key(t)
	jwk := p256JWK(&priv.PublicKey)
	bad, _ := base64.RawURLEncoding.DecodeString(jwk["y"].(string))
	bad[len(bad)-1] ^= 0x01
	jwk["y"] = base64.RawURLEncoding.EncodeToString(bad)

	r := New()
	r.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) {
		return didDocWithJWK(t, jwk), nil
	}
	if _, err := r.ResolveAllKeys(context.Background(), "did:web:issuer.example"); err != ErrNoKey {
		t.Fatalf("off-curve JWK should yield no usable key, got %v", err)
	}
}

// TestMalformedP256JWKRejected covers coordinate widths, which RFC 7518 fixes at
// 32 octets for P-256; variable widths would give one key several encodings.
func TestMalformedP256JWKRejected(t *testing.T) {
	priv := p256Key(t)
	base := p256JWK(&priv.PublicKey)

	short := map[string]any{"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(make([]byte, 31)), "y": base["y"]}
	long := map[string]any{"kty": "EC", "crv": "P-256",
		"x": base["x"], "y": base64.RawURLEncoding.EncodeToString(make([]byte, 33))}
	missing := map[string]any{"kty": "EC", "crv": "P-256", "x": base["x"]}
	wrongCurve := map[string]any{"kty": "EC", "crv": "P-384", "x": base["x"], "y": base["y"]}

	for name, jwk := range map[string]map[string]any{
		"short x": short, "long y": long, "missing y": missing, "wrong curve": wrongCurve,
	} {
		if _, err := jwkToPublicKey(jwk); err == nil {
			t.Errorf("%s should be rejected", name)
		}
	}
}

// TestP256MultikeyRejectsEd25519AndViceVersa guards against curve confusion:
// the two multicodec prefixes are distinct and must not cross-decode.
func TestP256MultikeyRejectsEd25519AndViceVersa(t *testing.T) {
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	edMK := multiformats.EncodeEd25519Multikey(edPub)
	if _, err := multiformats.DecodeP256Multikey(edMK); err == nil {
		t.Error("an Ed25519 multikey must not decode as P-256")
	}

	priv := p256Key(t)
	p256MK, err := multiformats.EncodeP256Multikey(elliptic.MarshalCompressed(elliptic.P256(), priv.X, priv.Y))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := multiformats.DecodeEd25519Multikey(p256MK); err == nil {
		t.Error("a P-256 multikey must not decode as Ed25519")
	}
}

func TestEncodeP256MultikeyValidatesInput(t *testing.T) {
	if _, err := multiformats.EncodeP256Multikey(make([]byte, 33)); err == nil {
		t.Error("compressed point must start 0x02/0x03")
	}
	if _, err := multiformats.EncodeP256Multikey(make([]byte, 65)); err == nil {
		t.Error("uncompressed length must be rejected by the multikey encoder")
	}
}
