package jwe

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

// ============================================================================
// Axis 143: JWE response encryption (ECDH-ES + A128GCM, P-256)
//
// HAIP / OpenID4VP §8.3 require verifiers to accept an encrypted Authorization
// Response and pin ECDH-ES + A128GCM on P-256 — what Chrome/Safari's Digital
// Credentials API emit. The key-agreement math is anchored on the fully-worked
// example in RFC 7518 Appendix C, so interoperability is proven, not assumed.
// ============================================================================

// TestConcatKDF_RFC7518AppendixC is the conformance anchor: RFC 7518 Appendix C
// works a complete ECDH-ES key agreement for alg="ECDH-ES", enc="A128GCM",
// apu="Alice", apv="Bob", and publishes both the shared secret Z and the
// resulting 128-bit derived key. Reproducing that byte-for-byte proves the
// Concat KDF OtherInfo construction is correct.
func TestConcatKDF_RFC7518AppendixC(t *testing.T) {
	// Z, the ECDH shared secret from Appendix C (32 octets).
	z := []byte{
		158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132,
		38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121,
		140, 254, 144, 196,
	}
	// AlgorithmID for direct agreement is the enc value; PartyU/V are the raw
	// (un-base64) "Alice"/"Bob" from the example.
	got := concatKDF(z, []byte("A128GCM"), []byte("Alice"), []byte("Bob"), 128)

	// RFC 7518 Appendix C derived key, base64url "VqqN6vgjbSBcIijNcacQGg".
	want := []byte{86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26}
	if !bytes.Equal(got, want) {
		t.Fatalf("Concat KDF disagrees with RFC 7518 Appendix C:\n got  %v\n want %v", got, want)
	}
	if enc := base64.RawURLEncoding.EncodeToString(got); enc != "VqqN6vgjbSBcIijNcacQGg" {
		t.Fatalf("derived key base64url = %q, want VqqN6vgjbSBcIijNcacQGg", enc)
	}
}

func p256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	recipient := p256(t)
	msg := []byte(`{"vp_token":"eyJ...","state":"abc"}`)

	compact, err := Encrypt(&recipient.PublicKey, msg, nil, nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if n := strings.Count(compact, "."); n != 4 {
		t.Fatalf("compact JWE must have 5 parts (4 dots), got %d", n)
	}
	// Direct agreement: the encrypted_key part (index 1) is empty.
	if parts := strings.Split(compact, "."); parts[1] != "" {
		t.Errorf("encrypted_key must be empty for ECDH-ES direct, got %q", parts[1])
	}

	back, err := Decrypt(compact, recipient)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(back, msg) {
		t.Fatalf("round trip mismatch: got %q want %q", back, msg)
	}
}

func TestEncryptWithAPUAPV(t *testing.T) {
	recipient := p256(t)
	msg := []byte("secret")
	apu, apv := []byte("wallet-nonce"), []byte("did:web:verifier")

	compact, err := Encrypt(&recipient.PublicKey, msg, apu, apv)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Decrypt(compact, recipient)
	if err != nil {
		t.Fatalf("decrypt with apu/apv: %v", err)
	}
	if !bytes.Equal(back, msg) {
		t.Fatal("apu/apv round trip mismatch")
	}
}

// TestEncryptIsNondeterministic proves the ephemeral key is fresh per call, so
// identical plaintext yields distinct ciphertexts (single-use ephemeral key,
// fresh IV).
func TestEncryptIsNondeterministic(t *testing.T) {
	recipient := p256(t)
	a, _ := Encrypt(&recipient.PublicKey, []byte("x"), nil, nil)
	b, _ := Encrypt(&recipient.PublicKey, []byte("x"), nil, nil)
	if a == b {
		t.Fatal("two encryptions of the same plaintext must differ")
	}
}

func TestDecryptWrongRecipientFails(t *testing.T) {
	recipient := p256(t)
	attacker := p256(t)
	compact, err := Encrypt(&recipient.PublicKey, []byte("secret"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(compact, attacker); err == nil {
		t.Fatal("a different recipient key must not decrypt")
	}
}

// TestDecryptTamperDetected checks the AEAD integrity: any bit flipped in the
// ciphertext, tag, IV, or protected header (which is the AAD) must fail.
func TestDecryptTamperDetected(t *testing.T) {
	recipient := p256(t)
	compact, err := Encrypt(&recipient.PublicKey, []byte("sensitive"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(compact, ".")
	for _, idx := range []int{0, 2, 3, 4} { // header, iv, ct, tag (skip empty enc key)
		tampered := append([]string{}, parts...)
		tampered[idx] = flipLastBit(t, tampered[idx])
		if _, err := Decrypt(strings.Join(tampered, "."), recipient); err == nil {
			t.Errorf("tampering with part %d must be detected", idx)
		}
	}
}

func TestDecryptRejectsUnsupportedAlg(t *testing.T) {
	recipient := p256(t)
	// Hand-craft a header naming an unimplemented alg.
	hdr := b64([]byte(`{"alg":"RSA-OAEP","enc":"A128GCM","epk":{"kty":"EC","crv":"P-256","x":"","y":""}}`))
	compact := hdr + "..AAAA.BBBB.CCCC"
	if _, err := Decrypt(compact, recipient); err != ErrUnsupportedAlg {
		t.Fatalf("unsupported alg should give ErrUnsupportedAlg, got %v", err)
	}
	// An unimplemented content encryption.
	hdr2 := b64([]byte(`{"alg":"ECDH-ES","enc":"A256CBC-HS512","epk":{"kty":"EC","crv":"P-256","x":"","y":""}}`))
	if _, err := Decrypt(hdr2+"..AAAA.BBBB.CCCC", recipient); err != ErrUnsupportedAlg {
		t.Fatalf("unsupported enc should give ErrUnsupportedAlg, got %v", err)
	}
}

// TestDecryptRejectsNonEmptyEncryptedKey: direct agreement forbids a JWE
// Encrypted Key. One present signals a different key-management mode.
func TestDecryptRejectsNonEmptyEncryptedKey(t *testing.T) {
	recipient := p256(t)
	compact, err := Encrypt(&recipient.PublicKey, []byte("x"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(compact, ".")
	parts[1] = "c29tZWtleQ" // inject an encrypted_key
	if _, err := Decrypt(strings.Join(parts, "."), recipient); err != ErrUnsupportedAlg {
		t.Fatalf("non-empty encrypted_key must be rejected, got %v", err)
	}
}

func TestDecryptMalformed(t *testing.T) {
	recipient := p256(t)
	cases := map[string]string{
		"empty":             "",
		"too few parts":     "a.b.c",
		"too many parts":    "a.b.c.d.e.f",
		"empty header":      ".." + "AAAA.BBBB.CCCC"[0:0] + ".iv.ct.tag",
		"bad base64 header": "!!!..aXY.Y3Q.dGFn",
	}
	for name, c := range cases {
		if _, err := Decrypt(c, recipient); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestEncryptRejectsNonP256(t *testing.T) {
	// A P-384 key must be refused up front.
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Encrypt(&k.PublicKey, []byte("x"), nil, nil); err != ErrBadKey {
		t.Fatalf("non-P-256 recipient should give ErrBadKey, got %v", err)
	}
	if _, err := Encrypt(nil, []byte("x"), nil, nil); err != ErrBadKey {
		t.Fatalf("nil recipient should give ErrBadKey, got %v", err)
	}
}

// TestPublicKeyJWK renders the verifier's advertised encryption key and proves a
// wallet can encrypt to the parsed form.
func TestPublicKeyJWK(t *testing.T) {
	recipient := p256(t)
	jwk, err := PublicKeyJWK(&recipient.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if jwk["kty"] != "EC" || jwk["crv"] != "P-256" || jwk["use"] != "enc" {
		t.Fatalf("unexpected JWK: %v", jwk)
	}
	// Coordinates must be 32-byte fixed-width (RFC 7518 §6.2.1.2).
	x, err := base64.RawURLEncoding.DecodeString(jwk["x"].(string))
	if err != nil || len(x) != 32 {
		t.Fatalf("x coordinate not 32 bytes: %v (%d)", err, len(x))
	}
}

func flipLastBit(t *testing.T, seg string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil || len(raw) == 0 {
		// If the segment can't be decoded/empty, mutate the string directly.
		return seg + "AA"
	}
	raw[len(raw)-1] ^= 0x01
	return base64.RawURLEncoding.EncodeToString(raw)
}
