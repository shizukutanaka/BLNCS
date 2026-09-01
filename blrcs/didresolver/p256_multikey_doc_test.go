package didresolver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"

	"blrcs/ecdsakey"
	"blrcs/multiformats"
)

// TestParseDIDDocP256MultibaseKey covers the P-256 branch of
// multibaseToPublicKey: a DID document that publishes its verification method as
// a Multikey (`publicKeyMultibase`) rather than a JWK. Multikey is the form W3C
// Data Integrity recommends, so a P-256 issuer publishing a did:web document
// this way must resolve — and until this test, no case exercised that path.
func TestParseDIDDocP256MultibaseKey(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	compressed := elliptic.MarshalCompressed(elliptic.P256(), priv.X, priv.Y)
	mb, err := multiformats.EncodeP256Multikey(compressed)
	if err != nil {
		t.Fatalf("EncodeP256Multikey: %v", err)
	}
	docBytes, _ := json.Marshal(map[string]any{
		"verificationMethod": []map[string]any{
			{"publicKeyMultibase": mb},
		},
	})

	keys, err := parseDIDDocumentKeys(docBytes)
	if err != nil {
		t.Fatalf("parseDIDDocumentKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("want 1 key, got %d", len(keys))
	}
	if keys[0].Alg != AlgES256 {
		t.Fatalf("alg = %q, want %q", keys[0].Alg, AlgES256)
	}
	// The resolver must hand back the uncompressed SEC1 form callers expect,
	// not the compressed bytes it parsed.
	want, err := ecdsakey.MarshalP256PublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytesEqual(keys[0].Bytes, want) {
		t.Fatal("resolved key does not match the published key")
	}
}

// TestParseDIDDocMultibaseRejectsGarbage proves the multibase branch fails
// closed: an unparseable value yields no key rather than a zero-valued one.
func TestParseDIDDocMultibaseRejectsGarbage(t *testing.T) {
	docBytes, _ := json.Marshal(map[string]any{
		"verificationMethod": []map[string]any{
			{"publicKeyMultibase": "znotarealmultikey"},
		},
	})
	if _, err := parseDIDDocumentKeys(docBytes); err != ErrNoKey {
		t.Fatalf("want ErrNoKey for an unparseable multikey, got %v", err)
	}
}
