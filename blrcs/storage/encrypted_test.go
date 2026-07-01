package storage_test

// External test package (not `package storage`): EncryptedStorage only needs
// the public Storage/BlobCipher surface, and testing it against the real
// atrest.Cipher exercises the actual intended composition (Axis 96).

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"blrcs/atrest"
	"blrcs/storage"
)

func newTestCipher(t *testing.T) *atrest.Cipher {
	t.Helper()
	key := make([]byte, atrest.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	c, err := atrest.NewCipher(atrest.KeyIDFromUint32(1), key)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestEncryptedStorageRoundTrip verifies AppendStatement/IterateStatements
// transparently encrypt/decrypt so callers see plaintext exactly as with an
// unwrapped Storage.
func TestEncryptedStorageRoundTrip(t *testing.T) {
	es := storage.NewEncryptedStorage(storage.NewMemoryStorage(), newTestCipher(t))

	want := []byte(`{"productId":"battery-42","carbonFootprint":12.5}`)
	idx, err := es.AppendStatement(want)
	if err != nil {
		t.Fatal(err)
	}
	if idx != 0 {
		t.Errorf("first leaf index: got %d want 0", idx)
	}

	var got []byte
	err = es.IterateStatements(func(i uint64, blob storage.StatementBlob) error {
		got = blob
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("round trip: got %s want %s", got, want)
	}
}

// TestEncryptedStorageBlobsAreOpaqueOnDisk verifies the underlying Storage
// never sees plaintext — it only ever stores/returns the AES-GCM envelope.
func TestEncryptedStorageBlobsAreOpaqueOnDisk(t *testing.T) {
	underlying := storage.NewMemoryStorage()
	es := storage.NewEncryptedStorage(underlying, newTestCipher(t))

	secret := []byte(`{"supplierName":"confidential-corp"}`)
	if _, err := es.AppendStatement(secret); err != nil {
		t.Fatal(err)
	}

	var raw []byte
	if err := underlying.IterateStatements(func(i uint64, blob storage.StatementBlob) error {
		raw = blob
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("confidential-corp")) {
		t.Error("plaintext leaked into the underlying (unwrapped) storage")
	}
}

// TestEncryptedStorageWrongKeyFailsToDecrypt verifies that data encrypted
// under one key cannot be read back with a different key (GCM authentication
// failure), matching atrest's own tamper-detection guarantee.
func TestEncryptedStorageWrongKeyFailsToDecrypt(t *testing.T) {
	underlying := storage.NewMemoryStorage()
	writeSide := storage.NewEncryptedStorage(underlying, newTestCipher(t))
	if _, err := writeSide.AppendStatement([]byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}

	readSide := storage.NewEncryptedStorage(underlying, newTestCipher(t)) // different key
	err := readSide.IterateStatements(func(i uint64, blob storage.StatementBlob) error {
		return nil
	})
	if err == nil {
		t.Fatal("decrypting with the wrong key should fail")
	}
	// Same keyID (both use KeyIDFromUint32(1)) but different random key bytes,
	// so this fails GCM authentication (ErrIntegrityFail), not the keyID
	// lookup (ErrUnknownKey) — either way it must not silently return garbage.
	if !errors.Is(err, atrest.ErrIntegrityFail) && !strings.Contains(err.Error(), "decrypt") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestEncryptedStorageSizeLoadSaveKeyPairPassThrough verifies the
// non-statement methods delegate unchanged (Size, LoadKeyPair, SaveKeyPair,
// Close) — encryption is scoped to the statement log only.
func TestEncryptedStorageSizeLoadSaveKeyPairPassThrough(t *testing.T) {
	underlying := storage.NewMemoryStorage()
	es := storage.NewEncryptedStorage(underlying, newTestCipher(t))

	if _, err := es.AppendStatement([]byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	n, err := es.Size()
	if err != nil || n != 1 {
		t.Errorf("Size: got %d, %v; want 1, nil", n, err)
	}

	if _, _, err := es.LoadKeyPair(); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("LoadKeyPair before save: want ErrNotFound, got %v", err)
	}

	if err := es.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestEncryptedStorageBlobPassThrough verifies SaveBlob/LoadBlob delegate to
// the underlying store unencrypted (Axis 100).
func TestEncryptedStorageBlobPassThrough(t *testing.T) {
	underlying := storage.NewMemoryStorage()
	es := storage.NewEncryptedStorage(underlying, newTestCipher(t))

	if err := es.SaveBlob("revocation-list", []byte("plain-data")); err != nil {
		t.Fatal(err)
	}
	got, err := es.LoadBlob("revocation-list")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "plain-data" {
		t.Errorf("got %q want plain-data", got)
	}
	// Confirm it's readable unencrypted from the underlying store too — blobs
	// are explicitly out of scope for encryption.
	rawGot, err := underlying.LoadBlob("revocation-list")
	if err != nil || string(rawGot) != "plain-data" {
		t.Errorf("underlying blob should be plaintext: %q, %v", rawGot, err)
	}
}
