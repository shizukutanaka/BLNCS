package atrest

import (
	"bytes"
	"errors"
	"sync"
	"testing"
)

// ============================================================================
// Cipher basics
// ============================================================================

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key, _ := GenerateKey()
	c, err := NewCipher(KeyIDFromUint32(1), key)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("secret payload")
	envelope, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	// Envelope ≠ plaintext
	if bytes.Equal(envelope, plaintext) {
		t.Error("envelope should differ from plaintext")
	}
	// Envelope contains version + keyID prefix
	if envelope[0] != EnvelopeVersion {
		t.Errorf("version byte: %d", envelope[0])
	}

	recovered, err := c.Decrypt(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Errorf("round-trip mismatch: %s", recovered)
	}
}

func TestEncryptProducesDifferentCiphertext(t *testing.T) {
	// Same plaintext should produce different envelopes (random nonce)
	key, _ := GenerateKey()
	c, _ := NewCipher(KeyIDFromUint32(1), key)
	payload := []byte("identical")
	env1, _ := c.Encrypt(payload)
	env2, _ := c.Encrypt(payload)
	if bytes.Equal(env1, env2) {
		t.Error("envelopes should differ (random nonce)")
	}
	// Both decrypt back correctly
	dec1, _ := c.Decrypt(env1)
	dec2, _ := c.Decrypt(env2)
	if !bytes.Equal(dec1, payload) || !bytes.Equal(dec2, payload) {
		t.Error("both should decrypt back")
	}
}

// ============================================================================
// Key validation
// ============================================================================

func TestNewCipherRejectsWrongKeySize(t *testing.T) {
	for _, size := range []int{0, 16, 24, 31, 33, 64} {
		key := make([]byte, size)
		_, err := NewCipher(KeyIDFromUint32(1), key)
		if !errors.Is(err, ErrInvalidKey) {
			t.Errorf("size %d: want ErrInvalidKey, got %v", size, err)
		}
	}
}

// ============================================================================
// Tamper detection (GCM auth tag)
// ============================================================================

func TestTamperedCiphertextDetected(t *testing.T) {
	key, _ := GenerateKey()
	c, _ := NewCipher(KeyIDFromUint32(1), key)
	envelope, _ := c.Encrypt([]byte("important data"))

	// Flip a bit in the ciphertext portion
	tampered := make([]byte, len(envelope))
	copy(tampered, envelope)
	tampered[len(tampered)-5] ^= 0x01

	_, err := c.Decrypt(tampered)
	if !errors.Is(err, ErrIntegrityFail) {
		t.Fatalf("want ErrIntegrityFail, got %v", err)
	}
}

func TestTamperedNonceDetected(t *testing.T) {
	key, _ := GenerateKey()
	c, _ := NewCipher(KeyIDFromUint32(1), key)
	envelope, _ := c.Encrypt([]byte("data"))

	// Modify nonce portion
	tampered := make([]byte, len(envelope))
	copy(tampered, envelope)
	tampered[1+keyIDSize] ^= 0xFF

	_, err := c.Decrypt(tampered)
	if !errors.Is(err, ErrIntegrityFail) {
		t.Fatalf("want ErrIntegrityFail, got %v", err)
	}
}

// ============================================================================
// Wrong key rejection
// ============================================================================

func TestWrongKeyCannotDecrypt(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()
	c1, _ := NewCipher(KeyIDFromUint32(1), key1)
	c2, _ := NewCipher(KeyIDFromUint32(2), key2)

	envelope, _ := c1.Encrypt([]byte("secret"))
	// c2 has different keyID — should refuse before even trying to decrypt
	_, err := c2.Decrypt(envelope)
	if !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("want ErrUnknownKey, got %v", err)
	}
}

// ============================================================================
// Envelope format validation
// ============================================================================

func TestRejectShortEnvelope(t *testing.T) {
	key, _ := GenerateKey()
	c, _ := NewCipher(KeyIDFromUint32(1), key)
	for _, size := range []int{0, 1, 5, 10, 32} {
		_, err := c.Decrypt(make([]byte, size))
		if !errors.Is(err, ErrInvalidEnvelope) && !errors.Is(err, ErrUnsupportedVersion) {
			t.Errorf("size %d: want envelope/version error, got %v", size, err)
		}
	}
}

func TestRejectUnknownVersion(t *testing.T) {
	key, _ := GenerateKey()
	c, _ := NewCipher(KeyIDFromUint32(1), key)
	envelope, _ := c.Encrypt([]byte("x"))
	tampered := make([]byte, len(envelope))
	copy(tampered, envelope)
	tampered[0] = 99 // unknown version

	_, err := c.Decrypt(tampered)
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("want ErrUnsupportedVersion, got %v", err)
	}
}

// ============================================================================
// Keyring — rotation
// ============================================================================

func TestKeyringRotation(t *testing.T) {
	keyring := NewKeyring()

	// Add v1 key, encrypt with it
	k1, _ := GenerateKey()
	c1, _ := NewCipher(KeyIDFromUint32(1), k1)
	keyring.Add(c1)

	envelope1, err := keyring.Encrypt([]byte("data v1"))
	if err != nil {
		t.Fatal(err)
	}

	// Rotate: add v2, set active
	k2, _ := GenerateKey()
	c2, _ := NewCipher(KeyIDFromUint32(2), k2)
	keyring.Add(c2)
	if err := keyring.SetActive(KeyIDFromUint32(2)); err != nil {
		t.Fatal(err)
	}

	envelope2, _ := keyring.Encrypt([]byte("data v2"))

	// Both can be decrypted via keyring
	d1, err := keyring.Decrypt(envelope1)
	if err != nil {
		t.Errorf("decrypt v1: %v", err)
	}
	if !bytes.Equal(d1, []byte("data v1")) {
		t.Errorf("v1 mismatch: %s", d1)
	}
	d2, err := keyring.Decrypt(envelope2)
	if err != nil {
		t.Errorf("decrypt v2: %v", err)
	}
	if !bytes.Equal(d2, []byte("data v2")) {
		t.Errorf("v2 mismatch: %s", d2)
	}

	// Active key is v2
	active := keyring.ActiveKeyID()
	if active != KeyIDFromUint32(2) {
		t.Errorf("active: %x", active)
	}
}

func TestKeyringEncryptWithoutActiveFails(t *testing.T) {
	kr := NewKeyring()
	_, err := kr.Encrypt([]byte("x"))
	if err == nil {
		t.Error("encrypt with empty keyring should fail")
	}
}

func TestKeyringSetActiveUnknown(t *testing.T) {
	kr := NewKeyring()
	err := kr.SetActive(KeyIDFromUint32(99))
	if !errors.Is(err, ErrUnknownKey) {
		t.Errorf("want ErrUnknownKey, got %v", err)
	}
}

func TestKeyringDecryptUnknownKey(t *testing.T) {
	// Encrypt with key v1 but keyring only has v2
	k1, _ := GenerateKey()
	c1, _ := NewCipher(KeyIDFromUint32(1), k1)
	envelope, _ := c1.Encrypt([]byte("x"))

	kr := NewKeyring()
	k2, _ := GenerateKey()
	c2, _ := NewCipher(KeyIDFromUint32(2), k2)
	kr.Add(c2)

	_, err := kr.Decrypt(envelope)
	if !errors.Is(err, ErrUnknownKey) {
		t.Errorf("unknown keyID in envelope: want ErrUnknownKey, got %v", err)
	}
}

func TestKeyringHasKey(t *testing.T) {
	kr := NewKeyring()
	k, _ := GenerateKey()
	c, _ := NewCipher(KeyIDFromUint32(42), k)
	kr.Add(c)
	if !kr.HasKey(KeyIDFromUint32(42)) {
		t.Error("HasKey: 42 should be true")
	}
	if kr.HasKey(KeyIDFromUint32(43)) {
		t.Error("HasKey: 43 should be false")
	}
}

// ============================================================================
// Key generator + ID helpers
// ============================================================================

func TestGenerateKeyProducesCorrectSize(t *testing.T) {
	for i := 0; i < 5; i++ {
		k, err := GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		if len(k) != KeySize {
			t.Errorf("key size: %d", len(k))
		}
	}
}

func TestGenerateKeyDifferent(t *testing.T) {
	k1, _ := GenerateKey()
	k2, _ := GenerateKey()
	if bytes.Equal(k1, k2) {
		t.Error("two GenerateKey calls should differ")
	}
}

func TestKeyIDFromUint32(t *testing.T) {
	id := KeyIDFromUint32(0x12345678)
	want := [keyIDSize]byte{0x12, 0x34, 0x56, 0x78}
	if id != want {
		t.Errorf("KeyIDFromUint32: %x want %x", id, want)
	}
}

// ============================================================================
// Empty plaintext
// ============================================================================

func TestEncryptEmptyPlaintext(t *testing.T) {
	key, _ := GenerateKey()
	c, _ := NewCipher(KeyIDFromUint32(1), key)
	envelope, err := c.Encrypt(nil)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := c.Decrypt(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if len(dec) != 0 {
		t.Errorf("empty roundtrip: %v", dec)
	}
}

func TestCipherKeyID(t *testing.T) {
	key, _ := GenerateKey()
	id := KeyIDFromUint32(0xDEADBEEF)
	c, err := NewCipher(id, key)
	if err != nil {
		t.Fatal(err)
	}
	if c.KeyID() != id {
		t.Errorf("KeyID: got %x want %x", c.KeyID(), id)
	}
}

// ============================================================================
// ActiveKeyID on empty keyring
// ============================================================================

func TestActiveKeyIDEmptyKeyring(t *testing.T) {
	kr := NewKeyring()
	id := kr.ActiveKeyID()
	// Active key on empty keyring should be the zero value.
	var zero [keyIDSize]byte
	if id != zero {
		t.Errorf("empty keyring ActiveKeyID: want zero, got %x", id)
	}
}

// ============================================================================
// NewCipher — Encrypt path: bad reader is untestable, but cover the path
// where the nonce is written properly (already tested) vs. nil active cipher.
// The coverage gap is in GenerateKey I/O failure — untestable in unit tests
// without replacing rand.Reader. Accept the gap and add a simple functional check.
// ============================================================================

func TestNewCipherValidKey(t *testing.T) {
	id := KeyIDFromUint32(7)
	key := make([]byte, KeySize)
	c, err := NewCipher(id, key)
	if err != nil {
		t.Fatal(err)
	}
	if c.KeyID() != id {
		t.Errorf("KeyID: %x", c.KeyID())
	}
}

// TestKeyringDecryptInvalidEnvelope covers the validateEnvelope error path in
// Keyring.Decrypt (too-short envelope is rejected before keyID lookup).
func TestKeyringDecryptInvalidEnvelope(t *testing.T) {
	kr := NewKeyring()
	k, _ := GenerateKey()
	c, _ := NewCipher(KeyIDFromUint32(1), k)
	kr.Add(c)
	_, err := kr.Decrypt([]byte("short"))
	if err == nil {
		t.Fatal("invalid envelope should be rejected by Keyring.Decrypt")
	}
}

// ============================================================================
// NIST SP 800-38D nonce-space limit
// ============================================================================

// TestEncryptKeyExhaustedAfterLimit verifies that Cipher.Encrypt returns
// ErrKeyExhausted once the per-key encryption count reaches maxEncryptionsPerKey.
// We fast-path this by pre-setting the atomic counter to the limit directly
// (same package), so the test doesn't actually perform 2^32 encryptions.
func TestEncryptKeyExhaustedAfterLimit(t *testing.T) {
	key, _ := GenerateKey()
	c, err := NewCipher(KeyIDFromUint32(42), key)
	if err != nil {
		t.Fatal(err)
	}

	// Confirm normal encryption works.
	if _, err := c.Encrypt([]byte("hello")); err != nil {
		t.Fatalf("first encrypt should succeed: %v", err)
	}

	// Artificially advance the counter to the limit so the next call overflows.
	c.encCount.Store(maxEncryptionsPerKey)

	if _, err := c.Encrypt([]byte("overflowed")); !errors.Is(err, ErrKeyExhausted) {
		t.Fatalf("want ErrKeyExhausted, got %v", err)
	}
}

// TestKeyringRotationAfterExhaustion verifies the intended workflow: rotate
// to a new key via Keyring.SetActive and encryption resumes successfully.
func TestKeyringRotationAfterExhaustion(t *testing.T) {
	kr := NewKeyring()
	k1, _ := GenerateKey()
	c1, _ := NewCipher(KeyIDFromUint32(1), k1)
	kr.Add(c1)

	// Exhaust key 1.
	c1.encCount.Store(maxEncryptionsPerKey)
	if _, err := kr.Encrypt([]byte("x")); !errors.Is(err, ErrKeyExhausted) {
		t.Fatalf("exhausted key should return ErrKeyExhausted: %v", err)
	}

	// Add and activate key 2 — encryption must resume.
	k2, _ := GenerateKey()
	c2, _ := NewCipher(KeyIDFromUint32(2), k2)
	kr.Add(c2)
	if err := kr.SetActive(KeyIDFromUint32(2)); err != nil {
		t.Fatal(err)
	}
	env, err := kr.Encrypt([]byte("after-rotation"))
	if err != nil {
		t.Fatalf("encrypt after key rotation: %v", err)
	}
	plain, err := kr.Decrypt(env)
	if err != nil {
		t.Fatalf("decrypt after rotation: %v", err)
	}
	if string(plain) != "after-rotation" {
		t.Errorf("plaintext mismatch: %s", plain)
	}
}

// ============================================================================
// Concurrent Keyring access (data-race guard)
// ============================================================================

// TestKeyringConcurrentRotationAndEncrypt verifies that concurrent SetActive
// (key rotation) and Encrypt/Decrypt calls on a Keyring are race-free.
// Before the sync.RWMutex fix, concurrent map reads/writes were a data race
// detectable under -race and could produce crashes or corrupted state.
func TestKeyringConcurrentRotationAndEncrypt(t *testing.T) {
	k1, _ := GenerateKey()
	k2, _ := GenerateKey()
	c1, _ := NewCipher(KeyIDFromUint32(1), k1)
	c2, _ := NewCipher(KeyIDFromUint32(2), k2)

	kr := NewKeyring()
	kr.Add(c1)
	kr.Add(c2)

	payload := []byte("concurrent-payload")

	var wg sync.WaitGroup
	// Goroutine 1: repeatedly rotate the active key.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			if i%2 == 0 {
				_ = kr.SetActive(KeyIDFromUint32(1))
			} else {
				_ = kr.SetActive(KeyIDFromUint32(2))
			}
		}
	}()
	// Goroutine 2: repeatedly encrypt (reads active key pointer).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			if env, err := kr.Encrypt(payload); err == nil {
				if _, err := kr.Decrypt(env); err != nil {
					t.Errorf("Decrypt after concurrent rotation: %v", err)
				}
			}
		}
	}()
	// Goroutine 3: repeatedly check HasKey (reads ciphers map).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			kr.HasKey(KeyIDFromUint32(1))
		}
	}()
	wg.Wait()
}
