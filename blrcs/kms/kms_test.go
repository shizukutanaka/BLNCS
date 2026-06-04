package kms

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// ============================================================================
// MemorySigner
// ============================================================================

func TestMemorySignerSignVerify(t *testing.T) {
	s, err := NewMemorySigner("did:web:test")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	msg := []byte("hello world")
	sig, err := s.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifySignature(s.PublicKey(), msg, sig) {
		t.Error("verify failed")
	}
	// tamper
	tampered := []byte("hello world!")
	if VerifySignature(s.PublicKey(), tampered, sig) {
		t.Error("tampered verify should fail")
	}
}

func TestMemorySignerEmptyID(t *testing.T) {
	if _, err := NewMemorySigner(""); err == nil {
		t.Fatal("empty ID should fail")
	}
}

func TestMemorySignerPrivateKeyAccessible(t *testing.T) {
	s, _ := NewMemorySigner("did:web:t")
	defer s.Close()
	priv := s.PrivateKey()
	if len(priv) != ed25519.PrivateKeySize {
		t.Errorf("priv size: %d", len(priv))
	}
}

func TestMemorySignerCloseZeroizes(t *testing.T) {
	s, _ := NewMemorySigner("did:web:t")
	priv := s.PrivateKey()
	// Save reference
	cp := make([]byte, len(priv))
	copy(cp, priv)
	s.Close()
	// Close should make Sign fail
	if _, err := s.Sign([]byte("x")); err == nil {
		t.Error("sign after close should fail")
	}
	// PrivateKey reference becomes nil
	if s.PrivateKey() != nil {
		t.Error("PrivateKey() should be nil after Close")
	}
}

func TestImportMemorySigner(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := ImportMemorySigner("did:web:imp", priv)
	if err != nil {
		t.Fatal(err)
	}
	if string(s.PublicKey()) != string(pub) {
		t.Error("public key mismatch")
	}
	// Sign
	sig, err := s.Sign([]byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	if !VerifySignature(pub, []byte("test"), sig) {
		t.Error("verify failed")
	}
}

func TestImportInvalidKey(t *testing.T) {
	if _, err := ImportMemorySigner("id", []byte("too-short")); err == nil {
		t.Fatal("invalid key size should fail")
	}
}

// ============================================================================
// FileSigner — persistence
// ============================================================================

func TestFileSignerNewAndPersist(t *testing.T) {
	dir, _ := os.MkdirTemp("", "blrcs-kms-*")
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "key.bin")

	// First load — generates new key
	s1, err := NewFileSigner("did:web:fs", path)
	if err != nil {
		t.Fatal(err)
	}
	pub1 := s1.PublicKey()
	sig, _ := s1.Sign([]byte("payload"))
	s1.Close()

	// Second load — restores same key
	s2, err := NewFileSigner("did:web:fs", path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if string(s2.PublicKey()) != string(pub1) {
		t.Error("key not persisted across loads")
	}
	// Signature from first session verifies with second's pubkey
	if !VerifySignature(s2.PublicKey(), []byte("payload"), sig) {
		t.Error("cross-session sig verify failed")
	}
}

func TestFileSignerPermissions(t *testing.T) {
	dir, _ := os.MkdirTemp("", "blrcs-kms-*")
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "key.bin")
	s, _ := NewFileSigner("id", path)
	defer s.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	mode := info.Mode().Perm()
	if mode != 0o600 {
		t.Errorf("key file perms: %#o (want 0600)", mode)
	}
}

func TestFileSignerEmptyPath(t *testing.T) {
	if _, err := NewFileSigner("id", ""); err == nil {
		t.Fatal("empty path should fail")
	}
}

func TestFileSignerCorruptedFile(t *testing.T) {
	dir, _ := os.MkdirTemp("", "blrcs-kms-*")
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "key.bin")
	os.WriteFile(path, []byte("garbage"), 0o600)
	if _, err := NewFileSigner("id", path); err == nil {
		t.Fatal("corrupted file should fail")
	}
}

// ============================================================================
// ExternalSigner — production HSM/KMS pattern
// ============================================================================

func TestExternalSignerWithRealCrypto(t *testing.T) {
	// Simulate AWS KMS: signFn calls into a hidden private key
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signFn := func(payload []byte) ([]byte, error) {
		return ed25519.Sign(priv, payload), nil
	}
	es, err := NewExternalSigner("aws-kms-key-1", pub, signFn, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer es.Close()

	sig, err := es.Sign([]byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	if !VerifySignature(pub, []byte("test"), sig) {
		t.Error("verify failed")
	}
	// External signer does NOT export private key
	_, isExporter := any(es).(PrivateKeyExporter)
	if isExporter {
		t.Error("CRITICAL: ExternalSigner must NOT implement PrivateKeyExporter")
	}
}

func TestExternalSignerSignFnReturnsError(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	signFn := func(_ []byte) ([]byte, error) {
		return nil, errors.New("HSM unavailable")
	}
	es, _ := NewExternalSigner("hsm", pub, signFn, nil)
	defer es.Close()
	if _, err := es.Sign([]byte("x")); err == nil {
		t.Fatal("error from signFn should propagate")
	}
}

func TestExternalSignerWrongSignatureSize(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	signFn := func(_ []byte) ([]byte, error) {
		return []byte("not-64-bytes"), nil
	}
	es, _ := NewExternalSigner("hsm", pub, signFn, nil)
	defer es.Close()
	if _, err := es.Sign([]byte("x")); err == nil {
		t.Fatal("wrong sig size should fail")
	}
}

func TestExternalSignerEmptyID(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := NewExternalSigner("", pub, func(b []byte) ([]byte, error) { return nil, nil }, nil); err == nil {
		t.Fatal("empty ID should fail")
	}
}

func TestExternalSignerNilSignFn(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := NewExternalSigner("id", pub, nil, nil); err == nil {
		t.Fatal("nil signFn should fail")
	}
}

// ============================================================================
// Verify signature (signer-agnostic)
// ============================================================================

func TestVerifySignatureSizes(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if VerifySignature(pub[:10], []byte("x"), make([]byte, 64)) {
		t.Error("short pub should not verify")
	}
	if VerifySignature(pub, []byte("x"), make([]byte, 10)) {
		t.Error("short sig should not verify")
	}
}

// ============================================================================
// Pluggability — different signers all satisfy Signer interface
// ============================================================================

func TestPluggability(t *testing.T) {
	// Build via different mechanisms, all yield Signer
	mem, _ := NewMemorySigner("mem")
	defer mem.Close()

	dir, _ := os.MkdirTemp("", "blrcs-kms-*")
	defer os.RemoveAll(dir)
	file, _ := NewFileSigner("file", filepath.Join(dir, "k"))
	defer file.Close()

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ext, _ := NewExternalSigner("ext", pub, func(p []byte) ([]byte, error) {
		return ed25519.Sign(priv, p), nil
	}, nil)
	defer ext.Close()

	signers := []Signer{mem, file, ext}
	for _, s := range signers {
		if s.ID() == "" {
			t.Errorf("signer has empty ID")
		}
		sig, err := s.Sign([]byte("payload"))
		if err != nil {
			t.Errorf("%s sign: %v", s.ID(), err)
			continue
		}
		if !VerifySignature(s.PublicKey(), []byte("payload"), sig) {
			t.Errorf("%s verify failed", s.ID())
		}
	}
}

// ============================================================================
// Coverage uplift: PrivateKey accessor, FileSigner error paths, ExternalSigner close
// ============================================================================

func TestMemorySignerPrivateKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := ImportMemorySigner("did:web:test", priv)
	got := s.PrivateKey()
	if string(got) != string(priv) {
		t.Error("PrivateKey() mismatch")
	}
}

func TestMemorySignerGenerate(t *testing.T) {
	s, err := NewMemorySigner("did:web:gen")
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello signer")
	sig, err := s.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(s.PublicKey(), msg, sig) {
		t.Error("generated signer signature invalid")
	}
}

func TestFileSignerReloadExisting(t *testing.T) {
	dir := t.TempDir()
	keyPath := dir + "/signer.key"
	s1, err := NewFileSigner("did:web:file1", keyPath)
	if err != nil {
		t.Fatal(err)
	}
	pub1 := s1.PublicKey()
	s1.Close()

	// Reload — must use same keys
	s2, err := NewFileSigner("did:web:file1", keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	pub2 := s2.PublicKey()
	if string(pub1) != string(pub2) {
		t.Error("reloaded key should match original")
	}
}

func TestFileSignerPrivateKey(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileSigner("did:web:fp", dir+"/fp.key")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	priv := s.PrivateKey()
	if len(priv) != ed25519.PrivateKeySize {
		t.Errorf("private key size: %d", len(priv))
	}
}

// ============================================================================
// ExternalSigner — full path coverage (validation, sign errors, close)
// ============================================================================

type fakeCloser struct{ closed bool }

func (f *fakeCloser) Close() error { f.closed = true; return nil }

func TestExternalSignerValidation(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signFn := func(p []byte) ([]byte, error) { return ed25519.Sign(priv, p), nil }

	// Empty ID
	if _, err := NewExternalSigner("", pub, signFn, nil); err == nil {
		t.Error("empty ID should error")
	}
	// Bad pubkey size
	if _, err := NewExternalSigner("id", []byte("short"), signFn, nil); err == nil {
		t.Error("bad pubkey should error")
	}
	// Nil sign function
	if _, err := NewExternalSigner("id", pub, nil, nil); err == nil {
		t.Error("nil signFn should error")
	}
}

func TestExternalSignerSignAndVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signFn := func(p []byte) ([]byte, error) { return ed25519.Sign(priv, p), nil }
	s, err := NewExternalSigner("did:web:ext", pub, signFn, nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("external-sign-test")
	sig, err := s.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(s.PublicKey(), msg, sig) {
		t.Error("external signature invalid")
	}
	if s.ID() != "did:web:ext" {
		t.Errorf("ID: %s", s.ID())
	}
}

func TestExternalSignerSignError(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	signFn := func(p []byte) ([]byte, error) { return nil, errors.New("HSM offline") }
	s, _ := NewExternalSigner("id", pub, signFn, nil)
	if _, err := s.Sign([]byte("x")); err == nil {
		t.Error("sign error should propagate")
	}
}

func TestExternalSignerWrongSigSize(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	signFn := func(p []byte) ([]byte, error) { return []byte("tooshort"), nil }
	s, _ := NewExternalSigner("id", pub, signFn, nil)
	if _, err := s.Sign([]byte("x")); err == nil {
		t.Error("wrong sig size should error")
	}
}

func TestExternalSignerCloseInvokesCloser(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signFn := func(p []byte) ([]byte, error) { return ed25519.Sign(priv, p), nil }
	fc := &fakeCloser{}
	s, _ := NewExternalSigner("id", pub, signFn, fc)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if !fc.closed {
		t.Error("Close should invoke the underlying closer")
	}
	// After close, Sign must fail
	if _, err := s.Sign([]byte("x")); err == nil {
		t.Error("sign after close should error")
	}
}
