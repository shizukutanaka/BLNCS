package tlsharden

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

// ============================================================================
// Modern config
// ============================================================================

func TestModernMinVersion(t *testing.T) {
	cfg := Modern()
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("min version: %x", cfg.MinVersion)
	}
	if cfg.MaxVersion != tls.VersionTLS13 {
		t.Errorf("max version: %x", cfg.MaxVersion)
	}
}

func TestModernAllowsTLS13(t *testing.T) {
	cfg := Modern()
	if !VerifyMinVersion(cfg, tls.VersionTLS12) {
		t.Error("Modern should accept TLS 1.2 min")
	}
}

func TestModernHasForwardSecrecy(t *testing.T) {
	cfg := Modern()
	if !HasForwardSecrecy(cfg) {
		t.Error("Modern config must have Forward Secrecy")
	}
}

func TestModernNoWeakCiphers(t *testing.T) {
	cfg := Modern()
	weakCiphers := []uint16{
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256, // Non-ECDHE
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	}
	for _, weak := range weakCiphers {
		for _, c := range cfg.CipherSuites {
			if c == weak {
				t.Errorf("weak cipher %x in Modern config", weak)
			}
		}
	}
}

func TestModernCipherSuitesAllAEAD(t *testing.T) {
	cfg := Modern()
	for _, c := range cfg.CipherSuites {
		// All cipher suites in Modern config should be GCM or ChaCha20-Poly1305
		switch c {
		case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:
			// OK
		default:
			t.Errorf("non-AEAD cipher in Modern: %x", c)
		}
	}
}

// ============================================================================
// Strict config (TLS 1.3 only)
// ============================================================================

func TestStrictMinVersion(t *testing.T) {
	cfg := Strict()
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("Strict min version: %x", cfg.MinVersion)
	}
	if cfg.MaxVersion != tls.VersionTLS13 {
		t.Errorf("Strict max version: %x", cfg.MaxVersion)
	}
}

func TestStrictHasForwardSecrecy(t *testing.T) {
	cfg := Strict()
	if !HasForwardSecrecy(cfg) {
		t.Error("Strict (TLS 1.3 only) must report Forward Secrecy")
	}
}

func TestStrictRejectsTLS12(t *testing.T) {
	cfg := Strict()
	if VerifyMinVersion(cfg, tls.VersionTLS12) && cfg.MinVersion < tls.VersionTLS13 {
		t.Error("Strict should require TLS 1.3")
	}
}

// ============================================================================
// Forward Secrecy detection
// ============================================================================

func TestHasForwardSecrecyDetectsBadCipher(t *testing.T) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, // OK
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,       // BAD: no FS
		},
	}
	if HasForwardSecrecy(cfg) {
		t.Error("config with non-ECDHE cipher should fail FS check")
	}
}

func TestHasForwardSecrecyOnNilConfig(t *testing.T) {
	if HasForwardSecrecy(nil) {
		t.Error("nil config should not have FS")
	}
}

// ============================================================================
// VerifyMinVersion edge cases
// ============================================================================

func TestVerifyMinVersionRejectsLowerMin(t *testing.T) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS10}
	if VerifyMinVersion(cfg, tls.VersionTLS12) {
		t.Error("TLS 1.0 should not satisfy TLS 1.2 minimum")
	}
}

func TestVerifyMinVersionAcceptsHigherMin(t *testing.T) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if !VerifyMinVersion(cfg, tls.VersionTLS12) {
		t.Error("TLS 1.3 should satisfy TLS 1.2 minimum")
	}
}

func TestVerifyMinVersionNilConfig(t *testing.T) {
	if VerifyMinVersion(nil, tls.VersionTLS12) {
		t.Error("nil config should not satisfy any minimum")
	}
}

// ============================================================================
// Curves
// ============================================================================

func TestModernIncludesX25519(t *testing.T) {
	cfg := Modern()
	found := false
	for _, c := range cfg.CurvePreferences {
		if c == tls.X25519 {
			found = true
		}
	}
	if !found {
		t.Error("Modern should include X25519")
	}
}

func TestStrictPrefersX25519(t *testing.T) {
	cfg := Strict()
	if cfg.CurvePreferences[0] != tls.X25519 {
		t.Errorf("Strict should prefer X25519, got %v", cfg.CurvePreferences[0])
	}
}

func TestMutualTLS(t *testing.T) {
	pool := x509.NewCertPool()
	cfg := MutualTLS(pool)
	if cfg == nil {
		t.Fatal("MutualTLS returned nil")
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth: got %v", cfg.ClientAuth)
	}
	if cfg.ClientCAs != pool {
		t.Error("ClientCAs not set")
	}
	// Must inherit Modern()'s min version
	if cfg.MinVersion < tls.VersionTLS12 {
		t.Errorf("MinVersion too low: %d", cfg.MinVersion)
	}
}
