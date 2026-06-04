package config

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := Default()
	if cfg.Listen != ":8080" {
		t.Errorf("listen: %s", cfg.Listen)
	}
	if cfg.TLSMode != "modern" {
		t.Errorf("tls mode: %s", cfg.TLSMode)
	}
	if cfg.RateLimitRPS != 100 {
		t.Errorf("rate limit: %d", cfg.RateLimitRPS)
	}
	if cfg.SessionTTL != 30*time.Minute {
		t.Errorf("session TTL: %v", cfg.SessionTTL)
	}
	if !cfg.SCITTEnabled {
		t.Error("SCITT should be enabled by default")
	}
	if cfg.WebhookRetries != 4 {
		t.Errorf("webhook retries: %d", cfg.WebhookRetries)
	}
}

func TestDefaultValidates(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Errorf("default config should validate: %v", err)
	}
}

func TestFromJSON(t *testing.T) {
	data := []byte(`{
		"listen": ":9090",
		"rateLimitRPS": 50,
		"dataDir": "/data",
		"issuerDID": "did:web:test"
	}`)
	cfg, err := FromJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":9090" {
		t.Errorf("listen: %s", cfg.Listen)
	}
	if cfg.RateLimitRPS != 50 {
		t.Errorf("rate limit: %d", cfg.RateLimitRPS)
	}
	if cfg.DataDir != "/data" {
		t.Errorf("data dir: %s", cfg.DataDir)
	}
	if cfg.IssuerDID != "did:web:test" {
		t.Errorf("issuer DID: %s", cfg.IssuerDID)
	}
	// Defaults preserved for unset fields
	if cfg.TLSMode != "modern" {
		t.Errorf("TLS mode should default: %s", cfg.TLSMode)
	}
}

func TestFromJSONBadInput(t *testing.T) {
	_, err := FromJSON([]byte("{bad json"))
	if err == nil {
		t.Fatal("bad JSON should fail")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	cfg := Default()
	cfg.IssuerDID = "did:web:roundtrip"
	cfg.AuthTokens = map[string]string{"tok1": "alice"}
	b, err := cfg.JSON()
	if err != nil {
		t.Fatal(err)
	}
	cfg2, err := FromJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	if cfg2.IssuerDID != cfg.IssuerDID {
		t.Errorf("roundtrip issuerDID: %s", cfg2.IssuerDID)
	}
	if cfg2.AuthTokens["tok1"] != "alice" {
		t.Error("auth tokens not preserved")
	}
}

func TestFromEnv(t *testing.T) {
	// Set env vars
	os.Setenv("BLRCS_LISTEN", ":9999")
	os.Setenv("BLRCS_DATA_DIR", "/tmp/blrcs-test")
	os.Setenv("BLRCS_AUTH_TOKENS", "tok1:alice,tok2:bob")
	os.Setenv("BLRCS_RATE_LIMIT_RPS", "200")
	os.Setenv("BLRCS_LOG_FORMAT", "json")
	os.Setenv("BLRCS_SESSION_TTL_SECONDS", "600")
	os.Setenv("BLRCS_SCITT_ENABLED", "false")
	os.Setenv("BLRCS_WEBHOOK_RETRIES", "2")
	defer func() {
		for _, k := range []string{
			"BLRCS_LISTEN", "BLRCS_DATA_DIR", "BLRCS_AUTH_TOKENS",
			"BLRCS_RATE_LIMIT_RPS", "BLRCS_LOG_FORMAT",
			"BLRCS_SESSION_TTL_SECONDS", "BLRCS_SCITT_ENABLED",
			"BLRCS_WEBHOOK_RETRIES",
		} {
			os.Unsetenv(k)
		}
	}()

	cfg := FromEnv()
	if cfg.Listen != ":9999" {
		t.Errorf("listen: %s", cfg.Listen)
	}
	if cfg.DataDir != "/tmp/blrcs-test" {
		t.Errorf("data dir: %s", cfg.DataDir)
	}
	if cfg.AuthTokens["tok1"] != "alice" || cfg.AuthTokens["tok2"] != "bob" {
		t.Errorf("auth tokens: %v", cfg.AuthTokens)
	}
	if cfg.RateLimitRPS != 200 {
		t.Errorf("rate limit: %d", cfg.RateLimitRPS)
	}
	if cfg.LogFormat != "json" {
		t.Errorf("log format: %s", cfg.LogFormat)
	}
	if cfg.SessionTTL != 600*time.Second {
		t.Errorf("session TTL: %v", cfg.SessionTTL)
	}
	if cfg.SCITTEnabled {
		t.Error("SCITT should be disabled")
	}
	if cfg.WebhookRetries != 2 {
		t.Errorf("webhook retries: %d", cfg.WebhookRetries)
	}
}

func TestValidation(t *testing.T) {
	cases := []struct {
		name   string
		modify func(c *Config)
		wantOK bool
	}{
		{"valid default", func(c *Config) {}, true},
		{"empty listen", func(c *Config) { c.Listen = "" }, false},
		{"cert without key", func(c *Config) { c.TLSCert = "cert.pem" }, false},
		{"key without cert", func(c *Config) { c.TLSKey = "key.pem" }, false},
		{"cert with key", func(c *Config) { c.TLSCert = "c"; c.TLSKey = "k" }, true},
		{"bad tls mode", func(c *Config) { c.TLSMode = "insecure" }, false},
		{"strict tls", func(c *Config) { c.TLSMode = "strict" }, true},
		{"bad log format", func(c *Config) { c.LogFormat = "xml" }, false},
		{"json log", func(c *Config) { c.LogFormat = "json" }, true},
		{"negative rate", func(c *Config) { c.RateLimitRPS = -1 }, false},
		{"zero rate (unlimited)", func(c *Config) { c.RateLimitRPS = 0 }, true},
		{"negative session", func(c *Config) { c.SessionTTL = -1 }, false},
		{"negative retries", func(c *Config) { c.WebhookRetries = -1 }, false},
	}
	for _, tc := range cases {
		cfg := Default()
		tc.modify(cfg)
		err := cfg.Validate()
		if tc.wantOK && err != nil {
			t.Errorf("%s: unexpected error: %v", tc.name, err)
		}
		if !tc.wantOK && err == nil {
			t.Errorf("%s: expected error", tc.name)
		}
	}
}

func TestHasTLS(t *testing.T) {
	cfg := Default()
	if cfg.HasTLS() {
		t.Error("default should not have TLS")
	}
	cfg.TLSCert = "cert.pem"
	cfg.TLSKey = "key.pem"
	if !cfg.HasTLS() {
		t.Error("should have TLS")
	}
}

func TestParseTokens(t *testing.T) {
	cases := []struct {
		input string
		want  int
	}{
		{"tok1:alice,tok2:bob", 2},
		{"single:user", 1},
		{"", 0},
		{"  ,  ,  ", 0},
		{"a:1, b:2, c:3", 3},
	}
	for _, c := range cases {
		got := parseTokens(c.input)
		if len(got) != c.want {
			t.Errorf("parseTokens(%q): got %d want %d", c.input, len(got), c.want)
		}
	}
}

func TestFromEnvTLSFields(t *testing.T) {
	os.Setenv("BLRCS_TLS_CERT", "/etc/tls/cert.pem")
	os.Setenv("BLRCS_TLS_KEY", "/etc/tls/key.pem")
	os.Setenv("BLRCS_TLS_MODE", "strict")
	os.Setenv("BLRCS_ISSUER_DID", "did:web:env.test")
	os.Setenv("BLRCS_SCITT_SIGNER_DID", "did:web:scitt.env")
	defer func() {
		for _, k := range []string{"BLRCS_TLS_CERT", "BLRCS_TLS_KEY", "BLRCS_TLS_MODE", "BLRCS_ISSUER_DID", "BLRCS_SCITT_SIGNER_DID"} {
			os.Unsetenv(k)
		}
	}()
	cfg := FromEnv()
	if cfg.TLSCert != "/etc/tls/cert.pem" {
		t.Errorf("tls cert: %s", cfg.TLSCert)
	}
	if cfg.TLSMode != "strict" {
		t.Errorf("tls mode: %s", cfg.TLSMode)
	}
	if cfg.IssuerDID != "did:web:env.test" {
		t.Errorf("issuer DID: %s", cfg.IssuerDID)
	}
	if cfg.SCITTSignerDID != "did:web:scitt.env" {
		t.Errorf("SCITT signer: %s", cfg.SCITTSignerDID)
	}
}

// suppress unused import warning
var _ = json.Marshal
var _ = strings.Contains
