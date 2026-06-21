// Package config — BLRCS 宣言的設定管理
//
// 設計: Apple Xcode .xcconfig / SwiftUI App struct 思想。
//   - 全設定項目を1構造体に集約
//   - 検証付きコンストラクタ (不正値は起動時拒否)
//   - 環境変数フォールバック (BLRCS_ prefix)
//   - JSON ファイル読込
//   - デフォルト値は sensible (本番で変えなくても安全に動く)
//
// 利用:
//
//	cfg := config.Default()
//	cfg, err := config.FromEnv()
//	cfg, err := config.FromJSON(data)
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config — BLRCS サーバ設定
type Config struct {
	// Network
	Listen  string `json:"listen"`  // ":8080"
	TLSCert string `json:"tlsCert"` // TLS証明書パス (空=HTTP)
	TLSKey  string `json:"tlsKey"`  // TLS鍵パス
	TLSMode string `json:"tlsMode"` // "modern" | "strict" | "" (default=modern)

	// Auth
	AuthTokens   map[string]string `json:"authTokens"`   // token → principal
	RateLimitRPS int               `json:"rateLimitRPS"` // 0=unlimited

	// Storage
	DataDir string `json:"dataDir"` // 永続化ディレクトリ ("" = memory-only)

	// Identity
	IssuerDID string `json:"issuerDID"` // DID of this instance

	// Telemetry
	LogFormat     string `json:"logFormat"`     // "text" | "json"
	MetricsPath   string `json:"metricsPath"`   // "/metrics"
	DashboardPath string `json:"dashboardPath"` // "/dashboard"

	// Session
	SessionTTL time.Duration `json:"sessionTTL"`

	// SCITT
	SCITTEnabled   bool   `json:"scittEnabled"`
	SCITTSignerDID string `json:"scittSignerDID"`

	// Webhook
	WebhookRetries int `json:"webhookRetries"` // default 4
}

// Default — 安全なデフォルト設定
//
// 変更なしで localhost 開発が動く、本番は環境変数で上書き
func Default() *Config {
	return &Config{
		Listen:         ":8080",
		TLSMode:        "modern",
		RateLimitRPS:   100,
		DataDir:        "",
		LogFormat:      "text",
		MetricsPath:    "/metrics",
		DashboardPath:  "/dashboard",
		SessionTTL:     30 * time.Minute,
		SCITTEnabled:   true,
		WebhookRetries: 4,
		AuthTokens:     map[string]string{},
	}
}

// FromEnv — 環境変数から設定読込 (BLRCS_ prefix)
//
// 環境変数:
//
//	BLRCS_LISTEN, BLRCS_TLS_CERT, BLRCS_TLS_KEY, BLRCS_TLS_MODE
//	BLRCS_AUTH_TOKENS (token1:principal1,token2:principal2)
//	BLRCS_RATE_LIMIT_RPS, BLRCS_DATA_DIR, BLRCS_ISSUER_DID
//	BLRCS_LOG_FORMAT, BLRCS_SESSION_TTL_SECONDS
//	BLRCS_SCITT_ENABLED, BLRCS_SCITT_SIGNER_DID
//	BLRCS_WEBHOOK_RETRIES
func FromEnv() (*Config, error) {
	cfg := Default()
	var errs []string
	atoiEnv := func(key string, set func(int)) {
		v := os.Getenv(key)
		if v == "" {
			return
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			// Fail fast instead of silently keeping the default — a malformed
			// BLRCS_RATE_LIMIT_RPS must not silently disable the rate limiter.
			errs = append(errs, fmt.Sprintf("%s=%q: not an integer", key, v))
			return
		}
		set(n)
	}
	if v := os.Getenv("BLRCS_LISTEN"); v != "" {
		cfg.Listen = v
	}
	if v := os.Getenv("BLRCS_TLS_CERT"); v != "" {
		cfg.TLSCert = v
	}
	if v := os.Getenv("BLRCS_TLS_KEY"); v != "" {
		cfg.TLSKey = v
	}
	if v := os.Getenv("BLRCS_TLS_MODE"); v != "" {
		cfg.TLSMode = v
	}
	if v := os.Getenv("BLRCS_AUTH_TOKENS"); v != "" {
		tokens, err := parseTokens(v)
		if err != nil {
			errs = append(errs, err.Error())
		} else {
			cfg.AuthTokens = tokens
		}
	}
	atoiEnv("BLRCS_RATE_LIMIT_RPS", func(n int) { cfg.RateLimitRPS = n })
	if v := os.Getenv("BLRCS_DATA_DIR"); v != "" {
		cfg.DataDir = v
	}
	if v := os.Getenv("BLRCS_ISSUER_DID"); v != "" {
		cfg.IssuerDID = v
	}
	if v := os.Getenv("BLRCS_LOG_FORMAT"); v != "" {
		cfg.LogFormat = v
	}
	atoiEnv("BLRCS_SESSION_TTL_SECONDS", func(n int) { cfg.SessionTTL = time.Duration(n) * time.Second })
	if v := os.Getenv("BLRCS_SCITT_ENABLED"); v != "" {
		cfg.SCITTEnabled = v == "true" || v == "1"
	}
	if v := os.Getenv("BLRCS_SCITT_SIGNER_DID"); v != "" {
		cfg.SCITTSignerDID = v
	}
	atoiEnv("BLRCS_WEBHOOK_RETRIES", func(n int) { cfg.WebhookRetries = n })
	if len(errs) > 0 {
		return nil, fmt.Errorf("config: invalid environment: %s", strings.Join(errs, "; "))
	}
	// Honor the documented "reject invalid values at startup" contract: run the
	// full cross-field/range validation. Without this a value that parses but is
	// out of range — e.g. BLRCS_RATE_LIMIT_RPS=-1 — would slip through and
	// silently DISABLE the rate limiter (NewRateLimiter treats rps<=0 as off),
	// the exact failure the per-field fail-fast above tries to prevent.
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// FromJSON — JSON データから設定読込
func FromJSON(data []byte) (*Config, error) {
	cfg := Default()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("config: parse: %w", err)
	}
	// Reject invalid values at load time (see FromEnv).
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate — 設定の整合性チェック
func (c *Config) Validate() error {
	if c.Listen == "" {
		return errors.New("config: listen address required")
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return errors.New("config: both tlsCert and tlsKey must be set, or neither")
	}
	switch c.TLSMode {
	case "", "modern", "strict":
	default:
		return fmt.Errorf("config: invalid tlsMode %q (use modern or strict)", c.TLSMode)
	}
	switch c.LogFormat {
	case "", "text", "json":
	default:
		return fmt.Errorf("config: invalid logFormat %q", c.LogFormat)
	}
	if c.RateLimitRPS < 0 {
		return errors.New("config: rateLimitRPS must be >= 0")
	}
	if c.SessionTTL < 0 {
		return errors.New("config: sessionTTL must be >= 0")
	}
	if c.WebhookRetries < 0 {
		return errors.New("config: webhookRetries must be >= 0")
	}
	return nil
}

// HasTLS — TLS 設定があるか
func (c *Config) HasTLS() bool {
	return c.TLSCert != "" && c.TLSKey != ""
}

// JSON — 設定を JSON に出力
func (c *Config) JSON() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}

// ============================================================================
// helpers
// ============================================================================

// parseTokens — "token1:principal1,token2:principal2" → map.
// Returns an error for any pair that does not contain the required ':' separator
// or that has an empty token part, so that misconfigured auth tokens are caught
// at startup instead of being silently dropped.
func parseTokens(s string) (map[string]string, error) {
	tokens := map[string]string{}
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) != 2 || parts[0] == "" {
			return nil, fmt.Errorf("config: malformed auth token pair %q (expected non-empty-token:principal)", pair)
		}
		tokens[parts[0]] = parts[1]
	}
	return tokens, nil
}
