// Package tlsharden — TLS設定強化ヘルパ
//
// 設計: Apple App Transport Security (ATS) + Mozilla SSL Configuration Generator
// "Modern" レベル相当の secure default を強制。
//
// 解決する短所:
//   - "TLS minimum version 強制無 — クライアント TLS 1.2/1.3 強制設定なし"
//
// Apple ATS 相当の制約:
//   - TLS 1.2 minimum (デフォルト推奨は 1.3)
//   - Forward Secrecy 必須 (ECDHE のみ)
//   - 古い cipher 禁止 (RC4, 3DES, CBC モード)
//   - 安全でない hash 禁止 (SHA-1)
//
// 利用例:
//
//	srv := &http.Server{
//	    Addr: ":8443",
//	    TLSConfig: tlsharden.Modern(),
//	    // または:
//	    TLSConfig: tlsharden.Strict(), // TLS 1.3 only
//	}
package tlsharden

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"time"
)

// ServerTimeouts — HTTP サーバのタイムアウト群 (slowloris / リソース枯渇防御)。
//
// 値 0 は「無制限」を意味する。SSE / 長時間ストリーミングを行うサーバは
// Write を 0 にすること (default は通常の request/response 用)。
type ServerTimeouts struct {
	ReadHeader time.Duration
	Read       time.Duration
	Write      time.Duration
	Idle       time.Duration
}

// DefaultTimeouts — 一般的な request/response サーバ向けの安全な既定値。
func DefaultTimeouts() ServerTimeouts {
	return ServerTimeouts{
		ReadHeader: 5 * time.Second,
		Read:       15 * time.Second,
		Write:      30 * time.Second,
		Idle:       120 * time.Second,
	}
}

// HardenedServer — DefaultTimeouts と 1MiB の MaxHeaderBytes を設定した
// *http.Server を返す。素の http.ListenAndServe(無タイムアウト) の代替。
func HardenedServer(addr string, h http.Handler) *http.Server {
	return HardenedServerWith(addr, h, DefaultTimeouts())
}

// HardenedServerWith — タイムアウトを明示指定して hardened *http.Server を返す。
func HardenedServerWith(addr string, h http.Handler, t ServerTimeouts) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: t.ReadHeader,
		ReadTimeout:       t.Read,
		WriteTimeout:      t.Write,
		IdleTimeout:       t.Idle,
		MaxHeaderBytes:    1 << 20, // 1 MiB
	}
}

// Modern — TLS 1.2 minimum, modern cipher suites
//
// Mozilla "Modern" config equivalent.
//   - Min version: TLS 1.2
//   - Preferred:   TLS 1.3
//   - Cipher: AEAD のみ (GCM/ChaCha20-Poly1305)
//   - Forward Secrecy: 必須 (ECDHE)
//
// 推奨: 一般的な production deployment
func Modern() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		// TLS 1.2 cipher suites (TLS 1.3 cipher suites are auto-handled)
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519,    // prefer X25519 first: fastest, no timing side-channel
			tls.CurveP256,
			tls.CurveP384,
		},
		// Session ticket keys are generated fresh per-process. In a multi-instance
		// deployment, tickets issued by one instance are rejected by another (different
		// key), causing spurious full handshakes. Disable tickets by default; callers
		// running a single-instance server can re-enable with:
		//   cfg.SessionTicketsDisabled = false
		SessionTicketsDisabled: true,
	}
}

// Strict — TLS 1.3 only — Apple iOS 16+ default
//
// 推奨: 内部 microservice、新規 API
//   - Min version: TLS 1.3
//   - Cipher は TLS 1.3 標準セット (Go 自動)
//   - 0-RTT 無効 (replay attack 防止)
func Strict() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		// TLS 1.3 ciphers are not configurable in Go (RFC compliance)
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
	}
}

// MutualTLS — クライアント証明書必須 (mTLS)
//
// パートナーAPI / 内部サービス間通信向け。
//   - clientCAs: 信頼する client CA pool (caller が x509.NewCertPool で構築)
func MutualTLS(clientCAs *x509.CertPool) *tls.Config {
	cfg := Modern()
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	cfg.ClientCAs = clientCAs
	return cfg
}

// VerifyMinVersion — runtime helper to verify a tls.Config meets min version
//
// 用途: 既存設定が secure default に合っているか CI/test で確認
func VerifyMinVersion(cfg *tls.Config, minimum uint16) bool {
	if cfg == nil {
		return false
	}
	return cfg.MinVersion >= minimum
}

// HasForwardSecrecy — cipher suites が ECDHE のみか確認
func HasForwardSecrecy(cfg *tls.Config) bool {
	if cfg == nil || len(cfg.CipherSuites) == 0 {
		// TLS 1.3 のみは Forward Secrecy 強制 → OK
		return cfg != nil && cfg.MinVersion >= tls.VersionTLS13
	}
	for _, c := range cfg.CipherSuites {
		if !isECDHE(c) {
			return false
		}
	}
	return true
}

// isECDHE — cipher suite が ECDHE 開始か (Forward Secrecy 確認)
func isECDHE(suite uint16) bool {
	switch suite {
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:
		return true
	}
	return false
}
