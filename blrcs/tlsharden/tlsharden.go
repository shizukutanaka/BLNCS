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
)

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
			tls.CurveP256,
			tls.X25519,
			tls.CurveP384,
		},
		// Disable session tickets in cluster scenarios where keys aren't shared
		// (caller can override if they manage rotation)
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
