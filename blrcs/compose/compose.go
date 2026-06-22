// Package compose — 横断統合レイヤ
//
// Apple SDK の "convenience initializers" 思想:
//
//	個別パッケージは小さく分離、しかし最終ユーザは単一の高レベル関数で全機能を
//	使える。1関数で didresolver/webhook/CAS/telemetry を縦断する。
//
// Apple SwiftUI の `@main` モディファイア相当 — 内部で全 framework を協調動作。
//
// 利用例:
//
//	c := compose.New(compose.Options{
//	    Issuer:    issuer,
//	    Resolver:  resolver,
//	    TrustAnchor: trustAnchor,
//	    Bus:       webhookBus,
//	    CAS:       casStore,
//	    Telemetry: telemetry.Default(),
//	})
//
//	// 1コール: 発行 + CAS保存 + webhook通知 + telemetry計装
//	cred, hash, err := c.IssueAndPublish(ctx, claim, "P-001", validFor)
//
//	// 1コール: DID resolve + verify
//	err := c.VerifyByDID(ctx, cred, "did:web:factory.example")
package compose

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"blrcs/cas"
	"blrcs/compliance"
	"blrcs/didresolver"
	"blrcs/errkit"
	"blrcs/scitt"
	"blrcs/telemetry"
	"blrcs/webhook"
)

// ============================================================================
// Composer — 統合API
// ============================================================================

// Options — Composer 構築オプション
type Options struct {
	Issuer      *compliance.Issuer       // 発行者 (Required for issue ops)
	Resolver    *didresolver.Resolver    // DID解決器 (Required for verify-by-DID)
	TrustAnchor *didresolver.TrustAnchor // 信頼アンカー (Required for verify-by-DID)
	Bus         *webhook.Bus             // Webhook (Optional; nil ならskip)
	CAS         cas.Store                // Content store (Optional; nil ならskip)
	Provenance  *cas.Provenance          // Provenance index (Optional)
	Ledger      *scitt.Ledger            // SCITT (Optional)
	Telemetry   *telemetry.Telemetry     // Optional, default 使用
}

// Composer — 統合された高レベルAPI
type Composer struct {
	opts Options
	tel  *telemetry.Telemetry
}

// New — Composer 構築
func New(opts Options) *Composer {
	tel := opts.Telemetry
	if tel == nil {
		tel = telemetry.Default()
	}
	return &Composer{opts: opts, tel: tel}
}

// ============================================================================
// IssueAndPublish — 発行 + CAS保存 + Webhook + SCITT登録
// ============================================================================

// IssuanceResult — 1コールの返り値
type IssuanceResult struct {
	Credential *compliance.Credential // 発行された VC
	Hash       cas.Hash               // payload の content hash (CAS有効時)
	Receipt    *scitt.Receipt         // SCITT receipt (Ledger有効時)
}

// IssueAndPublish — DPP発行と関連 side-effect を1コールで実行
//
// 段階:
//  1. compliance.Issue で credential 発行
//  2. CAS.Put で payload 保存 (重複なら no-op)
//  3. SCITT に register (provenance 紐付け)
//  4. webhook 発火 ("dpp.issued" イベント)
//  5. telemetry 計装
func (c *Composer) IssueAndPublish(
	ctx context.Context,
	claim compliance.PassportClaim,
	externalID string,
	validFor time.Duration,
) (*IssuanceResult, error) {
	if c.opts.Issuer == nil {
		return nil, errkit.E(errkit.OpDPPIssue, errkit.CodeInvalidInput, "Issuer required for IssueAndPublish", nil)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	span := c.tel.StartSpan(ctx, "compose.IssueAndPublish",
		slog.String("externalID", externalID),
		slog.String("productID", claim.ProductID),
	)
	defer span.End()

	// Step 1: Issue
	cred, err := c.opts.Issuer.Issue(claim, validFor)
	if err != nil {
		span.RecordError(err)
		return nil, err
	}
	res := &IssuanceResult{Credential: cred}

	// Step 2: CAS save (optional)
	// Marshal failure here means the Credential struct contains a non-serializable
	// field (e.g. a func or channel added in the future). Silently discarding the
	// error would cause CAS, Provenance, and SCITT to record nil/empty bytes —
	// a silent data loss that invalidates provenance integrity. Fail hard instead.
	credBytes, err := json.Marshal(cred)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("compose: marshal credential: %w", err)
	}
	if c.opts.CAS != nil {
		h, err := c.opts.CAS.Put(credBytes)
		if err == nil {
			res.Hash = h
			c.tel.Counter("compose.cas.stored").Inc()
		}
	}
	// Step 2b: Provenance index
	if c.opts.Provenance != nil && externalID != "" {
		_, err := c.opts.Provenance.Record(externalID, credBytes)
		if err == nil {
			c.tel.Counter("compose.provenance.recorded").Inc()
		}
	}

	// Step 3: SCITT register (optional)
	if c.opts.Ledger != nil {
		stmt, sErr := scitt.SignStatement(
			c.opts.Issuer.PrivateKey(),
			c.opts.Issuer.ID,
			claim.ProductID,
			"application/vc+json",
			credBytes,
		)
		if sErr == nil {
			r, regErr := c.opts.Ledger.Register(stmt)
			if regErr == nil {
				res.Receipt = r
				c.tel.Counter("compose.scitt.registered").Inc()
			}
		}
	}

	// Step 4: Webhook (background, non-blocking on failure)
	if c.opts.Bus != nil {
		eventData := map[string]any{
			"productID":  claim.ProductID,
			"externalID": externalID,
			"hash":       string(res.Hash),
			"issuer":     c.opts.Issuer.ID,
		}
		if res.Receipt != nil {
			eventData["leafIndex"] = res.Receipt.LeafIndex
		}
		// 別 ctx — caller の cancel が webhook 配信を止めないよう
		go func() {
			defer func() { _ = recover() }() // fire-and-forget safety
			detached, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_, _, _ = c.opts.Bus.Publish(detached, "dpp.issued", eventData)
		}()
	}
	c.tel.Counter("compose.issued").Inc()
	return res, nil
}

// ============================================================================
// VerifyByDID — DID解決 + 信頼チェック + 署名検証 を1コール
// ============================================================================

// VerifyByDID — issuer DID から自動的に公開鍵を解決し、信頼確認、署名検証
//
// 利用例:
//
//	err := c.VerifyByDID(ctx, cred, cred.Issuer)
func (c *Composer) VerifyByDID(ctx context.Context, cred *compliance.Credential, issuerDID string) error {
	if c.opts.Resolver == nil || c.opts.TrustAnchor == nil {
		return errkit.E(errkit.OpVPProcess, errkit.CodeInvalidInput, "Resolver and TrustAnchor required for VerifyByDID", nil)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	span := c.tel.StartSpan(ctx, "compose.VerifyByDID",
		slog.String("issuer", issuerDID),
	)
	defer span.End()

	// ローテーション対応: 信頼できる全鍵を解決し、いずれか1つで検証できれば成功。
	keys, err := didresolver.ResolveAndVerifyAll(ctx, c.opts.Resolver, c.opts.TrustAnchor, issuerDID)
	if err != nil {
		span.RecordError(err)
		c.tel.Counter("compose.verify.trustfail").Inc()
		return err
	}
	var verr error
	for _, pub := range keys {
		if verr = compliance.Verify(cred, pub); verr == nil {
			c.tel.Counter("compose.verify.ok").Inc()
			return nil
		}
	}
	span.RecordError(verr)
	c.tel.Counter("compose.verify.signaturefail").Inc()
	return verr
}

// VerifySDJWTByDID — SD-JWT 版
func (c *Composer) VerifySDJWTByDID(ctx context.Context, sdjwt, issuerDID string) (*compliance.VerifiedClaims, error) {
	if c.opts.Resolver == nil || c.opts.TrustAnchor == nil {
		return nil, errkit.E(errkit.OpSDJWTVerify, errkit.CodeInvalidInput, "Resolver and TrustAnchor required", nil)
	}
	// ローテーション対応: 信頼できる全鍵で順に検証を試みる。
	keys, err := didresolver.ResolveAndVerifyAll(ctx, c.opts.Resolver, c.opts.TrustAnchor, issuerDID)
	if err != nil {
		return nil, err
	}
	var vc *compliance.VerifiedClaims
	var verr error
	for _, pub := range keys {
		if vc, verr = compliance.VerifySDJWT(sdjwt, pub); verr == nil {
			return vc, nil
		}
	}
	return nil, verr
}

// ============================================================================
// Lookup helpers — Provenance ベースの調査
// ============================================================================

// LookupByExternalID — 外部 ID から credential を取得
func (c *Composer) LookupByExternalID(externalID string) (*compliance.Credential, cas.Hash, error) {
	if c.opts.Provenance == nil {
		return nil, "", errkit.E(errkit.OpStorageRead, errkit.CodeInvalidInput, "Provenance not configured", nil)
	}
	payload, h, err := c.opts.Provenance.LookupByID(externalID)
	if err != nil {
		return nil, "", err
	}
	var cred compliance.Credential
	if err := json.Unmarshal(payload, &cred); err != nil {
		return nil, h, err
	}
	return &cred, h, nil
}

// DiscoverServices — issuer DID の service endpoint を解決する。
//
// DPP データストアや status list の所在を発見するための高レベル経路
// (arXiv:2410.15758)。Resolver 未設定ならエラー。
func (c *Composer) DiscoverServices(ctx context.Context, issuerDID string) ([]didresolver.Service, error) {
	if c.opts.Resolver == nil {
		return nil, errkit.E(errkit.OpVPProcess, errkit.CodeInvalidInput, "Resolver required for DiscoverServices", nil)
	}
	return c.opts.Resolver.ResolveServices(ctx, issuerDID)
}
