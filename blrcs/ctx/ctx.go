// Package ctx — Context propagation layer
//
// Apple 原則: "All async operations must respect context cancellation."
// HealthKit, CoreData, Network.framework — 全て context/Task に対応。
//
// 問題: compliance / scitt / openid4vp 全パッケージが context を受けない。
// 解法: アダプタ層で context 対応ラッパを提供し、既存 API を破壊しない。
//
// 設計:
//   - 既存関数は変えない (backward compat 絶対)
//   - WithContext* 系関数で context 透過版を提供
//   - Telemetry span も context 経由で自動計測
//   - Deadline 超過 → context.DeadlineExceeded を返す
//   - Cancellation → context.Canceled を返す
//
// 使用例:
//
//	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
//	defer cancel()
//
//	cred, err := ctx_layer.IssuePassport(ctx, tel, issuer, claim, validFor)
//	receipt, err := ctx_layer.RegisterSCITT(ctx, tel, ledger, stmt)
package ctx

import (
	"context"
	"time"

	"blrcs/compliance"
	"blrcs/errkit"
	"blrcs/scitt"
	"blrcs/semconv"
	"blrcs/telemetry"
)

// ============================================================================
// compliance — context 対応ラッパ
// ============================================================================

// IssuePassport — context 対応 DPP 発行
//
// context キャンセル確認 → span 開始 → 署名 → span 終了
// Ed25519 署名は ~30μs なので timeout が短くても通常問題ない
func IssuePassport(
	ctx context.Context,
	tel *telemetry.Telemetry,
	issuer *compliance.Issuer,
	claim compliance.PassportClaim,
	validFor time.Duration,
) (*compliance.Credential, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tel == nil {
		tel = telemetry.Default()
	}
	span := tel.StartSpan(ctx, "compliance.IssuePassport",
		semconv.IssuerAttr(issuer.ID),
		semconv.ProductIDAttr(claim.ProductID),
	)
	cred, err := issuer.Issue(claim, validFor)
	if err != nil {
		span.RecordError(err)
		span.End()
		return nil, errkit.Wrap(errkit.OpDPPIssue, err)
	}
	span.End()
	return cred, nil
}

// VerifyPassport — context 対応 DPP 検証
func VerifyPassport(
	ctx context.Context,
	tel *telemetry.Telemetry,
	cred *compliance.Credential,
	pub []byte,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if tel == nil {
		tel = telemetry.Default()
	}
	span := tel.StartSpan(ctx, "compliance.VerifyPassport")
	err := compliance.Verify(cred, pub)
	if err != nil {
		span.RecordError(err)
		span.End()
		return errkit.Wrap(errkit.OpDPPVerify, err)
	}
	span.End()
	return nil
}

// IssueSDJWT — context 対応 SD-JWT 発行
func IssueSDJWT(
	ctx context.Context,
	tel *telemetry.Telemetry,
	issuer *compliance.Issuer,
	subject string,
	sdClaims, clearClaims map[string]any,
	validFor time.Duration,
) (string, []compliance.Disclosure, error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	if tel == nil {
		tel = telemetry.Default()
	}
	span := tel.StartSpan(ctx, "compliance.IssueSDJWT",
		semconv.IssuerAttr(issuer.ID),
		semconv.SubjectAttr(subject),
		semconv.SDClaimsCountAttr(len(sdClaims)),
	)
	sdjwt, disclosures, err := issuer.IssueSDJWT(subject, sdClaims, clearClaims, validFor)
	if err != nil {
		span.RecordError(err)
		span.End()
		return "", nil, errkit.Wrap(errkit.OpSDJWTIssue, err)
	}
	span.End()
	return sdjwt, disclosures, nil
}

// VerifySDJWT — context 対応 SD-JWT 検証
func VerifySDJWT(
	ctx context.Context,
	tel *telemetry.Telemetry,
	sdjwt string,
	pub []byte,
) (*compliance.VerifiedClaims, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tel == nil {
		tel = telemetry.Default()
	}
	span := tel.StartSpan(ctx, "compliance.VerifySDJWT")
	vc, err := compliance.VerifySDJWT(sdjwt, pub)
	if err != nil {
		span.RecordError(err)
		span.End()
		return nil, errkit.Wrap(errkit.OpSDJWTVerify, err)
	}
	span.End()
	return vc, nil
}

// AttestRange — context 対応 ZK 範囲証明
func AttestRange(
	ctx context.Context,
	tel *telemetry.Telemetry,
	attester *compliance.SensorAttester,
	value float64,
	salt []byte,
	stmt compliance.RangeStatement,
) (*compliance.RangeProof, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tel == nil {
		tel = telemetry.Default()
	}
	span := tel.StartSpan(ctx, "compliance.AttestRange",
		semconv.AttesterAttr(attester.ID),
		semconv.RangeNameAttr(stmt.Name),
	)
	commit := compliance.Commit(value, salt, stmt)
	proof, err := attester.Attest(commit, value)
	if err != nil {
		span.RecordError(err)
		span.End()
		return nil, errkit.Wrap(errkit.OpRangeAttest, err)
	}
	span.End()
	return proof, nil
}

// ============================================================================
// scitt — context 対応ラッパ
// ============================================================================

// RegisterSCITT — context 対応 SCITT 登録
//
// 重要: ledger.Register() は durable な append (commit) であり、いったん開始すると
// 中断できない。そのため context は「開始前」のキャンセルにのみ作用する: ctx が
// 既に done なら登録を開始せず err を返す。開始後の deadline 超過では登録は完了し、
// その Receipt を返す (途中キャンセルして「未登録」を装うと、リトライで台帳に
// 重複 leaf を生む — それを避けるための設計)。呼出側はタイトな deadline が必要なら
// 事前に十分な余裕を確保すること。
func RegisterSCITT(
	ctx context.Context,
	tel *telemetry.Telemetry,
	ledger *scitt.Ledger,
	stmt scitt.Statement,
) (*scitt.Receipt, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tel == nil {
		tel = telemetry.Default()
	}
	span := tel.StartSpan(ctx, "scitt.Register",
		semconv.IssuerAttr(stmt.Issuer),
		semconv.SubjectAttr(stmt.Subject),
	)
	defer span.End()
	// Register は中断不能なため同期実行する。goroutine+select で早期 return すると
	// 登録自体は裏で commit され、呼出側の「キャンセルされた」という認識と矛盾する。
	r, err := ledger.Register(stmt)
	if err != nil {
		span.RecordError(err)
	}
	return r, err
}

// SignAndRegister — 署名 + 登録を1コールで
// Apple 式: 複雑な2ステップを1メソッドに隠蔽
func SignAndRegister(
	ctx context.Context,
	tel *telemetry.Telemetry,
	ledger *scitt.Ledger,
	issuerPriv []byte,
	issuerID, subject, contentType string,
	payload []byte,
) (*scitt.Statement, *scitt.Receipt, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	stmt, err := scitt.SignStatement(issuerPriv, issuerID, subject, contentType, payload)
	if err != nil {
		return nil, nil, err
	}
	receipt, err := RegisterSCITT(ctx, tel, ledger, stmt)
	if err != nil {
		return nil, nil, err
	}
	return &stmt, receipt, nil
}
