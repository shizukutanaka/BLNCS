// Package errkit — BLRCS の構造化エラー
//
// Apple の LocalizedError + Swift Error enum + Go errors.Is/As を統合。
//
// 設計目標:
//   - 種別 (Code) で分岐可能 — switch エラー時に有用
//   - 操作チェイン (Op) — どのレイヤで失敗したか追跡
//   - 公開安全 messeage と内部詳細を分離 — 機密漏洩防止
//   - Retryable / Permanent 識別 — クライアント側で自動リトライ判定可能
//   - errors.Is, errors.As 標準互換
//
// 利用例:
//
//	if err := store.Save(); err != nil {
//	    return errkit.E(errkit.OpStorageWrite, errkit.CodeIO, "failed to persist", err)
//	}
//
//	var e *errkit.Error
//	if errors.As(err, &e) && e.Code == errkit.CodeUnauthorized {
//	    // 401 を返す
//	}
package errkit

import (
	"errors"
	"fmt"
	"strings"
)

// Code — エラー分類 (Apple URLError.Code 相当)
type Code string

const (
	CodeUnknown      Code = "unknown"
	CodeInvalidInput Code = "invalid_input" // 4xx-class
	CodeNotFound     Code = "not_found"     // 404
	CodeUnauthorized Code = "unauthorized"  // 401
	CodeForbidden    Code = "forbidden"     // 403
	CodeConflict     Code = "conflict"      // 409
	CodeRateLimited  Code = "rate_limited"  // 429
	CodeIO           Code = "io"            // 5xx 一過性
	CodeIntegrity    Code = "integrity"     // 検証失敗 / 改ざん検知
	CodeSecurity     Code = "security"      // 鍵/署名 系
	CodeUnsupported  Code = "unsupported"   // 機能未対応
	CodeInternal     Code = "internal"      // バグ
	CodeTimeout      Code = "timeout"       // タイムアウト
	CodeNetwork      Code = "network"       // ネット失敗
)

// Op — 操作識別 (どのレイヤで失敗したか)
//
// 文字列だが const 集中管理で typo 防止 + grep 容易化
type Op string

const (
	// Compliance / DPP
	OpDPPIssue     Op = "compliance.IssueDPP"
	OpDPPVerify    Op = "compliance.VerifyDPP"
	OpSDJWTIssue   Op = "compliance.IssueSDJWT"
	OpSDJWTVerify  Op = "compliance.VerifySDJWT"
	OpSDJWTPresent Op = "compliance.PresentSDJWT"
	OpRangeAttest  Op = "compliance.RangeAttest"
	OpRangeVerify  Op = "compliance.RangeVerify"

	// Storage
	OpStorageOpen   Op = "storage.Open"
	OpStorageWrite  Op = "storage.Write"
	OpStorageRead   Op = "storage.Read"
	OpStorageReplay Op = "storage.Replay"

	// SCITT
	OpScittRegister Op = "scitt.Register"
	OpScittReceipt  Op = "scitt.Receipt"

	// OpenID4VP / VCI
	OpVPCreateRequest Op = "openid4vp.CreateRequest"
	OpVPProcess       Op = "openid4vp.Process"
	OpVCIOffer        Op = "vci.CreateOffer"
	OpVCIIssue        Op = "vci.Issue"
	OpVCIToken        Op = "vci.Exchange"

	// MCP
	OpMCPDispatch Op = "mcp.Dispatch"

	// DC-API
	OpDCAPIBuild Op = "dcapi.Build"
	OpDCAPIParse Op = "dcapi.Parse"
)

// Error — BLRCS 共通エラー型
//
// PublicMessage は API レスポンスや UI 表示用の安全文字列 (機密含まない)。
// Detail は server-side ログのみで使用。
type Error struct {
	Op            Op     // 操作
	Code          Code   // 分類
	PublicMessage string // 公開安全 (i18n 可能)
	Detail        string // 内部詳細 (機密含む可能性、ログのみ)
	Retryable     bool   // クライアントが再試行すべきか
	Wrapped       error  // 原因
}

// Error — fmt.Stringer / error 実装
//
// 形式: "{Op}: {PublicMessage}: {Detail} (cause: {wrapped})"
func (e *Error) Error() string {
	var b strings.Builder
	if e.Op != "" {
		b.WriteString(string(e.Op))
		b.WriteString(": ")
	}
	if e.PublicMessage != "" {
		b.WriteString(e.PublicMessage)
	} else {
		b.WriteString(string(e.Code))
	}
	if e.Detail != "" && e.Detail != e.PublicMessage {
		b.WriteString(": ")
		b.WriteString(e.Detail)
	}
	if e.Wrapped != nil {
		b.WriteString(" (cause: ")
		b.WriteString(e.Wrapped.Error())
		b.WriteString(")")
	}
	return b.String()
}

// Unwrap — errors.Unwrap 互換
func (e *Error) Unwrap() error { return e.Wrapped }

// Is — errors.Is 互換: Code 一致で true
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	if t.Code != "" && e.Code != t.Code {
		return false
	}
	if t.Op != "" && e.Op != t.Op {
		return false
	}
	return true
}

// PublicError — UI / API 応答用、機密を漏らさない短文
func (e *Error) PublicError() string {
	if e.PublicMessage != "" {
		return e.PublicMessage
	}
	return string(e.Code)
}

// HTTPStatus — HTTP ステータスへのマッピング
func (e *Error) HTTPStatus() int {
	switch e.Code {
	case CodeInvalidInput:
		return 400
	case CodeUnauthorized:
		return 401
	case CodeForbidden:
		return 403
	case CodeNotFound:
		return 404
	case CodeConflict:
		return 409
	case CodeRateLimited:
		return 429
	case CodeTimeout:
		return 408
	case CodeUnsupported:
		return 501
	case CodeIO, CodeNetwork, CodeInternal:
		return 500
	case CodeIntegrity, CodeSecurity:
		return 400
	}
	return 500
}

// ============================================================================
// Constructors — Apple 流の expressive 構築
// ============================================================================

// E — 一般構築。最後の引数群は wrapped error を許容
//
//	errkit.E(errkit.OpDPPIssue, errkit.CodeInvalidInput, "productId required", nil)
//	errkit.E(errkit.OpStorageWrite, errkit.CodeIO, "fsync failed", err)
func E(op Op, code Code, publicMsg string, cause error) *Error {
	return &Error{
		Op:            op,
		Code:          code,
		PublicMessage: publicMsg,
		Wrapped:       cause,
	}
}

// EWithDetail — 内部詳細付き
func EWithDetail(op Op, code Code, publicMsg, detail string, cause error) *Error {
	return &Error{
		Op:            op,
		Code:          code,
		PublicMessage: publicMsg,
		Detail:        detail,
		Wrapped:       cause,
	}
}

// Wrap — 既存エラーを構造化エラーに昇格 (op追加のみ)
func Wrap(op Op, err error) error {
	if err == nil {
		return nil
	}
	if e, ok := err.(*Error); ok {
		// 既に構造化されている → op を chain
		return &Error{
			Op:            op,
			Code:          e.Code,
			PublicMessage: e.PublicMessage,
			Detail:        e.Detail,
			Retryable:     e.Retryable,
			Wrapped:       e,
		}
	}
	return &Error{
		Op:            op,
		Code:          CodeUnknown,
		PublicMessage: "internal error",
		Wrapped:       err,
	}
}

// Retryable — 一過性 (network, IO timeout) を retryable に
func Retryable(op Op, code Code, publicMsg string, cause error) *Error {
	e := E(op, code, publicMsg, cause)
	e.Retryable = true
	return e
}

// IsRetryable — errors chain を辿って retryable フラグを検査
func IsRetryable(err error) bool {
	var e *Error
	if errors.As(err, &e) {
		return e.Retryable
	}
	return false
}

// CodeOf — errors chain から Code を取得
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return CodeUnknown
}

// Is sentinel constructors for switch comparisons
//
//	if errors.Is(err, errkit.NotFound()) { ... }
//
// これにより種別の switch / Is 比較が自然になる
func NotFound() error     { return &Error{Code: CodeNotFound} }
func Unauthorized() error { return &Error{Code: CodeUnauthorized} }
func Forbidden() error    { return &Error{Code: CodeForbidden} }
func InvalidInput() error { return &Error{Code: CodeInvalidInput} }
func Conflict() error     { return &Error{Code: CodeConflict} }
func RateLimited() error  { return &Error{Code: CodeRateLimited} }
func Integrity() error    { return &Error{Code: CodeIntegrity} }
func Security() error     { return &Error{Code: CodeSecurity} }
func Timeout() error      { return &Error{Code: CodeTimeout} }
func Internal() error     { return &Error{Code: CodeInternal} }

// LogLine — log/slog などへの 1行表現
//
// 機密 (Detail) を含むので server log のみで使う
func (e *Error) LogLine() string {
	return fmt.Sprintf("op=%s code=%s msg=%q detail=%q retryable=%v cause=%v",
		e.Op, e.Code, e.PublicMessage, e.Detail, e.Retryable, e.Wrapped)
}
