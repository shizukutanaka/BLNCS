// Package vctmeta — SD-JWT-VC Type Metadata の解決と整合性検証
// (draft-ietf-oauth-sd-jwt-vc §Type Metadata)。
//
// credential の `vct` が https URL の場合、そこから Type Metadata (JSON) を取得し、
// credential の `vct#integrity` claim (W3C Subresource Integrity 形式) で真正性を
// 検証できる。integrity が一致すれば metadata は静的とみなし安全にキャッシュ可能。
//
// 注: JSON Schema 検証 (schema / schema_uri) は本パッケージの対象外
// (zero-dependency 方針のため別途バリデータが必要)。ここでは取得・整合性・
// メタデータ構造の取り出しまでを提供する。
package vctmeta

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"blrcs/jsonschema"
)

var (
	ErrNotHTTPS            = errors.New("vctmeta: vct is not an https URL")
	ErrIntegrityFormat     = errors.New("vctmeta: malformed integrity metadata")
	ErrIntegrityMismatch   = errors.New("vctmeta: type metadata integrity mismatch")
	ErrTooLarge            = errors.New("vctmeta: type metadata too large")
	ErrNoSchema            = errors.New("vctmeta: type metadata has no embedded schema")
	ErrExtendsChainTooDeep = errors.New("vctmeta: extends chain exceeds maximum depth")
	ErrExtendsCycle        = errors.New("vctmeta: extends chain contains a cycle")
)

const (
	maxMetadataBytes = 1 << 20 // 1 MiB
	maxExtendsDepth  = 8       // DoS guard on extends chain depth
)

// TypeMetadata — SD-JWT-VC Type Metadata ドキュメント。
type TypeMetadata struct {
	VCT                string          `json:"vct"`
	Name               string          `json:"name,omitempty"`
	Description        string          `json:"description,omitempty"`
	Extends            string          `json:"extends,omitempty"`
	ExtendsIntegrity   string          `json:"extends#integrity,omitempty"`
	Schema             json.RawMessage `json:"schema,omitempty"`
	SchemaURI          string          `json:"schema_uri,omitempty"`
	SchemaURIIntegrity string          `json:"schema_uri#integrity,omitempty"`
	Raw                []byte          `json:"-"` // 取得した生バイト (再ハッシュ/キャッシュ用)
}

// FetchFunc — URL から生バイトを取得する (HTTP / テスト差し替え)。
type FetchFunc func(ctx context.Context, url string) ([]byte, error)

// HTTPFetcher — https GET で Type Metadata を取得する FetchFunc。client が nil なら
// 10s タイムアウトの既定クライアントを使う。
func HTTPFetcher(client *http.Client) FetchFunc {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return func(ctx context.Context, url string) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("vctmeta: GET %s: status %d", url, resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, maxMetadataBytes+1))
	}
}

// VerifyIntegrity — data が integrity (W3C SRI: "sha256-<base64std>") に一致するか検証。
func VerifyIntegrity(data []byte, integrity string) error {
	alg, b64, found := strings.Cut(integrity, "-")
	if !found || alg != "sha256" || b64 == "" {
		return ErrIntegrityFormat
	}
	want, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return ErrIntegrityFormat
	}
	sum := sha256.Sum256(data)
	if subtle.ConstantTimeCompare(sum[:], want) != 1 {
		return ErrIntegrityMismatch
	}
	return nil
}

// Integrity — data に対する SRI 整合性文字列 ("sha256-<base64std>") を生成する。
// Type Metadata 発行者が vct#integrity 値を計算するのに使う。
func Integrity(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}

// Resolve — vct (https URL) から Type Metadata を取得する。
//
// expectedIntegrity が非空なら取得バイトを検証する (credential の vct#integrity を渡す)。
// fetch は呼び出し側が注入 (本番は HTTPFetcher、テストはインメモリ)。
func Resolve(ctx context.Context, vct, expectedIntegrity string, fetch FetchFunc) (*TypeMetadata, error) {
	if !strings.HasPrefix(vct, "https://") {
		return nil, ErrNotHTTPS
	}
	data, err := fetch(ctx, vct)
	if err != nil {
		return nil, err
	}
	if len(data) > maxMetadataBytes {
		return nil, ErrTooLarge
	}
	if expectedIntegrity != "" {
		if err := VerifyIntegrity(data, expectedIntegrity); err != nil {
			return nil, err
		}
	}
	var tm TypeMetadata
	if err := json.Unmarshal(data, &tm); err != nil {
		return nil, fmt.Errorf("vctmeta: parse: %w", err)
	}
	tm.Raw = data
	return &tm, nil
}

// HasSchema reports whether the Type Metadata carries an embedded `schema`.
func (tm *TypeMetadata) HasSchema() bool { return len(tm.Schema) > 0 }

// ValidateClaims validates a decoded SD-JWT-VC claim set against the Type
// Metadata's embedded `schema` (draft-ietf-oauth-sd-jwt-vc §Type Metadata).
//
// claims is the verified claim set (e.g. compliance.VerifiedClaims.Claims, a
// map[string]any). Reserved SD-JWT claims that the verifier already strips
// (`_sd`, `cnf`, …) are not the schema's concern. Returns ErrNoSchema when no
// embedded schema is present (callers that require one should check HasSchema).
//
// Note: only the embedded `schema` is validated here. `schema_uri` is a remote
// reference; fetch it with the resolver and pass it to ValidateClaimsWithSchema.
func (tm *TypeMetadata) ValidateClaims(claims map[string]any) error {
	if !tm.HasSchema() {
		return ErrNoSchema
	}
	return ValidateClaimsWithSchema(tm.Schema, claims)
}

// ValidateClaimsWithSchema validates a claim set against a JSON Schema document.
func ValidateClaimsWithSchema(schema json.RawMessage, claims map[string]any) error {
	s, err := jsonschema.Compile(schema)
	if err != nil {
		return fmt.Errorf("vctmeta: compile schema: %w", err)
	}
	return s.Validate(claims)
}

// ResolveSchema returns the JSON Schema document for this Type Metadata,
// preferring the embedded `schema` and otherwise fetching `schema_uri`.
//
// When `schema_uri` is used it MUST be an https URL; if `schema_uri#integrity`
// is present the fetched bytes are verified against it (W3C SRI) before use, so
// the schema can be trusted and cached. Returns ErrNoSchema when neither a
// `schema` nor a `schema_uri` is present.
func (tm *TypeMetadata) ResolveSchema(ctx context.Context, fetch FetchFunc) (json.RawMessage, error) {
	if tm.HasSchema() {
		return tm.Schema, nil
	}
	if tm.SchemaURI == "" {
		return nil, ErrNoSchema
	}
	if !strings.HasPrefix(tm.SchemaURI, "https://") {
		return nil, ErrNotHTTPS
	}
	data, err := fetch(ctx, tm.SchemaURI)
	if err != nil {
		return nil, err
	}
	if len(data) > maxMetadataBytes {
		return nil, ErrTooLarge
	}
	if tm.SchemaURIIntegrity != "" {
		if err := VerifyIntegrity(data, tm.SchemaURIIntegrity); err != nil {
			return nil, err
		}
	}
	return json.RawMessage(data), nil
}

// ResolveAndValidate resolves the schema (embedded or via `schema_uri`) and
// validates the claim set against it. It is the one-call path for verifiers that
// hold Type Metadata and a verified claim set.
func (tm *TypeMetadata) ResolveAndValidate(ctx context.Context, claims map[string]any, fetch FetchFunc) error {
	schema, err := tm.ResolveSchema(ctx, fetch)
	if err != nil {
		return err
	}
	return ValidateClaimsWithSchema(schema, claims)
}

// ResolveChain follows the `extends` links of a Type Metadata document and
// returns the full inheritance chain from the root (most-base type) to the
// leaf (the type requested by vct), in that order.
//
// Guards:
//   - ErrExtendsChainTooDeep if the chain exceeds maxExtendsDepth (DoS defense)
//   - ErrExtendsCycle if a URL appears twice (cycle detection)
//   - ErrNotHTTPS if any link in the chain is a non-https URL
//   - ErrTooLarge, ErrIntegrityMismatch from each Resolve call
//
// If vct has no `extends` the result is a single-element slice.
func ResolveChain(ctx context.Context, vct, expectedIntegrity string, fetch FetchFunc) ([]TypeMetadata, error) {
	seen := make(map[string]struct{})
	var chain []TypeMetadata
	cur, curIntegrity := vct, expectedIntegrity

	for {
		if len(chain) >= maxExtendsDepth {
			return nil, ErrExtendsChainTooDeep
		}
		if _, dup := seen[cur]; dup {
			return nil, ErrExtendsCycle
		}
		seen[cur] = struct{}{}

		tm, err := Resolve(ctx, cur, curIntegrity, fetch)
		if err != nil {
			return nil, err
		}
		chain = append(chain, *tm)

		if tm.Extends == "" {
			break
		}
		cur, curIntegrity = tm.Extends, tm.ExtendsIntegrity
	}

	// Reverse so index 0 is the most-base (root) type.
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain, nil
}
