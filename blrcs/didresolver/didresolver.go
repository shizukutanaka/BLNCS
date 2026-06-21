// Package didresolver — DID 解決 + Trust Anchor 管理
//
// 設計思想: Apple WebPKI のルート証明書プログラムと同水準の信頼アンカー管理。
//   - 信頼するルート issuer の allow-list (DID または鍵ハッシュ)
//   - did:web/did:key/did:jwk を public key に解決
//   - キャッシュ + TTL (rate-limit and resilience)
//   - Test isolation: HTTP fetch は injectable
//
// 用途:
//   - "この VC issuer を本当に信用できるか" を1関数で判定
//   - W3C VC verify の前段で issuer 公開鍵を取得
//   - OpenID4VP/VCI で AcceptableIssuers を動的構築
package didresolver

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// Errors
// ============================================================================

var (
	ErrUnsupportedMethod = errors.New("didresolver: unsupported DID method")
	ErrMalformedDID      = errors.New("didresolver: malformed DID")
	ErrFetchFailed       = errors.New("didresolver: fetch failed")
	ErrNoKey             = errors.New("didresolver: no usable public key in DID document")
	ErrNotTrusted        = errors.New("didresolver: DID not in trust anchor list")
	// ErrRedirectNotAllowed is returned when the default did:web fetcher receives
	// a 3xx response. The W3C did:web spec defines an exact well-known path
	// (`/.well-known/did.json` or `<path>/did.json`), so a legitimate server has
	// no reason to redirect. Following a redirect would let a malicious DID
	// document trigger SSRF: a 302 to `http://169.254.169.254/...` (cloud
	// metadata), `127.0.0.1`, or an attacker-chosen cross-origin target would be
	// fetched and parsed as "the issuer's DID document". The default fetcher
	// therefore refuses every 3xx via CheckRedirect.
	ErrRedirectNotAllowed = errors.New("didresolver: did:web fetch redirects are not permitted")
)

// ============================================================================
// Resolver
// ============================================================================

// defaultMaxCacheSize caps the number of DID entries the resolver keeps in
// memory. Each entry is ~64 bytes of DID string + a 32-byte public key slice.
// 4096 entries ≈ 1 MB — ample for any realistic DID graph while preventing
// unbounded growth when an attacker presents credentials from many distinct
// fake DID issuers.
const defaultMaxCacheSize = 4096

// Resolver — DID → ed25519 公開鍵の解決
//
// HTTPFetcher は test-injectable (HTTP モック / オフライン解決)
type Resolver struct {
	HTTPFetcher  func(ctx context.Context, url string) ([]byte, error)
	CacheTTL     time.Duration
	MaxCacheSize int // 0 → defaultMaxCacheSize

	mu    sync.RWMutex
	cache map[string]cacheEntry
}

func (r *Resolver) maxEntries() int {
	if r.MaxCacheSize > 0 {
		return r.MaxCacheSize
	}
	return defaultMaxCacheSize
}

type cacheEntry struct {
	keys      []ed25519.PublicKey
	expiresAt time.Time
}

// New — デフォルト解決器構築
func New() *Resolver {
	return &Resolver{
		HTTPFetcher: defaultHTTPFetch,
		CacheTTL:    1 * time.Hour,
		cache:       make(map[string]cacheEntry),
	}
}

// Resolve — DID 文字列 → ed25519.PublicKey
//
// サポート: did:web (HTTP fetch), did:key (公開鍵埋込), did:jwk (JWK 埋込)
func (r *Resolver) Resolve(ctx context.Context, did string) (ed25519.PublicKey, error) {
	keys, err := r.ResolveAll(ctx, did)
	if err != nil {
		return nil, err
	}
	return keys[0], nil
}

// ResolveAll — DID が公開するすべての Ed25519 鍵を解決する。
//
// DID document は複数の verification method を持ちうる (特に鍵ローテーション中は
// 旧鍵と新鍵が併存する)。Resolve は先頭鍵だけを返すため、先頭以外の鍵で署名された
// credential を検証できない。ローテーションを跨いで検証する呼び出し側は ResolveAll を
// 使い、信頼済みの各鍵で順に署名検証を試みる。
// did:key / did:jwk は単一鍵のため 1 要素のスライスを返す。
func (r *Resolver) ResolveAll(ctx context.Context, did string) ([]ed25519.PublicKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Cache check
	r.mu.RLock()
	if e, ok := r.cache[did]; ok && time.Now().Before(e.expiresAt) {
		r.mu.RUnlock()
		return e.keys, nil
	}
	r.mu.RUnlock()

	parts := strings.SplitN(did, ":", 3)
	if len(parts) != 3 || parts[0] != "did" {
		return nil, fmt.Errorf("%w: %q", ErrMalformedDID, did)
	}
	method, identifier := parts[1], parts[2]

	var keys []ed25519.PublicKey
	var err error
	switch method {
	case "key":
		var pub ed25519.PublicKey
		if pub, err = resolveDIDKey(identifier); err == nil {
			keys = []ed25519.PublicKey{pub}
		}
	case "jwk":
		var pub ed25519.PublicKey
		if pub, err = resolveDIDJWK(identifier); err == nil {
			keys = []ed25519.PublicKey{pub}
		}
	case "web":
		keys, err = r.resolveDIDWebAll(ctx, identifier)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedMethod, method)
	}
	if err != nil {
		return nil, err
	}

	// Cache — bounded write: purge expired entries if at capacity, then insert
	// only if there is room. Skipping the insert when full is safe: the next
	// caller simply re-fetches, which is correct (no data loss, no panic).
	r.mu.Lock()
	if len(r.cache) >= r.maxEntries() {
		now := time.Now()
		for k, e := range r.cache {
			if now.After(e.expiresAt) {
				delete(r.cache, k)
			}
		}
	}
	if len(r.cache) < r.maxEntries() {
		r.cache[did] = cacheEntry{keys: keys, expiresAt: time.Now().Add(r.CacheTTL)}
	}
	r.mu.Unlock()
	return keys, nil
}

// InvalidateCache — キャッシュ強制クリア (ローテーション後等)
func (r *Resolver) InvalidateCache(did string) {
	r.mu.Lock()
	delete(r.cache, did)
	r.mu.Unlock()
}

// Service — DID document の service endpoint (公開用)。
type Service struct {
	ID              string
	Type            string
	ServiceEndpoint string
}

// ResolveServices — did:web の DID document から service endpoint 群を取得。
//
// DPP データ所在の公示に使う (arXiv:2410.15758 §2.3)。did:key / did:jwk は
// service を持たないため空スライスを返す。
func (r *Resolver) ResolveServices(ctx context.Context, did string) ([]Service, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	parts := strings.SplitN(did, ":", 3)
	if len(parts) != 3 || parts[0] != "did" {
		return nil, fmt.Errorf("%w: %q", ErrMalformedDID, did)
	}
	if parts[1] != "web" {
		// did:key / did:jwk carry no service endpoints
		return nil, nil
	}
	body, err := r.HTTPFetcher(ctx, didWebURL(parts[2]))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFetchFailed, err)
	}
	var doc didDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("didresolver: parse DID document: %w", err)
	}
	out := make([]Service, 0, len(doc.Service))
	for _, s := range doc.Service {
		out = append(out, Service(s))
	}
	return out, nil
}

// ============================================================================
// did:web resolution
// ============================================================================

// resolveDIDWeb — did:web:example.com[:path] → https://example.com[/path]/.well-known/did.json
//
// W3C did:web spec: identifier はドメイン (+ オプショナル path)
//
//	did:web:example.com         → https://example.com/.well-known/did.json
//	did:web:example.com:user:1  → https://example.com/user/1/did.json
func (r *Resolver) resolveDIDWebAll(ctx context.Context, identifier string) ([]ed25519.PublicKey, error) {
	url := didWebURL(identifier)
	body, err := r.HTTPFetcher(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFetchFailed, err)
	}
	return parseDIDDocumentAll(body)
}

func didWebURL(identifier string) string {
	parts := strings.Split(identifier, ":")
	domain := parts[0]
	if len(parts) == 1 {
		return "https://" + domain + "/.well-known/did.json"
	}
	pathParts := parts[1:]
	return "https://" + domain + "/" + strings.Join(pathParts, "/") + "/did.json"
}

// parseDIDDocument — W3C DID Document から最初の Ed25519 鍵を抽出
type didDocument struct {
	ID                 string               `json:"id,omitempty"`
	VerificationMethod []verificationMethod `json:"verificationMethod"`
	Service            []serviceEndpoint    `json:"service,omitempty"`
}

// serviceEndpoint — W3C DID Core service entry.
//
// DPP のデータ所在公示に使う (arXiv:2410.15758 §2.3)。DID resolution は
// 公開鍵メタデータのみ返し credential 本体は含まないため、service endpoint
// 経由で DPP ストレージや status list の所在を示す。
type serviceEndpoint struct {
	ID              string `json:"id"`
	Type            string `json:"type"`            // 例: "DPPService", "LinkedDomains", "BitstringStatusList"
	ServiceEndpoint string `json:"serviceEndpoint"` // URL
}

type verificationMethod struct {
	ID                 string                 `json:"id"`
	Type               string                 `json:"type"`
	Controller         string                 `json:"controller"`
	PublicKeyMultibase string                 `json:"publicKeyMultibase,omitempty"`
	PublicKeyJwk       map[string]interface{} `json:"publicKeyJwk,omitempty"`
	PublicKeyBase58    string                 `json:"publicKeyBase58,omitempty"`
}

func parseDIDDocument(body []byte) (ed25519.PublicKey, error) {
	keys, err := parseDIDDocumentAll(body)
	if err != nil {
		return nil, err
	}
	return keys[0], nil
}

// parseDIDDocumentAll returns every Ed25519 verification-method key in the
// document, in document order, de-duplicated. A DID document legitimately lists
// several keys — most importantly during key rotation, where the old and new
// keys co-exist — so a verifier that only ever reads the first key cannot verify
// a credential signed by any of the others. Verification-method entries that are
// not Ed25519 (or fail to parse) are skipped, not fatal.
func parseDIDDocumentAll(body []byte) ([]ed25519.PublicKey, error) {
	var doc didDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("didresolver: parse DID document: %w", err)
	}
	var keys []ed25519.PublicKey
	seen := make(map[string]bool)
	add := func(pub ed25519.PublicKey) {
		k := string(pub)
		if seen[k] {
			return
		}
		seen[k] = true
		keys = append(keys, pub)
	}
	for _, vm := range doc.VerificationMethod {
		// Try JWK first
		if jwk := vm.PublicKeyJwk; jwk != nil {
			if pub, err := jwkToEd25519(jwk); err == nil {
				add(pub)
				continue
			}
		}
		// Fall back to multibase
		if mb := vm.PublicKeyMultibase; mb != "" {
			if pub, err := multibaseToEd25519(mb); err == nil {
				add(pub)
			}
		}
	}
	if len(keys) == 0 {
		return nil, ErrNoKey
	}
	return keys, nil
}

func jwkToEd25519(jwk map[string]interface{}) (ed25519.PublicKey, error) {
	kty, _ := jwk["kty"].(string)
	crv, _ := jwk["crv"].(string)
	x, _ := jwk["x"].(string)
	if kty != "OKP" || crv != "Ed25519" || x == "" {
		return nil, errors.New("not an Ed25519 OKP JWK")
	}
	b, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("Ed25519 key wrong size: %d", len(b))
	}
	return ed25519.PublicKey(b), nil
}

func multibaseToEd25519(s string) (ed25519.PublicKey, error) {
	if len(s) < 2 {
		return nil, errors.New("multibase too short")
	}
	// 'z' = base58btc per multibase RFC
	if s[0] == 'z' {
		return base58Ed25519Decode(s[1:])
	}
	// 'm' = base64 (multibase). MUST length-check: ed25519.Verify panics on a
	// wrong-length key, so an attacker-controlled did:web document with a short
	// base64 key would otherwise crash any verifier that resolves the issuer.
	if s[0] == 'm' {
		b, err := base64.RawStdEncoding.DecodeString(s[1:])
		if err != nil {
			return nil, err
		}
		// Strip an optional multicodec ed25519-pub prefix (0xed 0x01).
		if len(b) == 2+ed25519.PublicKeySize && b[0] == 0xed && b[1] == 0x01 {
			b = b[2:]
		}
		if len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("multibase Ed25519 key wrong size: %d", len(b))
		}
		return ed25519.PublicKey(b), nil
	}
	return nil, fmt.Errorf("unsupported multibase prefix: %c", s[0])
}

// ============================================================================
// did:key resolution
// ============================================================================

// resolveDIDKey — did:key:z6Mk... 形式 → Ed25519 公開鍵
//
// W3C did:key spec: multicodec 0xed (Ed25519) 0x01 (varint) prefix + 公開鍵
func resolveDIDKey(identifier string) (ed25519.PublicKey, error) {
	if len(identifier) < 2 {
		return nil, ErrMalformedDID
	}
	if identifier[0] != 'z' {
		return nil, fmt.Errorf("%w: did:key requires base58btc 'z' prefix", ErrMalformedDID)
	}
	decoded, err := base58Decode(identifier[1:])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedDID, err)
	}
	// Multicodec ed25519-pub: 0xed 0x01 followed by exactly 32 key bytes.
	// Require the EXACT length: accepting trailing bytes after the key would
	// silently truncate them, so the same key would be addressable by infinitely
	// many distinct did:key strings (identifier malleability). For a system where
	// the DID *is* the issuer identity, that breaks the 1:1 DID↔key invariant and
	// could be used to slip past DID allow/deny lists with a non-canonical form.
	if len(decoded) != 2+ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: did:key must be 2-byte multicodec + 32-byte key, got %d bytes", ErrMalformedDID, len(decoded))
	}
	if decoded[0] != 0xed || decoded[1] != 0x01 {
		return nil, fmt.Errorf("%w: not Ed25519 multicodec (got %x %x)", ErrMalformedDID, decoded[0], decoded[1])
	}
	pub := decoded[2:]
	return ed25519.PublicKey(pub), nil
}

func base58Ed25519Decode(s string) (ed25519.PublicKey, error) {
	decoded, err := base58Decode(s)
	if err != nil {
		return nil, err
	}
	// Strip multicodec if present. Require the EXACT 34-byte length (2-byte
	// prefix + 32-byte key): accepting trailing bytes would silently truncate
	// them, making one key addressable by many distinct multibase strings
	// (identifier malleability — see resolveDIDKey).
	if len(decoded) == 2+ed25519.PublicKeySize && decoded[0] == 0xed && decoded[1] == 0x01 {
		return ed25519.PublicKey(decoded[2:]), nil
	}
	if len(decoded) == ed25519.PublicKeySize {
		return ed25519.PublicKey(decoded), nil
	}
	return nil, fmt.Errorf("base58 decoded length %d unexpected", len(decoded))
}

// ============================================================================
// did:jwk resolution
// ============================================================================

// resolveDIDJWK — did:jwk:base64url(JSON) → Ed25519
func resolveDIDJWK(identifier string) (ed25519.PublicKey, error) {
	jsonBytes, err := base64.RawURLEncoding.DecodeString(identifier)
	if err != nil {
		return nil, fmt.Errorf("%w: bad base64url", ErrMalformedDID)
	}
	var jwk map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &jwk); err != nil {
		return nil, fmt.Errorf("%w: bad JSON", ErrMalformedDID)
	}
	return jwkToEd25519(jwk)
}

// ============================================================================
// Trust Anchor — Apple WebPKI ルートストア相当
// ============================================================================

// TrustAnchor — 信頼する DID のセット (allow-list)
//
// 鍵ハッシュ (SHA-256) でも DID 文字列でも検査可能。
type TrustAnchor struct {
	mu        sync.RWMutex
	dids      map[string]bool // exact DID match
	keyHashes map[string]bool // SHA-256 hex of public key
	allowAll  bool            // dev mode: 全許可 (本番禁止)
}

// NewTrustAnchor — 空の trust anchor
func NewTrustAnchor() *TrustAnchor {
	return &TrustAnchor{
		dids:      make(map[string]bool),
		keyHashes: make(map[string]bool),
	}
}

// AddDID — DID を信頼対象に登録
func (t *TrustAnchor) AddDID(did string) {
	t.mu.Lock()
	t.dids[did] = true
	t.mu.Unlock()
}

// AddKey — 公開鍵を信頼対象に登録 (DID別名対応)
func (t *TrustAnchor) AddKey(pub ed25519.PublicKey) {
	hash := sha256.Sum256(pub)
	t.mu.Lock()
	t.keyHashes[hex.EncodeToString(hash[:])] = true
	t.mu.Unlock()
}

// RemoveDID — DID を信頼対象から外す (鍵漏洩・ローテーション時の失効)。
//
// 信頼ストアが追加専用だと、漏洩・更新された issuer 鍵を永久に信頼し続けてしまう。
// 運用上、信頼判断は取り消せる必要がある。未登録の DID に対しては何もしない。
func (t *TrustAnchor) RemoveDID(did string) {
	t.mu.Lock()
	delete(t.dids, did)
	t.mu.Unlock()
}

// RemoveKey — 公開鍵を信頼対象から外す (鍵漏洩・ローテーション時の失効)。
// 未登録の鍵に対しては何もしない。
func (t *TrustAnchor) RemoveKey(pub ed25519.PublicKey) {
	hash := sha256.Sum256(pub)
	t.mu.Lock()
	delete(t.keyHashes, hex.EncodeToString(hash[:]))
	t.mu.Unlock()
}

// Reset — すべての信頼登録 (DID・鍵) と allowAll を一括クリアする。
//
// allowAll が誤って有効化された場合の「非常停止」、および大規模な信頼ストア
// 再構築時の出発点として使う。Reset 後はゼロ値の TrustAnchor と同じく
// 何も信頼しない (secure-by-default に戻る)。
func (t *TrustAnchor) Reset() {
	t.mu.Lock()
	t.dids = make(map[string]bool)
	t.keyHashes = make(map[string]bool)
	t.allowAll = false
	t.mu.Unlock()
}

// AllowAll — DEV/TEST のみ。本番では絶対呼ばないこと。
func (t *TrustAnchor) AllowAll() {
	t.mu.Lock()
	t.allowAll = true
	t.mu.Unlock()
}

// IsTrusted — DID と公開鍵が信頼ストアに登録されているか
func (t *TrustAnchor) IsTrusted(did string, pub ed25519.PublicKey) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.allowAll {
		return true
	}
	if t.dids[did] {
		return true
	}
	hash := sha256.Sum256(pub)
	return t.keyHashes[hex.EncodeToString(hash[:])]
}

// ResolveAndVerify — DID 解決 + Trust check を1コールで
//
// 戻り値:
//   - 成功: 公開鍵
//   - 解決失敗: ErrFetchFailed / ErrNoKey
//   - 信頼外: ErrNotTrusted
func ResolveAndVerify(ctx context.Context, r *Resolver, t *TrustAnchor, did string) (ed25519.PublicKey, error) {
	pub, err := r.Resolve(ctx, did)
	if err != nil {
		return nil, err
	}
	if !t.IsTrusted(did, pub) {
		return nil, fmt.Errorf("%w: %s", ErrNotTrusted, did)
	}
	return pub, nil
}

// ResolveAndVerifyAll — DID を解決し、信頼ストアに照合した「信頼できる鍵だけ」を返す。
//
// ローテーション対応: DID が複数鍵を公開する場合、そのうち trust anchor に登録された
// 鍵 (または DID 自体が信頼されていれば全鍵) を返す。呼び出し側は返った各鍵で署名検証を
// 試みればよい。信頼できる鍵が 1 つも無ければ ErrNotTrusted。
func ResolveAndVerifyAll(ctx context.Context, r *Resolver, t *TrustAnchor, did string) ([]ed25519.PublicKey, error) {
	keys, err := r.ResolveAll(ctx, did)
	if err != nil {
		return nil, err
	}
	trusted := make([]ed25519.PublicKey, 0, len(keys))
	for _, pub := range keys {
		if t.IsTrusted(did, pub) {
			trusted = append(trusted, pub)
		}
	}
	if len(trusted) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNotTrusted, did)
	}
	return trusted, nil
}

// ============================================================================
// Default HTTP fetcher
// ============================================================================

// defaultClient is the shared, SSRF-hardened HTTP client used by defaultHTTPFetch.
// It is built once: rebuilding per call costs an extra Transport allocation per
// resolution. CheckRedirect refuses every 3xx so a malicious did:web document
// cannot 302 the fetch into a private/loopback/metadata target.
var defaultClient = &http.Client{
	Timeout: 5 * time.Second,
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return ErrRedirectNotAllowed
	},
}

func defaultHTTPFetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/did+json, application/json")
	client := defaultClient
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64*1024))
}

// ============================================================================
// Base58 (Bitcoin alphabet) - minimal stdlib-only impl
// ============================================================================

const b58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58Decode(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	// Build inverse alphabet
	var inv [128]int8
	for i := range inv {
		inv[i] = -1
	}
	for i, c := range b58Alphabet {
		inv[byte(c)] = int8(i)
	}
	// Count leading '1's = leading zero bytes
	zeros := 0
	for i := 0; i < len(s) && s[i] == '1'; i++ {
		zeros++
	}
	// Decode big-endian via repeated multiply
	size := (len(s)*733)/1000 + 1 // approx ceil(log2(58)/8)
	b := make([]byte, size)
	length := 0
	for i := zeros; i < len(s); i++ {
		c := s[i]
		if c >= 128 || inv[c] == -1 {
			return nil, fmt.Errorf("base58: invalid char %q", c)
		}
		carry := int(inv[c])
		j := 0
		for k := size - 1; (carry != 0 || j < length) && k >= 0; k, j = k-1, j+1 {
			carry += 58 * int(b[k])
			b[k] = byte(carry % 256)
			carry /= 256
		}
		length = j
	}
	// skip leading zero bytes from oversized buffer
	skip := size - length
	out := make([]byte, zeros+length)
	for i := 0; i < length; i++ {
		out[zeros+i] = b[skip+i]
	}
	return out, nil
}
