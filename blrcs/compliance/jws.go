package compliance

import (
	"crypto/ed25519"
	"sync"
)

// ============================================================================
// JWS algorithm agility — SD-JWT 発行者署名の `alg` を明示的に検証し、追加アルゴ
// (例: ML-DSA) を core 依存無しで差し込めるようにする。
//
// 既定では EdDSA (Ed25519) のみ対応。未知の `alg` (例: "none") は明示的に拒否し、
// algorithm-confusion を防ぐ。ポスト量子等を足す場合は RegisterJWSVerifier で
// 外部実装を登録する (BLRCS は zero-dependency を維持)。
// ============================================================================

// JWSVerifier — JWS の signing input (header.payload) を pub と sig で検証する。
type JWSVerifier func(pub, signingInput, sig []byte) bool

var (
	jwsMu        sync.RWMutex
	jwsVerifiers = map[string]JWSVerifier{"EdDSA": verifyEdDSA}
)

// RegisterJWSVerifier — SD-JWT 検証で追加の JWS `alg` を有効化する。
//
// BLRCS は EdDSA (Ed25519) のみ同梱。ML-DSA 等のポスト量子アルゴは外部実装を
// この関数で登録すれば、core 依存を増やさずに crypto-agility を得られる。
// 既存 alg ("EdDSA") の上書きも可能だが通常は不要。
func RegisterJWSVerifier(alg string, v JWSVerifier) {
	if alg == "" || v == nil {
		return
	}
	jwsMu.Lock()
	jwsVerifiers[alg] = v
	jwsMu.Unlock()
}

// lookupJWSVerifier — alg に対応する verifier を返す (無ければ ok=false)。
func lookupJWSVerifier(alg string) (JWSVerifier, bool) {
	jwsMu.RLock()
	v, ok := jwsVerifiers[alg]
	jwsMu.RUnlock()
	return v, ok
}

func verifyEdDSA(pub, msg, sig []byte) bool {
	return len(pub) == ed25519.PublicKeySize && ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}
