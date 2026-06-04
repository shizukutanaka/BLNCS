// Public Merkle helpers for conformance test suites.
// Exposes RFC 6962 leaf/node hashing without leaking other internals.
package scitt

// HashLeaf — RFC 6962 leaf hash: SHA256(0x00 || data)
// 公開用: コンフォーマンステストスイートでの参照値計算
func HashLeaf(data []byte) []byte { return hashLeaf(data) }

// HashNode — RFC 6962 internal node hash: SHA256(0x01 || left || right)
func HashNode(left, right []byte) []byte { return hashNode(left, right) }

// MerkleRootForTest — leaf hash 配列からルート計算 (RFC 6962)
// 公開: テストベクトル検証用
func MerkleRootForTest(leaves [][]byte) []byte { return merkleRoot(leaves) }
