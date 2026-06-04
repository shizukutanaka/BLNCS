package scitt

import "errors"

// Consistency proof — RFC 6962 §2.1.2 / COSE Receipts proof-of-consistency。
//
// ログが append-only であることを暗号学的に証明する。サイズ m の旧ツリーが
// サイズ n の新ツリーの prefix であることを、両 root hash とパスから検証可能。
// これが SCITT の non-equivocation 保証の核心 — 発行者が過去を書き換えて
// いないことを監査者が独立検証できる。

// ErrConsistency — consistency proof 検証失敗。
var ErrConsistency = errors.New("scitt: consistency proof verification failed")

// ConsistencyProof — サイズ m から n への append-only 証明 (m <= n)。
//
// idx 群でなくハッシュ列を返す (RFC 6962 PROOF(m, D[n])).
func (l *Ledger) ConsistencyProof(m, n uint64) ([][]byte, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if m > n || n > uint64(len(l.leafHashes)) {
		return nil, errors.New("scitt: invalid consistency range")
	}
	if m == 0 {
		return nil, nil // 空ツリーは任意ツリーの prefix
	}
	if m == n {
		return nil, nil // 同一サイズは自明
	}
	return subProof(m, l.leafHashes[:n], true), nil
}

// subProof — RFC 6962 §2.1.2 SUBPROOF(m, D[n], b)。
func subProof(m uint64, d [][]byte, b bool) [][]byte {
	n := uint64(len(d))
	if m == n {
		if b {
			return nil
		}
		return [][]byte{merkleRoot(d)}
	}
	k := uint64(largestPow2Below(int(n)))
	if m <= k {
		// 左部分木に降りる; 右部分木の root を path に追加
		path := subProof(m, d[:k], b)
		return append(path, merkleRoot(d[k:]))
	}
	// 右部分木に降りる; 左部分木の root を path に追加
	path := subProof(m-k, d[k:], false)
	return append(path, merkleRoot(d[:k]))
}

// VerifyConsistency — consistency proof を検証 (RFC 6962 §2.1.4)。
//
// oldRoot (サイズ m) と newRoot (サイズ n) が同一の append-only ツリーに
// 属することを path で検証する。
func VerifyConsistency(m, n uint64, oldRoot, newRoot []byte, proof [][]byte) error {
	if m > n {
		return ErrConsistency
	}
	if m == n {
		if !equalBytes(oldRoot, newRoot) {
			return ErrConsistency
		}
		if len(proof) != 0 {
			return ErrConsistency
		}
		return nil
	}
	if m == 0 {
		// 空の旧ツリーは常に consistent (proof 不要)
		return nil
	}

	// RFC 6962 §2.1.4 検証アルゴリズム
	// m が 2 のべきなら oldRoot を seed に補う
	proofArr := proof
	if isPow2(m) {
		proofArr = append([][]byte{oldRoot}, proof...)
	}

	fn, sn := m-1, n-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}

	if len(proofArr) == 0 {
		return ErrConsistency
	}
	fr := proofArr[0]
	sr := proofArr[0]

	for _, c := range proofArr[1:] {
		if sn == 0 {
			return ErrConsistency
		}
		if fn&1 == 1 || fn == sn {
			fr = hashNode(c, fr)
			sr = hashNode(c, sr)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = hashNode(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}

	if !equalBytes(fr, oldRoot) {
		return ErrConsistency
	}
	if !equalBytes(sr, newRoot) {
		return ErrConsistency
	}
	if sn != 0 {
		return ErrConsistency
	}
	return nil
}

func isPow2(x uint64) bool {
	return x != 0 && x&(x-1) == 0
}

// Root — 現在のツリーの root hash (consistency proof の入力用)。
func (l *Ledger) Root() []byte {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return merkleRoot(l.leafHashes)
}
