// Witness cosigning — split-view 攻撃の防御 (C2SP tlog-witness / RFC 6962 系)。
//
// log は新しい checkpoint を作るたびに witness へ「前回からの consistency proof」
// 付きで提示する。witness は (1) log 署名を検証し、(2) 自分が以前 cosign した
// checkpoint から append-only に発展していることを consistency proof で確認した
// 上でのみ副署する。これにより、log が relying party ごとに異なる履歴
// (split view) を見せることを検知・拒否できる。
package scitt

import (
	"crypto/ed25519"
	"encoding/base64"
	"sync"
)

// Cosignature — witness が特定 checkpoint に与える副署。
type Cosignature struct {
	WitnessID string `json:"witnessId"`
	Signature string `json:"sig"` // base64(std), checkpointSigPayload に対する署名
}

// Witness — append-only を検証して checkpoint に副署する独立エンティティ。
//
// log ごと (TSID 単位) に「最後に副署した checkpoint」を保持し、新しい
// checkpoint がそれと consistency proof で繋がる場合のみ副署する。
type Witness struct {
	id   string
	priv ed25519.PrivateKey
	mu   sync.Mutex
	seen map[string]Checkpoint // TSID → last cosigned checkpoint
}

// NewWitness — 副署鍵付き witness を構築。
func NewWitness(id string, priv ed25519.PrivateKey) *Witness {
	return &Witness{id: id, priv: priv, seen: make(map[string]Checkpoint)}
}

// ID — witness 識別子。
func (w *Witness) ID() string { return w.id }

// PublicKey — 副署検証用の公開鍵。
func (w *Witness) PublicKey() ed25519.PublicKey {
	return w.priv.Public().(ed25519.PublicKey)
}

// Cosign — log の checkpoint を検証し、append-only であれば副署を返す。
//
// tsPub: witness が信頼する log (TS) の公開鍵。
// consistencyProof: 同 log で前回副署した checkpoint から cp への RFC 6962
// consistency proof (初回、または前回サイズ 0 の場合は無視される)。
//
// 不整合 (split view) や tree size 後退は副署せず error を返す。
func (w *Witness) Cosign(cp Checkpoint, tsPub ed25519.PublicKey, consistencyProof [][]byte) (Cosignature, error) {
	if err := VerifyCheckpoint(cp, tsPub); err != nil {
		return Cosignature{}, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	if prev, ok := w.seen[cp.TSID]; ok {
		switch {
		case cp.TreeSize < prev.TreeSize:
			return Cosignature{}, ErrCheckpointRegression
		case cp.TreeSize == prev.TreeSize:
			// 同サイズなら root が一致しなければ split view。
			if cp.RootHash != prev.RootHash {
				return Cosignature{}, ErrSplitView
			}
		default: // cp.TreeSize > prev.TreeSize
			if prev.TreeSize > 0 {
				oldRoot, err := hexDecode(prev.RootHash)
				if err != nil {
					return Cosignature{}, ErrSplitView
				}
				newRoot, err := hexDecode(cp.RootHash)
				if err != nil {
					return Cosignature{}, ErrSplitView
				}
				if err := VerifyConsistency(prev.TreeSize, cp.TreeSize, oldRoot, newRoot, consistencyProof); err != nil {
					return Cosignature{}, ErrSplitView
				}
			}
		}
	}

	w.seen[cp.TSID] = cp
	sig := ed25519.Sign(w.priv, checkpointSigPayload(cp))
	return Cosignature{
		WitnessID: w.id,
		Signature: base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// VerifyCosignature — witness 副署を checkpoint に対して検証する。
func VerifyCosignature(cp Checkpoint, cs Cosignature, witnessPub ed25519.PublicKey) error {
	sig, err := base64.StdEncoding.DecodeString(cs.Signature)
	if err != nil {
		return ErrCheckpointSig
	}
	if len(witnessPub) != ed25519.PublicKeySize || !ed25519.Verify(witnessPub, checkpointSigPayload(cp), sig) {
		return ErrCheckpointSig
	}
	return nil
}
