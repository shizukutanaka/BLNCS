// Package scitt — IETF Supply Chain Integrity, Transparency, and Trust
//
// 準拠: draft-ietf-scitt-architecture (2026年安定版)
// RFC 6962 式 Merkle ツリーでの append-only 透明性ログ
//
// 用途:
//   - DPP発行の全記録
//   - 配送イベントの不変監査証跡
//   - MCPツール呼出の完全トレース
//
// 設計:
//   - スレッドセーフ (単一ミューテックス、読取りロック最小化)
//   - 永続化は外部Storage契約経由 (KV/SQL/S3差替可能)
//   - Merkle hash: RFC 6962 (leaf 0x00, internal 0x01 prefix)
package scitt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"blrcs/storage"
)

var (
	ErrNotFound        = errors.New("scitt: statement not found")
	ErrBadReceipt      = errors.New("scitt: receipt invalid")
	ErrBadProof        = errors.New("scitt: inclusion proof invalid")
	ErrEmptyStmt       = errors.New("scitt: statement payload required")
	ErrPayloadTooLarge = errors.New("scitt: statement payload exceeds size limit")
	// ErrStatementMalformed is returned by SignStatement when required fields are
	// missing or the private key has the wrong length. A well-formed statement
	// must carry a non-empty Issuer, Subject, ContentType, and a valid private key.
	ErrStatementMalformed = errors.New("scitt: statement malformed")
	// ErrUntrustedIssuer is returned by Register when a trusted-issuer policy is
	// configured (via RegisterTrustedIssuer) and the submitted statement's Issuer
	// is not in the allowlist, or the embedded IssuerKey does not match the
	// registered key for the claimed issuer ID.
	//
	// Without this guard VerifyStatement only proves that the signature is
	// consistent with the embedded IssuerKey — it does NOT prove that the
	// embedded key belongs to the entity named in the Issuer field. An attacker
	// who calls SignStatement with their own private key and sets Issuer to a
	// legitimate DID passes VerifyStatement: the signature is valid against their
	// key, and their key is embedded in the statement. The result is an
	// attestation-forgery: the log would contain a verified-looking statement
	// from a DID the attacker does not control.
	ErrUntrustedIssuer = errors.New("scitt: issuer not in trusted-issuer allowlist")

	// Checkpoint / witness cosigning
	ErrCheckpointSig        = errors.New("scitt: checkpoint signature invalid")
	ErrCheckpointRegression = errors.New("scitt: checkpoint tree size went backwards")
	ErrSplitView            = errors.New("scitt: checkpoint inconsistent with witness history (split view)")
)

// Statement — SCITT Signed Statement (COSE/JSON簡易版)
//
// 完全COSE_Sign1実装は重い。実用上JSON+Ed25519で十分な保証。
// 将来: COSE変換層を追加可能、契約不変。
type Statement struct {
	Issuer      string    `json:"issuer"`      // DID
	Subject     string    `json:"subject"`     // 対象ID (productId, shipmentId等)
	ContentType string    `json:"cty"`         // "application/vc+json" 等
	PayloadHash string    `json:"payloadHash"` // hex sha256
	IssuedAt    time.Time `json:"iat"`
	Signature   string    `json:"sig"`       // base64
	IssuerKey   string    `json:"issuerKey"` // base64 ed25519 pub
}

// Receipt — 登録受領証 (ledger位置 + 包含証明 + TS署名)
type Receipt struct {
	LeafIndex    uint64    `json:"leafIndex"`
	TreeSize     uint64    `json:"treeSize"`
	RootHash     string    `json:"rootHash"`  // hex
	AuditPath    []string  `json:"auditPath"` // hex hashes, leaf→root
	TSSignature  string    `json:"tsSig"`     // base64 — Transparency Serviceの署名
	TSKey        string    `json:"tsKey"`     // base64 ed25519 pub
	RegisteredAt time.Time `json:"regAt"`
}

// ============================================================================
// Merkle tree — RFC 6962準拠
// ============================================================================

const (
	leafPrefix byte = 0x00
	nodePrefix byte = 0x01
)

// maxStatementPayloadBytes caps the payload accepted by SignStatement. A DPP/
// Battery Passport payload (JSON-LD, SD-JWT-VC claims) is typically under 64 KiB;
// 1 MiB provides generous headroom while preventing unbounded SHA-256 work and
// downstream ledger storage exhaustion by an authenticated-but-misbehaving issuer.
const maxStatementPayloadBytes = 1 << 20 // 1 MiB

func hashLeaf(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{leafPrefix})
	h.Write(data)
	return h.Sum(nil)
}

func hashNode(l, r []byte) []byte {
	h := sha256.New()
	h.Write([]byte{nodePrefix})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}

// merkleRoot — O(n) で現在のルートを計算
// 大規模本番ではキャッシュ付きインクリメンタル更新に置換推奨
func merkleRoot(leaves [][]byte) []byte {
	n := len(leaves)
	if n == 0 {
		return sha256.New().Sum(nil)
	}
	if n == 1 {
		return leaves[0]
	}
	// 最大2のべきで分割 (RFC 6962式)
	k := largestPow2Below(n)
	return hashNode(merkleRoot(leaves[:k]), merkleRoot(leaves[k:]))
}

func largestPow2Below(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

// auditPath — leaf index に対する包含証明パス生成
func auditPath(leaves [][]byte, idx int) [][]byte {
	n := len(leaves)
	if n <= 1 {
		return nil
	}
	k := largestPow2Below(n)
	if idx < k {
		return append(auditPath(leaves[:k], idx), merkleRoot(leaves[k:]))
	}
	return append(auditPath(leaves[k:], idx-k), merkleRoot(leaves[:k]))
}

// VerifyInclusion — leaf が root に含まれることをpathで検証
func VerifyInclusion(leafHash, rootHash []byte, idx, size uint64, path [][]byte) bool {
	if idx >= size {
		return false
	}
	node := leafHash
	i, n := idx, size
	for _, p := range path {
		if n == 0 {
			return false
		}
		if i&1 == 1 || i+1 == n {
			node = hashNode(p, node)
			for i&1 == 0 {
				i >>= 1
				n = (n + 1) >> 1
			}
		} else {
			node = hashNode(node, p)
		}
		i >>= 1
		n = (n + 1) >> 1
	}
	// 残り上方ノードがない = root
	return subtle.ConstantTimeCompare(node, rootHash) == 1
}

// ============================================================================
// Transparency Service — ledger本体
// ============================================================================

// Ledger — transparency service本体。永続化はStorage層で差替可能。
type Ledger struct {
	mu         sync.RWMutex
	leafHashes [][]byte
	cached     []Statement
	store      storage.Storage
	tsPriv     ed25519.PrivateKey
	tsPub      ed25519.PublicKey
	tsID       string

	// trustedIssuers is the optional issuer allowlist: issuerID → authorised
	// Ed25519 public key. When non-empty, Register enforces that every submitted
	// statement's Issuer ID appears in the map and its IssuerKey matches the
	// registered key. When empty the ledger is in open mode (any issuer accepted).
	trustedIssuers map[string]ed25519.PublicKey

	// Secondary indexes for lifecycle search (CEN-CENELEC EN 18222): map a
	// statement's Subject (productId/batteryId) and Issuer (manufacturer DID) to
	// the leaf indices carrying them, so FindBySubject/FindByIssuer answer
	// "all passports for product X / manufacturer Y" without scanning the whole
	// ledger. Maintained under l.mu on Register and rebuilt during replay.
	bySubject map[string][]uint64
	byIssuer  map[string][]uint64

	// subtreeCache memoizes the hashes of completed perfect subtrees, keyed by
	// (offset, size) with size a power of two. Such subtrees are immutable in an
	// append-only log, so entries never need invalidation. This turns the per-
	// append root/audit-path computation from O(n) into O(log n) amortized,
	// avoiding the O(n²) cost of building a large log. (Reference funcs
	// merkleRoot/auditPath remain for verification and as a correctness oracle.)
	subtreeCache sync.Map // map[[2]int][]byte
}

// perfectSubtree returns the Merkle root of the immutable perfect subtree
// covering leaves [off, off+size) where size is a power of two, memoizing it.
func (l *Ledger) perfectSubtree(off, size int) []byte {
	if size == 1 {
		return l.leafHashes[off]
	}
	key := [2]int{off, size}
	if v, ok := l.subtreeCache.Load(key); ok {
		return v.([]byte)
	}
	half := size / 2
	h := hashNode(l.perfectSubtree(off, half), l.perfectSubtree(off+half, half))
	l.subtreeCache.Store(key, h)
	return h
}

// cachedRoot computes the RFC 6962 root over the first n leaves using the
// perfect-subtree cache. Identical result to merkleRoot(l.leafHashes[:n]).
func (l *Ledger) cachedRoot(n int) []byte {
	if n == 0 {
		return sha256.New().Sum(nil)
	}
	return l.cachedSubtreeRoot(0, n)
}

func (l *Ledger) cachedSubtreeRoot(off, n int) []byte {
	if n == 1 {
		return l.leafHashes[off]
	}
	k := largestPow2Below(n)
	return hashNode(l.perfectSubtree(off, k), l.cachedSubtreeRoot(off+k, n-k))
}

// cachedAuditPath returns the inclusion path for leaf idx within the first n
// leaves, using the perfect-subtree cache. Identical to auditPath(leaves[:n], idx).
func (l *Ledger) cachedAuditPath(idx, n int) [][]byte {
	return l.cachedAuditPathAbs(0, idx, n)
}

// cachedAuditPathAbs mirrors the reference auditPath but uses absolute leaf
// offsets so it can consult the perfect-subtree cache. idx is relative to off;
// it operates over leaves[off : off+n).
func (l *Ledger) cachedAuditPathAbs(off, idx, n int) [][]byte {
	if n <= 1 {
		return nil
	}
	k := largestPow2Below(n)
	if idx < k {
		return append(l.cachedAuditPathAbs(off, idx, k), l.cachedSubtreeRoot(off+k, n-k))
	}
	return append(l.cachedAuditPathAbs(off+k, idx-k, n-k), l.perfectSubtree(off, k))
}

// NewLedger — 揮発版 (後方互換)。メモリstorageを内部使用。
func NewLedger(tsID string) (*Ledger, error) {
	return NewLedgerWithStorage(tsID, storage.NewMemoryStorage())
}

// NewLedgerWithStorage — storageに紐付いたledger。起動時に状態を復元。
// 存在すれば keypair を復元、なければ生成して保存。
// 全 statement を replay して Merkle leaves を再構築、同時に全署名を再検証。
func NewLedgerWithStorage(tsID string, store storage.Storage) (*Ledger, error) {
	if tsID == "" {
		return nil, errors.New("transparency service ID required")
	}
	l := &Ledger{
		store:     store,
		tsID:      tsID,
		bySubject: make(map[string][]uint64),
		byIssuer:  make(map[string][]uint64),
	}

	pub, priv, err := store.LoadKeyPair()
	switch {
	case errors.Is(err, storage.ErrNotFound):
		pub, priv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		if err := store.SaveKeyPair(pub, priv); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, fmt.Errorf("load keypair: %w", err)
	}
	l.tsPub, l.tsPriv = pub, priv

	if err := store.IterateStatements(func(idx uint64, blob json.RawMessage) error {
		var stmt Statement
		if err := json.Unmarshal(blob, &stmt); err != nil {
			return fmt.Errorf("replay at idx %d: %w", idx, err)
		}
		if err := VerifyStatement(&stmt); err != nil {
			return fmt.Errorf("replay bad sig at idx %d: %w", idx, err)
		}
		l.indexStatementLocked(stmt, idx)
		l.cached = append(l.cached, stmt)
		l.leafHashes = append(l.leafHashes, hashLeaf(blob))
		return nil
	}); err != nil {
		return nil, err
	}
	return l, nil
}

// indexStatementLocked records a statement's Subject/Issuer in the secondary
// indexes. The caller must hold l.mu (Register) or be single-threaded (replay
// during construction). Empty Subject/Issuer are not indexed (nothing to
// search on).
func (l *Ledger) indexStatementLocked(stmt Statement, idx uint64) {
	if stmt.Subject != "" {
		l.bySubject[stmt.Subject] = append(l.bySubject[stmt.Subject], idx)
	}
	if stmt.Issuer != "" {
		l.byIssuer[stmt.Issuer] = append(l.byIssuer[stmt.Issuer], idx)
	}
}

// Close — 下層storageを閉じる
func (l *Ledger) Close() error {
	return l.store.Close()
}

func (l *Ledger) PublicKey() ed25519.PublicKey { return l.tsPub }
func (l *Ledger) TSID() string                 { return l.tsID }

// RegisterTrustedIssuer adds an (issuerID, publicKey) entry to the ledger's
// trusted-issuer allowlist. Once at least one entry is registered, Register
// enforces that every submitted statement's Issuer ID is present in the map
// and its embedded IssuerKey matches the registered public key for that ID.
// Call at startup before accepting statements from external parties.
func (l *Ledger) RegisterTrustedIssuer(issuerID string, pub ed25519.PublicKey) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.trustedIssuers == nil {
		l.trustedIssuers = make(map[string]ed25519.PublicKey)
	}
	l.trustedIssuers[issuerID] = pub
}

// SignStatement — 発行者が自分のSigned Statementを作成
// issuerPub は checkpointに埋込用 (後で検索可能)
func SignStatement(issuerPriv ed25519.PrivateKey, issuerID, subject, contentType string, payload []byte) (Statement, error) {
	if len(issuerPriv) != ed25519.PrivateKeySize {
		return Statement{}, fmt.Errorf("%w: bad private key length", ErrStatementMalformed)
	}
	if issuerID == "" {
		return Statement{}, fmt.Errorf("%w: missing issuer", ErrStatementMalformed)
	}
	if subject == "" {
		return Statement{}, fmt.Errorf("%w: missing subject", ErrStatementMalformed)
	}
	if contentType == "" {
		return Statement{}, fmt.Errorf("%w: missing content-type", ErrStatementMalformed)
	}
	if len(payload) == 0 {
		return Statement{}, ErrEmptyStmt
	}
	if len(payload) > maxStatementPayloadBytes {
		return Statement{}, fmt.Errorf("%w: %d bytes (limit %d)", ErrPayloadTooLarge, len(payload), maxStatementPayloadBytes)
	}
	h := sha256.Sum256(payload)
	stmt := Statement{
		Issuer:      issuerID,
		Subject:     subject,
		ContentType: contentType,
		PayloadHash: fmt.Sprintf("%x", h[:]),
		IssuedAt:    time.Now().UTC(),
		IssuerKey:   base64.StdEncoding.EncodeToString(issuerPriv.Public().(ed25519.PublicKey)),
	}
	sigPayload, err := statementSigPayload(&stmt)
	if err != nil {
		return Statement{}, err
	}
	stmt.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(issuerPriv, sigPayload))
	return stmt, nil
}

// statementSigPayload builds the bytes a statement's signature covers.
//
// It returns an error rather than discarding one. The discarded form was an
// integrity hazard, not a style issue: json.Marshal fails on a time.Time whose
// year falls outside [0,9999], and the old code then signed and verified over
// nil — so every statement carrying such a timestamp shared one signing
// payload, leaving issuer, subject and payloadHash unauthenticated. Reachable
// in-process (time.Now().AddDate(100000, 0, 0)), though not over the wire,
// since Go's RFC 3339 parser rejects expanded years.
func statementSigPayload(s *Statement) ([]byte, error) {
	// 決定的: 署名対象フィールドを固定順JSON化
	b, err := json.Marshal(struct {
		I   string    `json:"i"`
		Sub string    `json:"s"`
		Cty string    `json:"c"`
		Ph  string    `json:"p"`
		Iat time.Time `json:"t"`
		Ik  string    `json:"k"`
	}{s.Issuer, s.Subject, s.ContentType, s.PayloadHash, s.IssuedAt, s.IssuerKey})
	if err != nil {
		return nil, fmt.Errorf("scitt: encode statement signing payload: %w", err)
	}
	return b, nil
}

// VerifyStatement — 発行者署名検証
func VerifyStatement(s *Statement) error {
	pub, err := base64.StdEncoding.DecodeString(s.IssuerKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("scitt: bad issuer key")
	}
	sig, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil {
		return errors.New("scitt: bad sig encoding")
	}
	sigPayload, err := statementSigPayload(s)
	if err != nil {
		// Fail closed: a statement whose signing payload cannot be built is
		// unverifiable, never verified.
		return fmt.Errorf("%w: %v", ErrStatementMalformed, err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), sigPayload, sig) {
		return ErrBadReceipt
	}
	return nil
}

// Register — Signed Statement を ledger に登録、Receipt を返す
// 書込順: storage耐久化 → in-memory Merkle更新 → Receipt署名
func (l *Ledger) Register(stmt Statement) (*Receipt, error) {
	if err := VerifyStatement(&stmt); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	// Trusted-issuer policy: when the allowlist is non-empty, the submitted
	// statement's Issuer must be registered AND its embedded IssuerKey must
	// match the registered public key. VerifyStatement (above) only proves that
	// the signature is consistent with IssuerKey — it does not prove that IssuerKey
	// belongs to the entity named in Issuer. Without this check any party can
	// register statements as any issuer by embedding their own key.
	if len(l.trustedIssuers) > 0 {
		want, ok := l.trustedIssuers[stmt.Issuer]
		if !ok {
			return nil, fmt.Errorf("%w: %q not registered", ErrUntrustedIssuer, stmt.Issuer)
		}
		got, err := base64.StdEncoding.DecodeString(stmt.IssuerKey)
		if err != nil || subtle.ConstantTimeCompare(got, want) != 1 {
			return nil, fmt.Errorf("%w: IssuerKey mismatch for %q", ErrUntrustedIssuer, stmt.Issuer)
		}
	}

	raw, err := json.Marshal(stmt)
	if err != nil {
		return nil, err
	}
	// storage永続化 (fsync) を先に。失敗時はin-memory状態変更なし
	idx, err := l.store.AppendStatement(raw)
	if err != nil {
		return nil, fmt.Errorf("storage append: %w", err)
	}
	leaf := hashLeaf(raw)
	if idx != uint64(len(l.leafHashes)) {
		return nil, fmt.Errorf("ledger: storage/memory desync idx=%d mem=%d", idx, len(l.leafHashes))
	}
	l.indexStatementLocked(stmt, idx)
	l.cached = append(l.cached, stmt)
	l.leafHashes = append(l.leafHashes, leaf)

	size := uint64(len(l.leafHashes))
	root := l.cachedRoot(int(size))
	pathBytes := l.cachedAuditPath(int(idx), int(size))
	pathHex := make([]string, len(pathBytes))
	for i, p := range pathBytes {
		pathHex[i] = fmt.Sprintf("%x", p)
	}

	receipt := &Receipt{
		LeafIndex:    idx,
		TreeSize:     size,
		RootHash:     fmt.Sprintf("%x", root),
		AuditPath:    pathHex,
		TSKey:        base64.StdEncoding.EncodeToString(l.tsPub),
		RegisteredAt: time.Now().UTC(),
	}
	sigPayload := receiptSigPayload(receipt)
	receipt.TSSignature = base64.StdEncoding.EncodeToString(ed25519.Sign(l.tsPriv, sigPayload))
	return receipt, nil
}

func receiptSigPayload(r *Receipt) []byte {
	buf := make([]byte, 0, 128)
	buf = append(buf, []byte(r.RootHash)...)
	var b [16]byte
	binary.BigEndian.PutUint64(b[0:8], r.LeafIndex)
	binary.BigEndian.PutUint64(b[8:16], r.TreeSize)
	buf = append(buf, b[:]...)
	buf = append(buf, []byte(r.RegisteredAt.Format(time.RFC3339Nano))...)
	return buf
}

// VerifyReceipt — TS署名検証 + 包含証明検証
// 検証には登録時のstatementが必要 (監査用)
func VerifyReceipt(r *Receipt, stmt Statement, tsPub ed25519.PublicKey) error {
	// ed25519.Verify panics on a wrong-length key (ed25519.PublicKey is a named
	// []byte, so the compiler permits one). Fail closed rather than crash.
	if len(tsPub) != ed25519.PublicKeySize {
		return ErrBadReceipt
	}
	sig, err := base64.StdEncoding.DecodeString(r.TSSignature)
	if err != nil {
		return ErrBadReceipt
	}
	if !ed25519.Verify(tsPub, receiptSigPayload(r), sig) {
		return ErrBadReceipt
	}
	// leaf再構築
	raw, err := json.Marshal(stmt)
	if err != nil {
		return err
	}
	leaf := hashLeaf(raw)
	root, err := hexDecode(r.RootHash)
	if err != nil {
		return ErrBadReceipt
	}
	// Reject before allocating: a valid RFC 6962 audit path for a 2^63-leaf tree
	// has at most 63 hashes; anything larger is malformed or a memory-exhaustion
	// attempt against VerifyReceipt callers.
	const maxAuditPathLen = 64
	if len(r.AuditPath) > maxAuditPathLen {
		return ErrBadReceipt
	}
	path := make([][]byte, len(r.AuditPath))
	for i, p := range r.AuditPath {
		b, err := hexDecode(p)
		if err != nil {
			return ErrBadReceipt
		}
		path[i] = b
	}
	if !VerifyInclusion(leaf, root, r.LeafIndex, r.TreeSize, path) {
		return ErrBadProof
	}
	return nil
}

func hexDecode(s string) ([]byte, error) {
	n := len(s)
	if n%2 != 0 {
		return nil, errors.New("odd hex length")
	}
	b := make([]byte, n/2)
	for i := 0; i < n; i += 2 {
		hi, err := hexChar(s[i])
		if err != nil {
			return nil, err
		}
		lo, err := hexChar(s[i+1])
		if err != nil {
			return nil, err
		}
		b[i/2] = hi<<4 | lo
	}
	return b, nil
}

func hexChar(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, fmt.Errorf("bad hex char %q", c)
}

// ============================================================================
// Public ledger queries
// ============================================================================

// Size — 現在のleaf数
func (l *Ledger) Size() uint64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return uint64(len(l.leafHashes))
}

// Checkpoint — 署名済みtree head (モニター/gossip用)
type Checkpoint struct {
	TreeSize  uint64    `json:"size"`
	RootHash  string    `json:"root"`
	Timestamp time.Time `json:"ts"`
	TSID      string    `json:"tsId"`
	Signature string    `json:"sig"`
}

func (l *Ledger) SignedCheckpoint() Checkpoint {
	l.mu.RLock()
	defer l.mu.RUnlock()
	n := len(l.leafHashes)
	root := l.cachedRoot(n) // O(log n) amortised; merkleRoot would be O(n) per call
	cp := Checkpoint{
		TreeSize:  uint64(len(l.leafHashes)),
		RootHash:  fmt.Sprintf("%x", root),
		Timestamp: time.Now().UTC(),
		TSID:      l.tsID,
	}
	cp.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(l.tsPriv, checkpointSigPayload(cp)))
	return cp
}

// checkpointSigPayload — checkpoint に対する署名/副署の正規バイト列。
//
// domain-tag ‖ TSID ‖ rootHash ‖ treeSize ‖ timestamp を、各可変長フィールドを
// 4-byte 長さ前置きして連結する (連結の曖昧性排除)。
//
// TSID (log / Transparency Service の識別子 = checkpoint の "origin") を必ず
// 署名対象に含めることが重要: witness の split-view 防御は cp.TSID 単位で
// lineage を追跡する (w.seen[cp.TSID]) ため、TSID が署名で束縛されないと、
// 正しく署名された checkpoint を別 log の TSID に張り替えても VerifyCheckpoint を
// 通過してしまい、per-log の追跡が破壊される。C2SP / RFC 6962 の checkpoint も
// origin 行を署名本体に含めるのと同じ理由。
func checkpointSigPayload(cp Checkpoint) []byte {
	buf := make([]byte, 0, 64+len(cp.TSID)+len(cp.RootHash))
	buf = appendLenPrefixed(buf, []byte("blrcs-checkpoint-v1")) // domain separation
	buf = appendLenPrefixed(buf, []byte(cp.TSID))
	buf = appendLenPrefixed(buf, []byte(cp.RootHash))
	var sz [8]byte
	binary.BigEndian.PutUint64(sz[:], cp.TreeSize)
	buf = append(buf, sz[:]...)
	buf = appendLenPrefixed(buf, []byte(cp.Timestamp.Format(time.RFC3339Nano)))
	return buf
}

// appendLenPrefixed appends a 4-byte big-endian length followed by b, so that
// concatenated variable-length fields cannot be confused for one another.
func appendLenPrefixed(dst, b []byte) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	dst = append(dst, l[:]...)
	return append(dst, b...)
}

// VerifyCheckpoint — log (Transparency Service) の checkpoint 署名を検証する。
// モニター / witness が tree head の真正性を確認するのに使う。
func VerifyCheckpoint(cp Checkpoint, tsPub ed25519.PublicKey) error {
	sig, err := base64.StdEncoding.DecodeString(cp.Signature)
	if err != nil {
		return ErrCheckpointSig
	}
	if len(tsPub) != ed25519.PublicKeySize || !ed25519.Verify(tsPub, checkpointSigPayload(cp), sig) {
		return ErrCheckpointSig
	}
	return nil
}

// Get — 位置から statement と Receipt を取得 (監査・再検証用)。
//
// 返す Receipt は現在のツリー (最新 root) に対して新規に署名し直したもので、
// RegisteredAt はその再発行時刻を表す。元の Register が返した Receipt とは
// (root もタイムスタンプも変わり得るため) バイト一致しない。
func (l *Ledger) Get(idx uint64) (Statement, *Receipt, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if idx >= uint64(len(l.cached)) {
		return Statement{}, nil, ErrNotFound
	}
	stmt := l.cached[idx]
	size := uint64(len(l.leafHashes))
	root := l.cachedRoot(int(size))
	pathBytes := l.cachedAuditPath(int(idx), int(size))
	pathHex := make([]string, len(pathBytes))
	for i, p := range pathBytes {
		pathHex[i] = fmt.Sprintf("%x", p)
	}
	receipt := &Receipt{
		LeafIndex:    idx,
		TreeSize:     size,
		RootHash:     fmt.Sprintf("%x", root),
		AuditPath:    pathHex,
		TSKey:        base64.StdEncoding.EncodeToString(l.tsPub),
		RegisteredAt: time.Now().UTC(),
	}
	sigPayload := receiptSigPayload(receipt)
	receipt.TSSignature = base64.StdEncoding.EncodeToString(ed25519.Sign(l.tsPriv, sigPayload))
	return stmt, receipt, nil
}

// SearchResult pairs a matched statement with its leaf index, so a caller can
// fetch the full statement + receipt via Get(idx) for verification.
type SearchResult struct {
	Index       uint64    `json:"index"`
	Issuer      string    `json:"issuer"`
	Subject     string    `json:"subject"`
	IssuedAt    time.Time `json:"iat"`
	PayloadHash string    `json:"payloadHash"`
}

// FindBySubject returns every statement whose Subject (e.g. productId /
// batteryId) equals subject, in registration order, using the secondary index
// (no full-ledger scan) — CEN-CENELEC EN 18222 lifecycle searchability.
func (l *Ledger) FindBySubject(subject string) []SearchResult {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.resultsForLocked(l.bySubject[subject])
}

// FindByIssuer returns every statement issued by issuer (e.g. a manufacturer
// DID), in registration order, using the secondary index.
func (l *Ledger) FindByIssuer(issuer string) []SearchResult {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.resultsForLocked(l.byIssuer[issuer])
}

// resultsForLocked materializes SearchResults for the given leaf indices. The
// caller must hold at least l.mu.RLock. Indices come from the append-only
// indexes so they are always in range, but the guard keeps it robust.
func (l *Ledger) resultsForLocked(indices []uint64) []SearchResult {
	out := make([]SearchResult, 0, len(indices))
	for _, idx := range indices {
		if idx >= uint64(len(l.cached)) {
			continue
		}
		s := l.cached[idx]
		out = append(out, SearchResult{
			Index:       idx,
			Issuer:      s.Issuer,
			Subject:     s.Subject,
			IssuedAt:    s.IssuedAt,
			PayloadHash: s.PayloadHash,
		})
	}
	return out
}
