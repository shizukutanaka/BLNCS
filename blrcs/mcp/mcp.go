// Package mcp — BLRCS Model Context Protocol Server
//
// エージェント時代のBLRCS門戸。AI agent (Claude, GPT, Gemini等) から
// BLRCS機能を直接呼び出せる。全呼出はSCITT ledgerに自動監査記録。
//
// プロトコル: MCP 2024-11-05 (JSON-RPC 2.0 over stdio)
//
// 公開ツール:
//
//	issue_passport      — EU DPP発行 (credentialStatus 自動埋込み)
//	issue_battery_passport — EU Battery Passport発行 (Reg 2023/1542 Annex XIII)
//	verify_passport     — DPP検証
//	attest_range        — センサ範囲証明 (値非開示)
//	verify_range        — 範囲証明検証
//	register_scitt      — 透明性ログ登録
//	get_scitt_receipt   — 受領証取得
//	ledger_checkpoint   — 署名済みtree head
//	search_passports    — SCITT ledger を subject/issuer で検索 (EN 18222)
//	build_dpp_bundle    — 自己完結・オフライン検証可能な DPP バンドル生成
//	anchor_dpp_bundle   — バンドルに archive timestamp を付与/更新 (LTV/ERS)
//	verify_dpp_bundle   — バンドルをネットワーク無しで検証
//	issue_sdjwt         — SD-JWT VC発行 (選択開示、status_list claim 自動埋込み)
//	verify_sdjwt        — SD-JWT VC検証 (exp/KB-JWT込み)
//	check_revocation    — W3C Bitstring Status List 失効確認
//	revoke_passport     — 発行済み DPP/SD-JWT VC を失効
//	get_revocation_list — 現在の署名済み Status List トークンを取得
//	get_server_capabilities — 有効な機能 (VCI/VP/永続化等) を報告 (機能検出)
//	create_credential_offer — OpenID4VCI pre-authorized offer 発行 (要 RegisterVCIIssuer)
//	issue_mdoc          — ISO 18013-5 mdoc/mDL発行 (IssuerSigned + MSO)
//	verify_mdoc         — mdoc署名検証
//	build_gs1_link      — GS1 Digital Link URI 構築
//	parse_gs1_link      — GS1 Digital Link URI 解析
//	build_gs1_linkset   — GS1 Digital Link Linkset 構築 (RFC 9264, DPP発見用)
//	parse_gs1_linkset   — GS1 Digital Link Linkset 解析
//	resolve_did         — did:web/did:key/did:jwk を公開鍵に解決 (SSRF対策済み)
//	discover_did_services — did:web の DID Document から service endpoint 群を取得
//	verify_passport_by_did — DPP検証 (issuer DID から鍵解決)
//	verify_sdjwt_by_did — SD-JWT検証 (issuer DID から鍵解決)
//	create_did_webvh    — did:webvh genesis log entry 作成 (pre-rotation/witness対応)
//	update_did_webvh    — did:webvh log にエントリ追加 (鍵ローテーション/失効/witness)
//	verify_did_webvh_log — did:webvh log 全体を検証・解決 (witness閾値含む)
//	sign_witness_proof  — did:webvh witness の Data Integrity proof 発行
//	resolve_vct_metadata — SD-JWT-VC Type Metadata 解決
//	validate_claims_against_vct — vct のJSON Schemaでクレームを検証
//	create_presentation_request — OpenID4VP authorization request 発行 (要 RegisterVPVerifier)
//	get_presentation_result     — 提示要求の結果取得 (state で問合せ)
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"

	"blrcs/bundle"
	"blrcs/capability"
	"blrcs/compliance"
	"blrcs/didresolver"
	"blrcs/didwebvh"
	"blrcs/mdoc"
	"blrcs/openid4vci"
	"blrcs/openid4vp"
	"blrcs/revocation"
	"blrcs/scitt"
	"blrcs/storage"
	"blrcs/vctmeta"
)

const (
	protocolVersion = "2024-11-05"
	serverName      = "blrcs-mcp"
	serverVersion   = "1.0.0"
)

// ============================================================================
// JSON-RPC 2.0
// ============================================================================

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

const (
	errParse          = -32700
	errInvalidRequest = -32600
	errMethodNotFound = -32601
	errInvalidParams  = -32602
	errRateLimit      = -32000 // server-defined: rate limit exceeded
)

// ============================================================================
// MCP structures
// ============================================================================

type initResult struct {
	ProtocolVersion string       `json:"protocolVersion"`
	ServerInfo      serverInfo   `json:"serverInfo"`
	Capabilities    capabilities `json:"capabilities"`
}

type serverInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type capabilities struct {
	Tools *toolsCap `json:"tools,omitempty"`
}

type toolsCap struct {
	ListChanged bool `json:"listChanged"`
}

type tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

type toolsListResult struct {
	Tools []tool `json:"tools"`
}

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type toolCallResult struct {
	Content []contentBlock `json:"content"`
	IsError bool           `json:"isError"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// ============================================================================
// Server
// ============================================================================

// Server is the BLRCS Model Context Protocol server: it exposes issuance,
// presentation, verification, revocation and transparency-log tools to an MCP
// client, backed by a SCITT ledger and one or more registered issuers.
//
// In stdio mode the Server has no HTTP surface of its own; a caller that wants
// OpenID4VCI endpoints mounts openid4vci.Issuer.Handler() separately and
// registers it with RegisterVCIIssuer.
//
// The registries a Server holds (issuers, attesters) are guarded by a mutex.
// Serve itself reads one request at a time from a single stream.
type Server struct {
	mu         sync.RWMutex
	issuers    map[string]*compliance.Issuer
	attesters  map[string]*compliance.SensorAttester
	ledger     *scitt.Ledger
	selfIssuer *compliance.Issuer
	limiter    *ToolLimiter // per-tool rate limiter; nil = unlimited

	// vciIssuer, when registered via RegisterVCIIssuer, lets create_credential_offer
	// mint real OpenID4VCI pre-authorized offers a wallet can redeem against the
	// issuer's HTTP endpoints (openid4vci.Issuer.Handler(), mounted separately by
	// the caller — this Server has no HTTP surface of its own in stdio mode).
	// nil means the tool is unavailable (dispatch returns an error).
	vciIssuer *openid4vci.Issuer

	// vpVerifier, when registered via RegisterVPVerifier, lets
	// create_presentation_request mint real OpenID4VP authorization requests.
	// The wallet's response arrives out-of-band over HTTP (openid4vp.Verifier's
	// CallbackHandler, mounted separately by the caller) and its result is
	// recorded via RecordPresentationResult, retrievable later through
	// get_presentation_result — the agent that created the request has no
	// other way to learn a stdio/tool-only server's results.
	vpVerifier  *openid4vp.Verifier
	presResults map[string]*presentationResult

	// didResolver backs resolve_did. Always initialized (unlike vciIssuer/
	// vpVerifier) since it adds no new HTTP surface of its own — it only
	// makes outbound fetches when a tool call asks it to, same risk shape as
	// any other MCP tool, and didresolver's default fetcher is SSRF-hardened
	// (see didresolver.defaultClient) so this is safe by default.
	didResolver *didresolver.Resolver

	// vctFetcher backs resolve_vct_metadata/validate_claims_against_vct.
	// Defaults to vctmeta.HTTPFetcher(nil) — SSRF-hardened (Axis 112) — but
	// is a settable field (rather than calling HTTPFetcher(nil) inline in
	// each tool) so tests can inject a mock and exercise the happy path
	// without a real network round-trip, same rationale as
	// Resolver.HTTPFetcher above.
	vctFetcher vctmeta.FetchFunc

	// trustAnchor gates verify_passport_by_did/verify_sdjwt_by_did: which
	// issuer DIDs' resolved keys this server accepts as trust roots. Defaults
	// to AllowAll() (any resolved key is trusted) — the exact same security
	// posture as an agent manually chaining resolve_did -> verify_passport
	// today, since neither step currently checks an allowlist. An operator
	// wanting a real PKI-style restriction registers a stricter TrustAnchor
	// via RegisterTrustAnchor (see cmd/blrcs-mcpd's BLRCS_TRUSTED_DIDS).
	trustAnchor *didresolver.TrustAnchor

	// Revocation: a single server-wide W3C Bitstring Status List that
	// issue_passport embeds into every issued credential's credentialStatus,
	// and revoke_passport mutates. Persisted via storage.BlobStorage when the
	// backing Storage supports it (both cmd/blrcs-mcp and cmd/blrcs-mcpd's
	// FileStorage do); falls back to in-memory-only (volatile) otherwise,
	// same as the rest of the ephemeral-mode contract.
	revocationList  *revocation.BitstringStatusList
	nextStatusIndex uint64
	revocationStore storage.BlobStorage // nil if the backing Storage doesn't support blobs
}

// presentationResult caches one completed (successful) OpenID4VP verification,
// keyed by request state. Failures are intentionally not cached — CallbackHandler
// already returns the failure synchronously to the wallet's own HTTP client, and
// its error detail is deliberately opaque (CWE-209) so there is nothing extra a
// polling agent should learn beyond "not found".
type presentationResult struct {
	vp        *openid4vp.VerifiedPresentation
	expiresAt time.Time
}

const (
	maxPresentationResults = 10_000
	presentationResultTTL  = 15 * time.Minute
)

const (
	revocationListBlobName  = "revocation-list"
	revocationIndexBlobName = "revocation-next-index"
)

// NewServer returns a Server backed by in-memory storage: nothing it records
// survives the process. tsID names the transparency service, serverDID the
// server's own DID.
//
// Use NewServerWithStorage to persist the ledger and revocation state.
func NewServer(tsID, serverDID string) (*Server, error) {
	// Route through NewServerWithStorage (backed by an explicit MemoryStorage)
	// rather than scitt.NewLedger's own internal storage.NewMemoryStorage — the
	// Server needs a handle on the Storage to persist revocation state (via
	// BlobStorage) using the same code path as the persistent case, keeping
	// ephemeral and persistent mode structurally identical.
	return NewServerWithStorage(tsID, serverDID, storage.NewMemoryStorage())
}

// NewServerWithStorage — 永続化層付き (プロダクション向け)
func NewServerWithStorage(tsID, serverDID string, store storage.Storage) (*Server, error) {
	ledger, err := scitt.NewLedgerWithStorage(tsID, store)
	if err != nil {
		return nil, err
	}
	return buildServer(tsID, serverDID, ledger, store)
}

func buildServer(tsID, serverDID string, ledger *scitt.Ledger, store storage.Storage) (*Server, error) {
	selfIss, err := compliance.NewIssuer(serverDID)
	if err != nil {
		return nil, err
	}
	defaultTrust := didresolver.NewTrustAnchor()
	defaultTrust.AllowAll()
	s := &Server{
		issuers:     make(map[string]*compliance.Issuer),
		attesters:   make(map[string]*compliance.SensorAttester),
		ledger:      ledger,
		selfIssuer:  selfIss,
		didResolver: didresolver.New(),
		trustAnchor: defaultTrust,
		vctFetcher:  vctmeta.HTTPFetcher(nil),
	}
	if err := s.initRevocation(store); err != nil {
		return nil, err
	}
	return s, nil
}

// initRevocation restores the revocation list and index counter from store
// (if it supports BlobStorage), or starts fresh otherwise. Both must be
// restored together: replaying only the list would let a freshly-restarted
// server reassign an already-used status index to a new credential, silently
// aliasing the new credential's revocation status to whatever the old one's
// bit happened to be.
func (s *Server) initRevocation(store storage.Storage) error {
	s.revocationList = revocation.NewBitstringStatusList(revocation.PurposeRevocation, revocation.MinBitstringSize)
	bs, ok := store.(storage.BlobStorage)
	if !ok {
		return nil
	}
	s.revocationStore = bs
	switch encoded, err := bs.LoadBlob(revocationListBlobName); {
	case err == nil:
		list, derr := revocation.DecodeBitstringStatusList(revocation.PurposeRevocation, string(encoded))
		if derr != nil {
			return fmt.Errorf("mcp: restore revocation list: %w", derr)
		}
		s.revocationList = list
	case errors.Is(err, storage.ErrNotFound):
		// no prior state — fresh list is correct
	default:
		return fmt.Errorf("mcp: load revocation list: %w", err)
	}
	switch idxBytes, err := bs.LoadBlob(revocationIndexBlobName); {
	case err == nil:
		n, perr := strconv.ParseUint(string(idxBytes), 10, 64)
		if perr != nil {
			return fmt.Errorf("mcp: restore revocation index: %w", perr)
		}
		s.nextStatusIndex = n
	case errors.Is(err, storage.ErrNotFound):
		// no prior state — start at 0
	default:
		return fmt.Errorf("mcp: load revocation index: %w", err)
	}
	return nil
}

// allocateStatusIndex reserves the next status-list bit for a newly-issued
// credential and durably persists the advanced counter before returning it —
// so a crash between allocation and the caller using the index can never
// replay the same index for two different credentials.
func (s *Server) allocateStatusIndex() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := s.nextStatusIndex
	if idx >= uint64(s.revocationList.Capacity()) {
		return 0, errors.New("mcp: revocation list capacity exhausted")
	}
	next := idx + 1
	if s.revocationStore != nil {
		if err := s.revocationStore.SaveBlob(revocationIndexBlobName, []byte(strconv.FormatUint(next, 10))); err != nil {
			return 0, fmt.Errorf("mcp: persist revocation index: %w", err)
		}
	}
	s.nextStatusIndex = next
	return int(idx), nil
}

// revokeByIndex marks index as revoked and durably persists the updated list.
// On a persist failure the in-memory bit is rolled back so the reported error
// matches the actual (unchanged) durable state — otherwise a caller retrying
// after "persist failed" would find the index already marked revoked
// in-memory and skip the retry, while disk still shows it as active.
func (s *Server) revokeByIndex(index int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.revocationList.SetStatus(index, true); err != nil {
		return err
	}
	if s.revocationStore == nil {
		return nil
	}
	encoded, err := s.revocationList.EncodedList()
	if err != nil {
		_ = s.revocationList.SetStatus(index, false)
		return fmt.Errorf("mcp: encode revocation list: %w", err)
	}
	if err := s.revocationStore.SaveBlob(revocationListBlobName, []byte(encoded)); err != nil {
		_ = s.revocationList.SetStatus(index, false)
		return fmt.Errorf("mcp: persist revocation list: %w", err)
	}
	return nil
}

func (s *Server) Ledger() *scitt.Ledger { return s.ledger }

func (s *Server) RegisterIssuer(iss *compliance.Issuer) {
	s.mu.Lock()
	s.issuers[iss.ID] = iss
	s.mu.Unlock()
}

func (s *Server) RegisterAttester(a *compliance.SensorAttester) {
	s.mu.Lock()
	s.attesters[a.ID] = a
	s.mu.Unlock()
}

// RegisterVCIIssuer wires an openid4vci.Issuer into this server so
// create_credential_offer can mint real pre-authorized offers. The caller is
// responsible for separately mounting iss.Handler() on an HTTP mux so a
// wallet can actually redeem the offer this tool returns — this Server has
// no HTTP surface of its own (e.g. it may run over stdio).
func (s *Server) RegisterVCIIssuer(iss *openid4vci.Issuer) {
	s.mu.Lock()
	s.vciIssuer = iss
	s.mu.Unlock()
}

// RegisterVPVerifier wires an openid4vp.Verifier into this server so
// create_presentation_request can mint real authorization requests. The
// caller is responsible for separately mounting the verifier's
// CallbackHandler on an HTTP mux — wired to call RecordPresentationResult on
// success — so a wallet can actually respond to the request this tool
// returns.
func (s *Server) RegisterVPVerifier(v *openid4vp.Verifier) {
	s.mu.Lock()
	s.vpVerifier = v
	s.mu.Unlock()
}

// RegisterTrustAnchor replaces this server's default (allow-all) trust
// anchor for verify_passport_by_did/verify_sdjwt_by_did. Pass a TrustAnchor
// built with AddDID/AddKey (no AllowAll call) to restrict trust to a
// specific issuer allowlist instead of accepting whatever a DID resolves to.
func (s *Server) RegisterTrustAnchor(t *didresolver.TrustAnchor) {
	s.mu.Lock()
	s.trustAnchor = t
	s.mu.Unlock()
}

// RecordPresentationResult caches a completed OpenID4VP verification so
// get_presentation_result can retrieve it later — the agent that called
// create_presentation_request has no other way to learn whether/how a
// wallet responded, since the response arrives over HTTP outside the MCP
// tool-calling loop. Wire this as the onSuccess callback passed to
// openid4vp.Verifier.CallbackHandler.
func (s *Server) RecordPresentationResult(vp *openid4vp.VerifiedPresentation) {
	if vp == nil || vp.State == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.presResults == nil {
		s.presResults = make(map[string]*presentationResult)
	}
	now := time.Now()
	// Opportunistic expiry sweep, then evict the entry closest to expiring if
	// still at capacity — mirrors the pattern already used for revocation/
	// rate-limit state elsewhere in this package, so an unauthenticated flood
	// of wallet callbacks can't grow this map without bound. Evicting by
	// soonest-to-expire (rather than tracking insertion order separately,
	// which would itself leak entries removed by this same sweep) needs no
	// extra state to stay consistent.
	for state, entry := range s.presResults {
		if now.After(entry.expiresAt) {
			delete(s.presResults, state)
		}
	}
	if len(s.presResults) >= maxPresentationResults {
		var oldestState string
		var oldestExpiry time.Time
		for state, entry := range s.presResults {
			if oldestState == "" || entry.expiresAt.Before(oldestExpiry) {
				oldestState, oldestExpiry = state, entry.expiresAt
			}
		}
		if oldestState != "" {
			delete(s.presResults, oldestState)
		}
	}
	s.presResults[vp.State] = &presentationResult{vp: vp, expiresAt: now.Add(presentationResultTTL)}
}

// ============================================================================
// Transport — stdio (改行区切りJSON)
// ============================================================================

func (s *Server) Serve(in io.Reader, out io.Writer) error {
	scan := bufio.NewScanner(in)
	scan.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	enc := json.NewEncoder(out)
	for scan.Scan() {
		line := scan.Bytes()
		if len(line) == 0 {
			continue
		}
		resp := s.handle(line)
		if resp != nil {
			if err := enc.Encode(resp); err != nil {
				return fmt.Errorf("encode: %w", err)
			}
		}
	}
	return scan.Err()
}

// HandleRaw — テスト用: 単一メッセージ処理、JSONバイトを返す
func (s *Server) HandleRaw(raw []byte) []byte {
	resp := s.handle(raw)
	if resp == nil {
		return nil
	}
	b, _ := json.Marshal(resp)
	return b
}

func (s *Server) handle(raw []byte) *rpcResponse {
	var req rpcRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return errorResp(nil, errParse, "parse error", err.Error())
	}
	if req.JSONRPC != "2.0" {
		return errorResp(req.ID, errInvalidRequest, "jsonrpc must be 2.0", nil)
	}
	switch req.Method {
	case "initialize":
		return okResp(req.ID, initResult{
			ProtocolVersion: protocolVersion,
			ServerInfo:      serverInfo{Name: serverName, Version: serverVersion},
			Capabilities:    capabilities{Tools: &toolsCap{ListChanged: false}},
		})
	case "notifications/initialized":
		return nil
	case "tools/list":
		return okResp(req.ID, toolsListResult{Tools: toolDefs()})
	case "tools/call":
		return s.handleToolCall(req.ID, req.Params)
	case "ping":
		return okResp(req.ID, struct{}{})
	default:
		return errorResp(req.ID, errMethodNotFound, "method not found: "+req.Method, nil)
	}
}

func okResp(id json.RawMessage, result any) *rpcResponse {
	return &rpcResponse{JSONRPC: "2.0", ID: id, Result: result}
}

func errorResp(id json.RawMessage, code int, msg string, data any) *rpcResponse {
	return &rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg, Data: data}}
}

// ============================================================================
// Tool definitions
// ============================================================================

func toolDefs() []tool {
	return []tool{
		{
			Name:        "issue_passport",
			Description: "Issue EU Digital Product Passport (W3C VC, Ed25519Signature2020). For ESPR compliance.",
			InputSchema: rawJSON(`{"type":"object","properties":{"issuerId":{"type":"string"},"productId":{"type":"string"},"category":{"type":"string"},"originCountry":{"type":"string"},"carbonKgCO2e":{"type":"number"},"recyclability":{"type":"number","minimum":0,"maximum":1},"validForDays":{"type":"integer","default":365}},"required":["issuerId","productId"]}`),
		},
		{
			Name:        "issue_battery_passport",
			Description: "Issue an EU Battery Passport (Regulation (EU) 2023/1542, Annex XIII). EV and industrial batteries over 2kWh require dueDiligenceReportUrl (Art.52) or issuance is rejected. Embeds a credentialStatus, same as issue_passport.",
			InputSchema: rawJSON(`{"type":"object","properties":{"issuerId":{"type":"string"},"batteryId":{"type":"string"},"gtin":{"type":"string"},"serialNo":{"type":"string"},"category":{"type":"string","enum":["ev","lmt","industrial","sli","portable"]},"chemistry":{"type":"string","enum":["nmc","nca","lfp","lto","lco"]},"capacityKWh":{"type":"number"},"voltageV":{"type":"number"},"weightKg":{"type":"number"},"placeOfManufacture":{"type":"string"},"modelId":{"type":"string"},"dateOfManufacture":{"type":"string","description":"RFC3339"},"commissioningDate":{"type":"string","description":"RFC3339"},"carbonFootprintKgCO2ePerKWh":{"type":"number"},"carbonFootprintClass":{"type":"string"},"recycledContent":{"type":"object","properties":{"cobalt":{"type":"number"},"lithium":{"type":"number"},"nickel":{"type":"number"},"lead":{"type":"number"}}},"renewableContentPct":{"type":"number"},"hazardousSubstances":{"type":"array","items":{"type":"string"}},"stateOfHealthPct":{"type":"number"},"cycleCount":{"type":"integer"},"expectedLifetimeYears":{"type":"number"},"euDeclarationOfConformityUrl":{"type":"string"},"dueDiligenceReportUrl":{"type":"string","description":"Required for EV/industrial batteries >2kWh (Art.52)"},"separateCollection":{"type":"boolean"},"recyclable":{"type":"boolean"},"validForDays":{"type":"integer","default":365}},"required":["issuerId","batteryId","category"]}`),
		},
		{
			Name:        "verify_passport",
			Description: "Verify DPP signature and expiration against an issuer public key.",
			InputSchema: rawJSON(`{"type":"object","properties":{"credentialJson":{"type":"string"},"issuerPublicKeyB64":{"type":"string"}},"required":["credentialJson","issuerPublicKeyB64"]}`),
		},
		{
			Name:        "attest_range",
			Description: "Attest sensor reading is within compliance range WITHOUT revealing the value.",
			InputSchema: rawJSON(`{"type":"object","properties":{"attesterId":{"type":"string"},"value":{"type":"number"},"min":{"type":"number"},"max":{"type":"number"},"unit":{"type":"string"},"name":{"type":"string"}},"required":["attesterId","value","min","max","name"]}`),
		},
		{
			Name:        "verify_range",
			Description: "Verify a sensor range proof against an attester public key.",
			InputSchema: rawJSON(`{"type":"object","properties":{"proofJson":{"type":"string"},"attesterPublicKeyB64":{"type":"string"}},"required":["proofJson","attesterPublicKeyB64"]}`),
		},
		{
			Name:        "register_scitt",
			Description: "Register a signed statement to the transparency ledger. Returns cryptographic receipt with Merkle inclusion proof.",
			InputSchema: rawJSON(`{"type":"object","properties":{"issuerId":{"type":"string"},"subject":{"type":"string"},"contentType":{"type":"string"},"payload":{"type":"string"}},"required":["issuerId","subject","payload"]}`),
		},
		{
			Name:        "get_scitt_receipt",
			Description: "Fetch receipt and statement at a given ledger index for audit re-verification.",
			InputSchema: rawJSON(`{"type":"object","properties":{"leafIndex":{"type":"integer","minimum":0}},"required":["leafIndex"]}`),
		},
		{
			Name:        "ledger_checkpoint",
			Description: "Signed tree head for gossip/monitoring. Proves current ledger state.",
			InputSchema: rawJSON(`{"type":"object","properties":{}}`),
		},
		{
			Name:        "search_passports",
			Description: "Search the SCITT ledger for statements by subject (productId/batteryId) and/or issuer (manufacturer DID) using a secondary index — no full-ledger scan (CEN-CENELEC EN 18222 lifecycle searchability). Returns {count, results:[{index, issuer, subject, iat, payloadHash}]}; pass each index to get_scitt_receipt for the full statement + inclusion proof. Both filters together return their intersection; at least one is required.",
			InputSchema: rawJSON(`{"type":"object","properties":{"subject":{"type":"string","description":"productId / batteryId to search for"},"issuer":{"type":"string","description":"manufacturer/issuer DID to search for"}}}`),
		},
		{
			Name:        "build_dpp_bundle",
			Description: "Package an issued credential into a self-contained, long-term-verifiable DPP bundle: the credential plus the issuer key, and optionally a signed status-list snapshot and a did:webvh provenance log. The artifact verifies with ZERO network calls, so a passport stays checkable for the product's 10-25 year life even when the issuer's server is gone and the scan point (recycler, port, customs) is offline. Call anchor_dpp_bundle next to add the trusted timestamp that long-term validation requires.",
			InputSchema: rawJSON(`{"type":"object","properties":{"credential":{"type":"string","description":"The SD-JWT VC (from issue_sdjwt)"},"issuerId":{"type":"string","description":"Registered issuer that signed the credential (preferred — the server looks up its key)"},"issuerPublicKeyB64":{"type":"string","description":"Alternative to issuerId: base64-std Ed25519 public key that signed the credential"},"statusToken":{"type":"string","description":"Optional signed Status List Token snapshot"},"statusPublicKeyB64":{"type":"string","description":"base64-std key that signed statusToken"},"issuerDidLog":{"type":"array","description":"Optional did:webvh log proving the issuer key's provenance"}},"required":["credential"]}`),
		},
		{
			Name:        "anchor_dpp_bundle",
			Description: "Add an archive timestamp to a DPP bundle using this server's SCITT transparency ledger as the timestamping authority. This supplies the component ETSI long-term validation requires but that stapled evidence alone cannot: proof the credential existed at a trusted time, while the issuer key was still valid. Call again later (before the in-use algorithms weaken) to RENEW — each renewal is taken over the whole bundle including prior anchors, per RFC 4998 Evidence Record Syntax, so older evidence is carried forward.",
			InputSchema: rawJSON(`{"type":"object","properties":{"bundleJson":{"type":"string","description":"The bundle from build_dpp_bundle"},"issuerId":{"type":"string","description":"Registered issuer whose key submits the anchor statement"}},"required":["bundleJson","issuerId"]}`),
		},
		{
			Name:        "verify_dpp_bundle",
			Description: "Verify a DPP bundle with NO network access. Always checks the credential signature and validity window; additionally checks issuer-key provenance, revocation and the archive-timestamp chain ONLY when the bundle carries that evidence. The result reports exactly which checks ran, so a missing status snapshot is never mistaken for 'not revoked'. Set the require* flags to fail closed when a required check has no evidence.",
			InputSchema: rawJSON(`{"type":"object","properties":{"bundleJson":{"type":"string"},"requireProvenance":{"type":"boolean"},"requireRevocationCheck":{"type":"boolean"},"requireTimestamp":{"type":"boolean","description":"Demand a verifiable archive timestamp (long-term validation)"},"maxStatusAgeSeconds":{"type":"integer","description":"Reject a status snapshot older than this many seconds"}},"required":["bundleJson"]}`),
		},
		{
			Name:        "issue_sdjwt",
			Description: "Issue an SD-JWT VC with selective disclosure. sdClaims become selectively disclosable; clearClaims are always visible. Embeds a status_list claim (revocable via revoke_passport, checkable via check_revocation/get_revocation_list). Returns the full SD-JWT token, a list of disclosures, and the statusListIndex.",
			InputSchema: rawJSON(`{"type":"object","properties":{"issuerId":{"type":"string"},"subject":{"type":"string"},"sdClaims":{"type":"object","description":"Claims to make selectively disclosable"},"clearClaims":{"type":"object","description":"Claims always visible in the JWT"},"validForDays":{"type":"integer","default":365}},"required":["issuerId","subject","sdClaims"]}`),
		},
		{
			Name:        "verify_sdjwt",
			Description: "Verify an SD-JWT VC signature, expiry, and (if present) KB-JWT holder binding. Returns the verified claims.",
			InputSchema: rawJSON(`{"type":"object","properties":{"sdjwt":{"type":"string","description":"Full SD-JWT presentation string (header.payload.sig~disc...~[kb-jwt])"},"issuerPublicKeyB64":{"type":"string","description":"Base64-encoded Ed25519 issuer public key"},"expectedNonce":{"type":"string","description":"Expected KB-JWT nonce (for OpenID4VP)"},"expectedAudience":{"type":"string","description":"Expected KB-JWT audience"}},"required":["sdjwt","issuerPublicKeyB64"]}`),
		},
		{
			Name:        "verify_passport_by_did",
			Description: "Verify a credential using its issuer field's DID as the trust root, instead of supplying the raw public key directly (verify_passport's contract). Resolves the DID and only accepts keys the server's trust anchor allows for it (default: any resolved key).",
			InputSchema: rawJSON(`{"type":"object","properties":{"credentialJson":{"type":"string"}},"required":["credentialJson"]}`),
		},
		{
			Name:        "verify_sdjwt_by_did",
			Description: "verify_sdjwt's DID-resolving counterpart: same nonce/audience binding options, but the issuer public key comes from resolving+trust-checking issuerDid instead of being supplied directly.",
			InputSchema: rawJSON(`{"type":"object","properties":{"sdjwt":{"type":"string"},"issuerDid":{"type":"string"},"expectedNonce":{"type":"string"},"expectedAudience":{"type":"string"}},"required":["sdjwt","issuerDid"]}`),
		},
		{
			Name:        "create_did_webvh",
			Description: "Create a new did:webvh genesis log entry (verifiable history + optional pre-rotation commitment + optional witness requirement + optional portability). issuerId must be a registered issuer whose key becomes the genesis update key. Returns the new DID and a one-entry log — keep it and pass it to update_did_webvh/verify_did_webvh_log; this server does not persist did:webvh logs.",
			InputSchema: rawJSON(`{"type":"object","properties":{"issuerId":{"type":"string"},"didPath":{"type":"string","description":"Method-specific id without the SCID, e.g. example.com:dids:org-1"},"nextKeyHashes":{"type":"array","items":{"type":"string"},"description":"Optional pre-rotation commitment hashes"},"stateExtra":{"type":"object","description":"Extra fields for the genesis DID document"},"witness":{"type":"object","description":"Optional witness requirement: {threshold, witnesses:[{id: did:key DID}]}. Collect proofs from each witness via sign_witness_proof and pass them as witnessLog to verify_did_webvh_log."},"portable":{"type":"boolean","description":"Optional: set true to allow this DID to later be moved to a different domain/path via update_did_webvh while retaining its SCID. Only settable at genesis; defaults to false (not portable)."},"watchers":{"type":"array","items":{"type":"string"},"description":"Optional watcher URLs monitoring this DID (spec §Parameters). Exposed in verify_did_webvh_log's result; not a verification gate."}},"required":["issuerId","didPath"]}`),
		},
		{
			Name:        "update_did_webvh",
			Description: "Append a new signed entry to an existing did:webvh log (key rotation, document update, deactivation, (re)declaring a witness requirement, or moving domain/path if the log was created with portable=true). signKeyIssuerId must be a registered issuer whose key currently holds update authority over the log. Returns the extended log.",
			InputSchema: rawJSON(`{"type":"object","properties":{"signKeyIssuerId":{"type":"string"},"log":{"type":"array","description":"The existing verified log (array of LogEntry)"},"newState":{"type":"object","description":"The new DID document"},"updateKeys":{"type":"array","items":{"type":"string"},"description":"Multikey-encoded keys that take update authority from this entry on"},"nextKeyHashes":{"type":"array","items":{"type":"string"}},"deactivate":{"type":"boolean"},"witness":{"type":"object","description":"Optional witness requirement to declare from this entry on: {threshold, witnesses:[{id: did:key DID}]}"},"portable":{"type":"boolean","description":"Optional: set false to permanently disable further domain/path moves. Omit to retain whatever was previously in effect. Cannot be set true here — portability may only be enabled at genesis."},"watchers":{"type":"array","items":{"type":"string"},"description":"Optional: (re)declare watcher URLs from this entry on. Omit to retain the prior list; an empty array clears it."}},"required":["signKeyIssuerId","log"]}`),
		},
		{
			Name:        "verify_did_webvh_log",
			Description: "Validate a complete did:webvh log (SCID self-certification, entry hash-chaining, sequential versions, update-key authorization, pre-rotation commitments, and — when witnessLog is supplied or any entry declares Parameters.Witness — witness threshold enforcement) and return the resolved DID document. Returns {valid, did, scid, document, versionId, versionTime, deactivated, watchers} or {valid:false, reason}.",
			InputSchema: rawJSON(`{"type":"object","properties":{"log":{"type":"array","description":"Array of LogEntry as returned by create_did_webvh/update_did_webvh"},"witnessLog":{"type":"array","description":"Optional did-witness.json content: [{versionId, proof:[...]}], collected via sign_witness_proof"}},"required":["log"]}`),
		},
		{
			Name:        "sign_witness_proof",
			Description: "Produce one witness's Data Integrity proof for a did:webvh log entry (did:webvh v1.0 §Witnesses). witnessIssuerId must be a registered issuer whose ID is that witness's did:key DID. Collect one proof per required witness and assemble them into a did-witness.json-shaped array to pass as verify_did_webvh_log's witnessLog.",
			InputSchema: rawJSON(`{"type":"object","properties":{"witnessIssuerId":{"type":"string"},"entry":{"type":"object","description":"The LogEntry being witnessed"},"predecessorVersionId":{"type":"string","description":"The prior entry's versionId; empty for the genesis entry"}},"required":["witnessIssuerId","entry"]}`),
		},
		{
			Name:        "resolve_vct_metadata",
			Description: "Resolve an SD-JWT-VC vct claim to its Type Metadata document (name, description, extends, schema). expectedIntegrity is an optional W3C SRI-style hash (sha256-<base64>) pinning the vct#integrity claim.",
			InputSchema: rawJSON(`{"type":"object","properties":{"vct":{"type":"string","description":"https URL identifying the credential type"},"expectedIntegrity":{"type":"string"}},"required":["vct"]}`),
		},
		{
			Name:        "validate_claims_against_vct",
			Description: "Resolve a vct's Type Metadata and validate claims against its JSON Schema — the natural complement to verify_sdjwt: after checking the signature, check the disclosed claims conform to the credential's declared type.",
			InputSchema: rawJSON(`{"type":"object","properties":{"vct":{"type":"string"},"expectedIntegrity":{"type":"string"},"claims":{"type":"object"}},"required":["vct","claims"]}`),
		},
		{
			Name:        "check_revocation",
			Description: "Check whether a credential is revoked using a W3C Bitstring Status List token. Returns {revoked:bool}.",
			InputSchema: rawJSON(`{"type":"object","properties":{"statusListTokenJWT":{"type":"string","description":"Status list token (application/statuslist+jwt)"},"statusListIssuerKeyB64":{"type":"string","description":"Base64-encoded Ed25519 public key of status list issuer"},"statusIndex":{"type":"integer","minimum":0,"description":"Bit index of the credential in the status list"}},"required":["statusListTokenJWT","statusListIssuerKeyB64","statusIndex"]}`),
		},
		{
			Name:        "revoke_passport",
			Description: "Revoke a previously-issued passport or SD-JWT VC by its statusListIndex (from issue_passport's credentialStatus, or issue_sdjwt's statusListIndex field — both draw from the same status list). Idempotent — revoking an already-revoked index succeeds.",
			InputSchema: rawJSON(`{"type":"object","properties":{"statusListIndex":{"type":"integer","minimum":0,"description":"statusListIndex from issue_passport's credentialStatus or issue_sdjwt's response"}},"required":["statusListIndex"]}`),
		},
		{
			Name:        "get_revocation_list",
			Description: "Fetch a freshly-signed W3C Bitstring Status List token for this server's current revocation state, plus the issuer key needed to verify it — feed both directly into check_revocation.",
			InputSchema: rawJSON(`{"type":"object","properties":{}}`),
		},
		{
			Name:        "get_server_capabilities",
			Description: "Report which optional server features are actually operational (OpenID4VCI issuance, OpenID4VP verification) plus always-present ones (DPP, Battery Passport, SCITT). Call this first to discover whether config-dependent tools like create_credential_offer / create_presentation_request will work before invoking them.",
			InputSchema: rawJSON(`{"type":"object","properties":{}}`),
		},
		{
			Name:        "create_credential_offer",
			Description: "Mint an OpenID4VCI pre-authorized credential offer a real wallet can redeem (returns openid-credential-offer:// URI + pre-authorized code). Requires the server to have a registered OpenID4VCI issuer; errors otherwise.",
			InputSchema: rawJSON(`{"type":"object","properties":{"configId":{"type":"string","description":"Registered CredentialConfiguration ID"},"subject":{"type":"string"},"sdClaims":{"type":"object","description":"Selectively disclosable claims"},"clearClaims":{"type":"object","description":"Always-visible claims"}},"required":["configId","subject"]}`),
		},
		{
			Name:        "issue_mdoc",
			Description: "Issue an ISO 18013-5 mdoc/mDL (IssuerSigned + MSO, COSE_Sign1). nameSpaces maps namespace to a flat object of elementIdentifier→value. Returns the IssuerSigned CBOR, base64-encoded.",
			InputSchema: rawJSON(`{"type":"object","properties":{"issuerId":{"type":"string"},"docType":{"type":"string","description":"e.g. org.iso.18013.5.1.mDL or eu.europa.ec.dpp.1"},"nameSpaces":{"type":"object","description":"namespace -> {elementIdentifier: value}"},"validForDays":{"type":"integer","default":365},"deviceKeyB64":{"type":"string","description":"Optional base64 Ed25519 device public key to bind the credential to a holder device"}},"required":["issuerId","docType","nameSpaces"]}`),
		},
		{
			Name:        "verify_mdoc",
			Description: "Verify an ISO 18013-5 mdoc's IssuerSigned/MSO signature against an issuer public key. Returns {valid, docType, nameSpaces} or {valid:false, reason}.",
			InputSchema: rawJSON(`{"type":"object","properties":{"issuerSignedB64":{"type":"string"},"issuerPublicKeyB64":{"type":"string"}},"required":["issuerSignedB64","issuerPublicKeyB64"]}`),
		},
		{
			Name:        "build_gs1_link",
			Description: "Build a GS1 Digital Link URI (ISO/IEC 18975) from a domain and GTIN (+ optional serial/batch).",
			InputSchema: rawJSON(`{"type":"object","properties":{"domain":{"type":"string","description":"e.g. example.com"},"gtin":{"type":"string","description":"8/12/13/14-digit GTIN"},"serial":{"type":"string"},"batch":{"type":"string"}},"required":["domain","gtin"]}`),
		},
		{
			Name:        "parse_gs1_link",
			Description: "Parse a GS1 Digital Link URI back into its domain, GTIN, serial, and batch.",
			InputSchema: rawJSON(`{"type":"object","properties":{"uri":{"type":"string"}},"required":["uri"]}`),
		},
		{
			Name:        "build_gs1_linkset",
			Description: "Build a GS1 Digital Link Linkset (RFC 9264 application/linkset+json) from an anchor product URI and a set of linkType -> links. This is the standard DPP discovery mechanism: a QR code resolves to the anchor URI, and the linkset routes from there to the passport, declaration of conformity, due-diligence statement, instructions, etc. Use the LinkTypeXxx constants (compliance package) as linkType keys, e.g. \"https://gs1.org/voc/epil\" for the DPP itself.",
			InputSchema: rawJSON(`{"type":"object","properties":{"anchor":{"type":"string","description":"Product identifier URI, e.g. the output of build_gs1_link"},"links":{"type":"object","description":"linkType URI -> array of {href, type, title, hreflang}","additionalProperties":{"type":"array","items":{"type":"object","properties":{"href":{"type":"string"},"type":{"type":"string"},"title":{"type":"string"},"hreflang":{"type":"string"}},"required":["href"]}}}},"required":["anchor","links"]}`),
		},
		{
			Name:        "parse_gs1_linkset",
			Description: "Parse a GS1 Digital Link Linkset (RFC 9264 application/linkset+json) back into its anchor URI and linkType -> links map.",
			InputSchema: rawJSON(`{"type":"object","properties":{"linksetJson":{"type":"string","description":"Raw application/linkset+json document"}},"required":["linksetJson"]}`),
		},
		{
			Name:        "resolve_did",
			Description: "Resolve a did:web/did:webvh/did:key/did:jwk identifier to its Ed25519 public key(s) — useful before verify_passport/verify_sdjwt/verify_mdoc when you only have an issuer's DID, not its raw public key. did:webvh resolution fetches and verifies the full did.jsonl log (SCID self-certification, hash-chaining, witness/portability rules). Does not itself decide trust; the caller evaluates the returned key(s).",
			InputSchema: rawJSON(`{"type":"object","properties":{"did":{"type":"string"}},"required":["did"]}`),
		},
		{
			Name:        "discover_did_services",
			Description: "Resolve a did:web/did:webvh identifier's DID Document and return its declared service endpoints (e.g. a wallet's credential-offer or presentation endpoint).",
			InputSchema: rawJSON(`{"type":"object","properties":{"did":{"type":"string"}},"required":["did"]}`),
		},
		{
			Name:        "create_presentation_request",
			Description: "Mint an OpenID4VP authorization request a real wallet can respond to (returns openid4vp:// request URL + state). Requires the server to have a registered OpenID4VP verifier; errors otherwise. Optionally bind the presentation to transaction_data (payment/consent) per OpenID4VP 1.0. Poll get_presentation_result with the returned state to see the wallet's response.",
			InputSchema: rawJSON(`{"type":"object","properties":{"presentationDefinition":{"type":"object","description":"DIF Presentation Exchange 2.0 PresentationDefinition (id, purpose, requiredClaims, format)"},"acceptableIssuerKeys":{"type":"object","description":"issuer DID -> base64 Ed25519 public key, the trust anchor ProcessResponse verifies the presented credential's signature against"},"transactionData":{"type":"array","items":{"type":"object"},"description":"OpenID4VP 1.0 transaction_data: JSON objects (payment/consent details) the holder must approve; the presentation is cryptographically bound to them"}},"required":["presentationDefinition"]}`),
		},
		{
			Name:        "get_presentation_result",
			Description: "Retrieve a previously-created presentation request's result by state. Returns {status:\"pending\"} until a wallet responds and verification succeeds, or {status:\"success\", subject, issuer, claims}.",
			InputSchema: rawJSON(`{"type":"object","properties":{"state":{"type":"string"}},"required":["state"]}`),
		},
	}
}

func rawJSON(s string) json.RawMessage { return json.RawMessage(s) }

// ============================================================================
// Tool dispatch + auto-audit
// ============================================================================

func (s *Server) handleToolCall(id json.RawMessage, params json.RawMessage) *rpcResponse {
	var p toolCallParams
	if err := json.Unmarshal(params, &p); err != nil {
		return errorResp(id, errInvalidParams, "bad params", err.Error())
	}
	s.mu.RLock()
	lim := s.limiter
	s.mu.RUnlock()
	if lim != nil && !lim.Allow(p.Name) {
		return errorResp(id, errRateLimit, "rate limit exceeded for tool: "+p.Name, nil)
	}

	result, err := s.dispatch(p.Name, p.Arguments)
	if err != nil {
		// A rejected call changed no state, so it must NOT append to the
		// transparency log. Auditing before dispatch let unauthorized/invalid
		// mutating calls (unknown issuer, bad params, validation failures) pollute
		// the append-only ledger and amplify write cost (one Ed25519 sign + Merkle
		// append per rejected call) — a ledger-pollution / write-amplification DoS.
		return okResp(id, toolCallResult{
			Content: []contentBlock{{Type: "text", Text: err.Error()}},
			IsError: true,
		})
	}

	// Only state-changing tools that actually succeeded are recorded to the
	// transparency log. Read-only tools (verify_*, get_*, checkpoint) are never
	// audited — otherwise a client issuing cheap reads grows the ledger without
	// bound and amplifies the O(log n) cost of each append.
	if auditableTool[p.Name] {
		s.auditToolCall(p.Name, p.Arguments)
	}

	return okResp(id, toolCallResult{
		Content: []contentBlock{{Type: "text", Text: result}},
		IsError: false,
	})
}

// auditableTool lists the state-changing tools whose calls are recorded to the
// transparency log. Read-only tools are intentionally excluded.
var auditableTool = map[string]bool{
	"issue_passport":              true,
	"issue_battery_passport":      true,
	"attest_range":                true,
	"register_scitt":              true,
	"issue_sdjwt":                 true,
	"revoke_passport":             true,
	"create_credential_offer":     true,
	"issue_mdoc":                  true,
	"create_presentation_request": true,
	"create_did_webvh":            true,
	"update_did_webvh":            true,
	"sign_witness_proof":          true,
}

func (s *Server) auditToolCall(name string, args json.RawMessage) {
	b, _ := json.Marshal(struct {
		Tool string          `json:"tool"`
		Args json.RawMessage `json:"args"`
		At   time.Time       `json:"at"`
	}{Tool: name, Args: args, At: time.Now().UTC()})
	stmt, err := scitt.SignStatement(
		s.selfIssuer.PrivateKey(),
		s.selfIssuer.ID,
		"mcp.tool_call:"+name,
		"application/json",
		b,
	)
	if err != nil {
		return
	}
	_, _ = s.ledger.Register(stmt)
}

func (s *Server) dispatch(name string, args json.RawMessage) (string, error) {
	switch name {
	case "issue_passport":
		return s.toolIssuePassport(args)
	case "issue_battery_passport":
		return s.toolIssueBatteryPassport(args)
	case "verify_passport":
		return s.toolVerifyPassport(args)
	case "attest_range":
		return s.toolAttestRange(args)
	case "verify_range":
		return s.toolVerifyRange(args)
	case "register_scitt":
		return s.toolRegisterSCITT(args)
	case "get_scitt_receipt":
		return s.toolGetSCITTReceipt(args)
	case "search_passports":
		return s.toolSearchPassports(args)
	case "build_dpp_bundle":
		return s.toolBuildDPPBundle(args)
	case "anchor_dpp_bundle":
		return s.toolAnchorDPPBundle(args)
	case "verify_dpp_bundle":
		return s.toolVerifyDPPBundle(args)
	case "ledger_checkpoint":
		return s.toolCheckpoint(args)
	case "issue_sdjwt":
		return s.toolIssueSDJWT(args)
	case "verify_sdjwt":
		return s.toolVerifySDJWT(args)
	case "verify_passport_by_did":
		return s.toolVerifyPassportByDID(args)
	case "verify_sdjwt_by_did":
		return s.toolVerifySDJWTByDID(args)
	case "create_did_webvh":
		return s.toolCreateDIDWebVH(args)
	case "update_did_webvh":
		return s.toolUpdateDIDWebVH(args)
	case "verify_did_webvh_log":
		return s.toolVerifyDIDWebVHLog(args)
	case "sign_witness_proof":
		return s.toolSignWitnessProof(args)
	case "resolve_vct_metadata":
		return s.toolResolveVCTMetadata(args)
	case "validate_claims_against_vct":
		return s.toolValidateClaimsAgainstVCT(args)
	case "check_revocation":
		return s.toolCheckRevocation(args)
	case "revoke_passport":
		return s.toolRevokePassport(args)
	case "get_revocation_list":
		return s.toolGetRevocationList(args)
	case "get_server_capabilities":
		return s.toolServerCapabilities(args)
	case "create_credential_offer":
		return s.toolCreateCredentialOffer(args)
	case "issue_mdoc":
		return s.toolIssueMdoc(args)
	case "verify_mdoc":
		return s.toolVerifyMdoc(args)
	case "build_gs1_link":
		return s.toolBuildGS1Link(args)
	case "parse_gs1_link":
		return s.toolParseGS1Link(args)
	case "build_gs1_linkset":
		return s.toolBuildGS1Linkset(args)
	case "parse_gs1_linkset":
		return s.toolParseGS1Linkset(args)
	case "resolve_did":
		return s.toolResolveDID(args)
	case "discover_did_services":
		return s.toolDiscoverDIDServices(args)
	case "create_presentation_request":
		return s.toolCreatePresentationRequest(args)
	case "get_presentation_result":
		return s.toolGetPresentationResult(args)
	}
	return "", fmt.Errorf("unknown tool: %s", name)
}

// ============================================================================
// Tool implementations
// ============================================================================

func (s *Server) toolIssuePassport(args json.RawMessage) (string, error) {
	var in struct {
		IssuerID      string  `json:"issuerId"`
		ProductID     string  `json:"productId"`
		Category      string  `json:"category"`
		OriginCountry string  `json:"originCountry"`
		CarbonKgCO2e  float64 `json:"carbonKgCO2e"`
		Recyclability float32 `json:"recyclability"`
		ValidForDays  int     `json:"validForDays"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	if in.CarbonKgCO2e < 0 {
		return "", errors.New("mcp: carbonKgCO2e must be non-negative")
	}
	// Recyclability is a fraction in [0,1] (compliance.PassportClaim canonical
	// range), and the advertised inputSchema declares minimum:0/maximum:1. The
	// previous 0..100 bound contradicted both and let a value like 85 (meant as
	// "85%") be signed into a credential as "8500%" — invalid data in a permanent
	// signed artifact. Validate against the real range.
	if in.Recyclability < 0 || in.Recyclability > 1 {
		return "", errors.New("mcp: recyclability must be a fraction between 0 and 1")
	}
	s.mu.RLock()
	iss, ok := s.issuers[in.IssuerID]
	s.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("unknown issuer: %s", in.IssuerID)
	}
	validFor := time.Duration(in.ValidForDays) * 24 * time.Hour
	if in.ValidForDays == 0 {
		validFor = 365 * 24 * time.Hour
	}
	// Every issued passport is revocable: allocate a status-list bit and embed
	// a credentialStatus so revoke_passport can later flip it and
	// get_revocation_list can serve a token that check_revocation verifies.
	// statusListURL is a stable self-identifier, not a dereferenceable HTTP
	// URL — this server may run as stdio (cmd/blrcs-mcp) with no HTTP surface
	// at all, so the list is fetched via the get_revocation_list tool instead.
	index, err := s.allocateStatusIndex()
	if err != nil {
		return "", err
	}
	cred, err := iss.IssueWithStatus(compliance.PassportClaim{
		ProductID:     in.ProductID,
		Category:      in.Category,
		OriginCountry: in.OriginCountry,
		Manufacturer:  in.IssuerID,
		CarbonKgCO2e:  in.CarbonKgCO2e,
		Recyclability: in.Recyclability,
	}, validFor, s.selfIssuer.ID+"#revocation-list", index, string(revocation.PurposeRevocation))
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(cred)
	return string(b), nil
}

// toolIssueBatteryPassport issues an EU Battery Passport (Regulation (EU)
// 2023/1542, Annex XIII). compliance.BatteryPassportClaim/
// IssueBatteryPassport already implement this fully and are tested — this
// tool exposes that existing capability on the MCP surface, since previously
// an agent could only issue a plain compliance.PassportClaim via
// issue_passport (no chemistry, capacity, recycled content, due-diligence, or
// any other Annex XIII field). Date fields are RFC3339 strings; empty means
// unset (matches the Go struct's omitempty semantics).
func (s *Server) toolIssueBatteryPassport(args json.RawMessage) (string, error) {
	var in struct {
		IssuerID                    string  `json:"issuerId"`
		BatteryID                   string  `json:"batteryId"`
		GTIN                        string  `json:"gtin"`
		SerialNo                    string  `json:"serialNo"`
		Category                    string  `json:"category"`
		Chemistry                   string  `json:"chemistry"`
		CapacityKWh                 float32 `json:"capacityKWh"`
		VoltageV                    float32 `json:"voltageV"`
		WeightKg                    float32 `json:"weightKg"`
		PlaceOfManufacture          string  `json:"placeOfManufacture"`
		ModelID                     string  `json:"modelId"`
		DateOfManufacture           string  `json:"dateOfManufacture"`
		CommissioningDate           string  `json:"commissioningDate"`
		CarbonFootprintKgCO2ePerKWh float32 `json:"carbonFootprintKgCO2ePerKWh"`
		CarbonFootprintClass        string  `json:"carbonFootprintClass"`
		RecycledContent             *struct {
			Cobalt  float32 `json:"cobalt"`
			Lithium float32 `json:"lithium"`
			Nickel  float32 `json:"nickel"`
			Lead    float32 `json:"lead"`
		} `json:"recycledContent"`
		RenewableContentPct          float32  `json:"renewableContentPct"`
		HazardousSubstances          []string `json:"hazardousSubstances"`
		StateOfHealthPct             float32  `json:"stateOfHealthPct"`
		CycleCount                   int      `json:"cycleCount"`
		ExpectedLifetimeYears        float32  `json:"expectedLifetimeYears"`
		EUDeclarationOfConformityURL string   `json:"euDeclarationOfConformityUrl"`
		DueDiligenceReportURL        string   `json:"dueDiligenceReportUrl"`
		SeparateCollection           bool     `json:"separateCollection"`
		Recyclable                   bool     `json:"recyclable"`
		ValidForDays                 int      `json:"validForDays"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	s.mu.RLock()
	iss, ok := s.issuers[in.IssuerID]
	s.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("unknown issuer: %s", in.IssuerID)
	}
	dateOfMfr, err := parseOptionalRFC3339(in.DateOfManufacture)
	if err != nil {
		return "", fmt.Errorf("mcp: dateOfManufacture: %w", err)
	}
	commissioningDate, err := parseOptionalRFC3339(in.CommissioningDate)
	if err != nil {
		return "", fmt.Errorf("mcp: commissioningDate: %w", err)
	}
	claim := compliance.BatteryPassportClaim{
		BatteryID:                    in.BatteryID,
		GTIN:                         in.GTIN,
		SerialNo:                     in.SerialNo,
		Category:                     compliance.BatteryCategory(in.Category),
		Chemistry:                    compliance.BatteryChemistry(in.Chemistry),
		CapacityKWh:                  in.CapacityKWh,
		VoltageV:                     in.VoltageV,
		WeightKg:                     in.WeightKg,
		PlaceOfMfr:                   in.PlaceOfManufacture,
		ModelID:                      in.ModelID,
		DateOfMfr:                    dateOfMfr,
		CommissioningDate:            commissioningDate,
		CarbonFootprintKgCO2ePerKWh:  in.CarbonFootprintKgCO2ePerKWh,
		CarbonFootprintClass:         in.CarbonFootprintClass,
		RenewableContentPct:          in.RenewableContentPct,
		HazardousSubstances:          in.HazardousSubstances,
		StateOfHealthPct:             in.StateOfHealthPct,
		CycleCount:                   in.CycleCount,
		ExpectedLifetimeYears:        in.ExpectedLifetimeYears,
		EUDeclarationOfConformityURL: in.EUDeclarationOfConformityURL,
		DueDiligenceReportURL:        in.DueDiligenceReportURL,
		SeparateCollection:           in.SeparateCollection,
		Recyclable:                   in.Recyclable,
	}
	if in.RecycledContent != nil {
		claim.RecycledContent = compliance.RecycledContent{
			Cobalt:  in.RecycledContent.Cobalt,
			Lithium: in.RecycledContent.Lithium,
			Nickel:  in.RecycledContent.Nickel,
			Lead:    in.RecycledContent.Lead,
		}
	}
	validFor := time.Duration(in.ValidForDays) * 24 * time.Hour
	if in.ValidForDays == 0 {
		validFor = 365 * 24 * time.Hour
	}
	// Same revocability treatment as issue_passport/issue_sdjwt — shares the
	// same status-list index space.
	index, err := s.allocateStatusIndex()
	if err != nil {
		return "", err
	}
	cred, err := iss.IssueBatteryPassportWithStatus(claim, validFor, s.selfIssuer.ID+"#revocation-list", index, string(revocation.PurposeRevocation))
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(cred)
	return string(b), nil
}

// parseOptionalRFC3339 parses s as RFC3339 if non-empty; an empty string
// yields the zero time.Time (matching BatteryPassportClaim's omitempty date
// fields — "not specified", not "epoch").
func parseOptionalRFC3339(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, s)
}

func (s *Server) toolVerifyPassport(args json.RawMessage) (string, error) {
	var in struct {
		CredentialJson     string `json:"credentialJson"`
		IssuerPublicKeyB64 string `json:"issuerPublicKeyB64"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	var cred compliance.Credential
	if err := json.Unmarshal([]byte(in.CredentialJson), &cred); err != nil {
		return "", err
	}
	pub, err := base64.StdEncoding.DecodeString(in.IssuerPublicKeyB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return "", errors.New("bad public key")
	}
	if err := compliance.Verify(&cred, ed25519.PublicKey(pub)); err != nil {
		// 検証失敗は MCP ツールの構造化結果として返す (Go の error ではない)。
		// err.Error() は攻撃者由来の入力を含み得るため必ず json.Marshal でエスケープ。
		return verifyResult(false, err.Error()), nil //nolint:nilerr
	}
	return `{"valid":true}`, nil
}

// toolIssueMdoc issues an ISO 18013-5 mdoc (IssuerSigned + MSO), previously
// only reachable via the mdoc package directly (exercised by doctor's
// self-check, never exposed as an MCP tool). Namespaces arrive as nested JSON
// objects (namespace → elementIdentifier → value) and are converted to
// mdoc.IssueParams's []Element form. Returns the IssuerSigned CBOR, base64
// encoded so it travels over JSON-RPC.
func (s *Server) toolIssueMdoc(args json.RawMessage) (string, error) {
	var in struct {
		IssuerID     string                    `json:"issuerId"`
		DocType      string                    `json:"docType"`
		NameSpaces   map[string]map[string]any `json:"nameSpaces"`
		ValidForDays int                       `json:"validForDays"`
		DeviceKeyB64 string                    `json:"deviceKeyB64"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	if in.DocType == "" {
		return "", errors.New("mcp: docType is required")
	}
	s.mu.RLock()
	iss, ok := s.issuers[in.IssuerID]
	s.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("unknown issuer: %s", in.IssuerID)
	}
	nameSpaces := make(map[string][]mdoc.Element, len(in.NameSpaces))
	for ns, elems := range in.NameSpaces {
		els := make([]mdoc.Element, 0, len(elems))
		for id, val := range elems {
			els = append(els, mdoc.Element{Identifier: id, Value: val})
		}
		nameSpaces[ns] = els
	}
	var deviceKey ed25519.PublicKey
	if in.DeviceKeyB64 != "" {
		dk, derr := base64.StdEncoding.DecodeString(in.DeviceKeyB64)
		if derr != nil || len(dk) != ed25519.PublicKeySize {
			return "", errors.New("mcp: bad deviceKeyB64")
		}
		deviceKey = dk
	}
	validFor := time.Duration(in.ValidForDays) * 24 * time.Hour
	if in.ValidForDays == 0 {
		validFor = 365 * 24 * time.Hour
	}
	now := time.Now().UTC()
	doc, err := mdoc.Issue(mdoc.IssueParams{
		DocType:    in.DocType,
		NameSpaces: nameSpaces,
		Validity: mdoc.ValidityInfo{
			Signed:     now,
			ValidFrom:  now,
			ValidUntil: now.Add(validFor),
		},
		DeviceKey:  deviceKey,
		IssuerPriv: iss.PrivateKey(),
	})
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(map[string]string{
		"issuerSignedB64": base64.StdEncoding.EncodeToString(doc),
	})
	return string(b), nil
}

// toolVerifyMdoc verifies an ISO 18013-5 mdoc against an issuer public key.
// Structural/signature failures return a structured {"valid":false,...}
// result rather than a Go error, matching verify_passport's contract.
func (s *Server) toolVerifyMdoc(args json.RawMessage) (string, error) {
	var in struct {
		IssuerSignedB64    string `json:"issuerSignedB64"`
		IssuerPublicKeyB64 string `json:"issuerPublicKeyB64"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	doc, err := base64.StdEncoding.DecodeString(in.IssuerSignedB64)
	if err != nil {
		return "", errors.New("mcp: bad issuerSignedB64")
	}
	pub, err := base64.StdEncoding.DecodeString(in.IssuerPublicKeyB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return "", errors.New("mcp: bad public key")
	}
	verified, err := mdoc.Verify(doc, ed25519.PublicKey(pub), time.Now().UTC())
	if err != nil {
		return verifyResult(false, err.Error()), nil //nolint:nilerr
	}
	b, _ := json.Marshal(map[string]any{
		"valid":      true,
		"docType":    verified.DocType,
		"nameSpaces": verified.NameSpaces,
	})
	return string(b), nil
}

// toolBuildGS1Link builds a GS1 Digital Link URI (ISO/IEC 18975) from a
// domain and key (GTIN/serial/batch) — previously only reachable via the
// compliance package directly, with no MCP wiring despite README listing
// "GS1 Digital Link (ISO/IEC 18975) ✅" as a shipped feature.
func (s *Server) toolBuildGS1Link(args json.RawMessage) (string, error) {
	var in struct {
		Domain string `json:"domain"`
		GTIN   string `json:"gtin"`
		Serial string `json:"serial"`
		Batch  string `json:"batch"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	uri, err := compliance.BuildDLURI(in.Domain, compliance.GS1Key{GTIN: in.GTIN, Serial: in.Serial, Batch: in.Batch})
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(map[string]string{"uri": uri})
	return string(b), nil
}

// toolParseGS1Link parses a GS1 Digital Link URI back into its domain and key.
func (s *Server) toolParseGS1Link(args json.RawMessage) (string, error) {
	var in struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	domain, key, err := compliance.ParseDLURI(in.URI)
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(map[string]string{
		"domain": domain,
		"gtin":   key.GTIN,
		"serial": key.Serial,
		"batch":  key.Batch,
	})
	return string(b), nil
}

// toolBuildGS1Linkset builds a GS1 Digital Link Linkset (RFC 9264
// application/linkset+json) — previously only reachable via the compliance
// package directly, despite compliance/linkset.go being a complete, tested
// implementation with no MCP tool or HTTP handler ever wiring it up. This is
// the standard DPP discovery mechanism: anchor URI -> linkType -> resources
// (passport, declaration of conformity, due-diligence statement, ...).
func (s *Server) toolBuildGS1Linkset(args json.RawMessage) (string, error) {
	var in struct {
		Anchor string                       `json:"anchor"`
		Links  map[string][]compliance.Link `json:"links"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	if in.Anchor == "" {
		return "", errors.New("mcp: anchor is required")
	}
	ls := compliance.NewLinkset(in.Anchor)
	for linkType, links := range in.Links {
		for _, l := range links {
			ls.Add(linkType, l)
		}
	}
	b, err := json.Marshal(ls)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// toolParseGS1Linkset parses a GS1 Digital Link Linkset (RFC 9264
// application/linkset+json) back into its anchor URI and linkType -> links map.
func (s *Server) toolParseGS1Linkset(args json.RawMessage) (string, error) {
	var in struct {
		LinksetJSON string `json:"linksetJson"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	ls, err := compliance.ParseLinkset([]byte(in.LinksetJSON))
	if err != nil {
		return "", err
	}
	links := make(map[string][]compliance.Link, len(ls.LinkTypes()))
	for _, lt := range ls.LinkTypes() {
		links[lt] = ls.Get(lt)
	}
	b, err := json.Marshal(map[string]any{
		"anchor": ls.Anchor,
		"links":  links,
	})
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// toolResolveDID resolves a did:web/did:webvh/did:key/did:jwk identifier to
// its Ed25519 public key(s) — previously only reachable via the didresolver
// package directly. Deliberately does NOT gate on a trust anchor: the caller
// decides whether to trust the result, same as verify_passport/verify_mdoc
// require the caller to already have a public key rather than deciding trust
// server-side. Safe to expose unconditionally because didresolver's default
// fetcher is SSRF-hardened (validates the resolved IP before connecting).
func (s *Server) toolResolveDID(args json.RawMessage) (string, error) {
	var in struct {
		DID string `json:"did"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	if in.DID == "" {
		return "", errors.New("mcp: did is required")
	}
	keys, err := s.didResolver.ResolveAll(context.Background(), in.DID)
	if err != nil {
		return "", err
	}
	b64Keys := make([]string, len(keys))
	for i, k := range keys {
		b64Keys[i] = base64.StdEncoding.EncodeToString(k)
	}
	b, _ := json.Marshal(map[string]any{"publicKeysB64": b64Keys})
	return string(b), nil
}

// toolDiscoverDIDServices resolves a did:web identifier's DID Document and
// returns its declared service endpoints (e.g. a wallet's credential-offer
// or presentation endpoint) — the complementary read to resolve_did (keys)
// for the service-discovery half of a DID Document. Same SSRF-hardened
// fetcher as resolve_did; no TrustAnchor gating for the same reason
// resolve_did has none (the caller decides what to do with the result).
func (s *Server) toolDiscoverDIDServices(args json.RawMessage) (string, error) {
	var in struct {
		DID string `json:"did"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	if in.DID == "" {
		return "", errors.New("mcp: did is required")
	}
	services, err := s.didResolver.ResolveServices(context.Background(), in.DID)
	if err != nil {
		return "", err
	}
	out := make([]map[string]string, len(services))
	for i, svc := range services {
		out[i] = map[string]string{
			"id":              svc.ID,
			"type":            svc.Type,
			"serviceEndpoint": svc.ServiceEndpoint,
		}
	}
	b, _ := json.Marshal(map[string]any{"services": out})
	return string(b), nil
}

// toolVerifyPassportByDID verifies a credential using its issuer field's DID
// as the trust root, instead of requiring the caller to already have the
// issuer's raw public key (verify_passport's contract) — resolves via
// s.didResolver, then only accepts keys s.trustAnchor deems trusted for that
// DID (see the Server.trustAnchor field doc for the default allow-all
// posture). Rotation-tolerant: tries every trusted key ResolveAndVerifyAll
// returns, succeeding if any one verifies (mirrors compose.VerifyByDID).
func (s *Server) toolVerifyPassportByDID(args json.RawMessage) (string, error) {
	var in struct {
		CredentialJson string `json:"credentialJson"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	var cred compliance.Credential
	if err := json.Unmarshal([]byte(in.CredentialJson), &cred); err != nil {
		return "", err
	}
	if cred.Issuer == "" {
		return "", errors.New("mcp: credential has no issuer")
	}
	s.mu.RLock()
	resolver, anchor := s.didResolver, s.trustAnchor
	s.mu.RUnlock()
	keys, err := didresolver.ResolveAndVerifyAll(context.Background(), resolver, anchor, cred.Issuer)
	if err != nil {
		return verifyResult(false, err.Error()), nil //nolint:nilerr
	}
	var verr error
	for _, pub := range keys {
		if verr = compliance.Verify(&cred, pub); verr == nil {
			return `{"valid":true}`, nil
		}
	}
	return verifyResult(false, verr.Error()), nil
}

// toolVerifySDJWTByDID is verify_sdjwt's DID-resolving counterpart: same
// nonce/audience binding options, but the issuer public key comes from
// resolving+trust-checking issuerDID instead of being supplied directly.
func (s *Server) toolVerifySDJWTByDID(args json.RawMessage) (string, error) {
	var in struct {
		SDJWT            string `json:"sdjwt"`
		IssuerDID        string `json:"issuerDid"`
		ExpectedNonce    string `json:"expectedNonce"`
		ExpectedAudience string `json:"expectedAudience"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	if in.IssuerDID == "" {
		return "", errors.New("mcp: issuerDid is required")
	}
	s.mu.RLock()
	resolver, anchor := s.didResolver, s.trustAnchor
	s.mu.RUnlock()
	keys, err := didresolver.ResolveAndVerifyAll(context.Background(), resolver, anchor, in.IssuerDID)
	if err != nil {
		return verifyResult(false, err.Error()), nil //nolint:nilerr
	}
	opts := compliance.VerifyOptions{
		ExpectedNonce:    in.ExpectedNonce,
		ExpectedAudience: in.ExpectedAudience,
	}
	var vc *compliance.VerifiedClaims
	var verr error
	for _, pub := range keys {
		if vc, verr = compliance.VerifySDJWTWithBinding(in.SDJWT, pub, opts); verr == nil {
			b, _ := json.Marshal(map[string]any{
				"valid":    true,
				"issuer":   vc.Issuer,
				"subject":  vc.Subject,
				"claims":   vc.Claims,
				"keyBound": vc.KeyBound,
				"issuedAt": vc.IssuedAt,
				"expires":  vc.Expires,
			})
			return string(b), nil
		}
	}
	return verifyResult(false, verr.Error()), nil
}

// toolCreateDIDWebVH creates a new did:webvh genesis log entry — previously
// only reachable via the didwebvh package directly, despite README listing
// "did:webvh (verifiable history + pre-rotation) ✅". The signing key is a
// pre-registered issuer's private key (never a raw key over the JSON-RPC
// wire), matching how issue_passport/issue_sdjwt/issue_mdoc already work.
// Returns the new DID and a one-entry log the caller must keep and pass to
// subsequent update_did_webvh/verify_did_webvh_log calls — this server does
// not persist did:webvh logs itself (same statelessness contract as
// credentialJson round-tripping through verify_passport).
func (s *Server) toolCreateDIDWebVH(args json.RawMessage) (string, error) {
	var in struct {
		IssuerID      string            `json:"issuerId"`
		DIDPath       string            `json:"didPath"`
		NextKeyHashes []string          `json:"nextKeyHashes"`
		StateExtra    map[string]any    `json:"stateExtra"`
		Witness       *didwebvh.Witness `json:"witness"`
		// Portable declares whether this DID may later be moved to a different
		// domain/path while retaining its SCID (spec §DID Portability). Omitted
		// or false leaves portability disabled (the spec default) — only the
		// genesis entry may ever set this true.
		Portable *bool `json:"portable"`
		// Watchers optionally lists watcher URLs monitoring this DID (spec
		// §Parameters). Omitted leaves the active list empty; a (possibly empty)
		// array sets it. Watchers are exposed in verify_did_webvh_log's result
		// but are not a verification gate.
		Watchers *[]string `json:"watchers"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	if in.DIDPath == "" {
		return "", errors.New("mcp: didPath is required")
	}
	s.mu.RLock()
	iss, ok := s.issuers[in.IssuerID]
	s.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("unknown issuer: %s", in.IssuerID)
	}
	entry, did, err := didwebvh.Create(didwebvh.CreateParams{
		DIDPath:       in.DIDPath,
		UpdateKey:     iss.PrivateKey(),
		NextKeyHashes: in.NextKeyHashes,
		StateExtra:    in.StateExtra,
		Witness:       in.Witness,
		Portable:      in.Portable,
		Watchers:      in.Watchers,
	})
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(map[string]any{
		"did": did,
		"log": []didwebvh.LogEntry{*entry},
	})
	return string(b), nil
}

// toolUpdateDIDWebVH appends a new signed entry to an existing did:webvh log
// (key rotation, document update, or deactivation). signKeyIssuerId must be
// a registered issuer whose key currently holds update authority over log
// (didwebvh.Update itself rejects otherwise) — this may be a different
// issuer than the one that created the log, if authority already rotated.
func (s *Server) toolUpdateDIDWebVH(args json.RawMessage) (string, error) {
	var in struct {
		SignKeyIssuerID string              `json:"signKeyIssuerId"`
		Log             []didwebvh.LogEntry `json:"log"`
		NewState        map[string]any      `json:"newState"`
		UpdateKeys      []string            `json:"updateKeys"`
		NextKeyHashes   []string            `json:"nextKeyHashes"`
		Deactivate      bool                `json:"deactivate"`
		Witness         *didwebvh.Witness   `json:"witness"`
		// Portable (re)declares the portability parameter from this entry on.
		// Omitted retains whatever value was previously in effect; false
		// permanently disables further moves. true is rejected here by
		// didwebvh.Update's underlying Verify contract — only the genesis entry
		// may ever set it.
		Portable *bool `json:"portable"`
		// Watchers (re)declares the watcher URL list from this entry on. Omitted
		// retains the prior value; a (possibly empty) array replaces it — an empty
		// array clears the list.
		Watchers *[]string `json:"watchers"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	if len(in.Log) == 0 {
		return "", errors.New("mcp: log is required")
	}
	s.mu.RLock()
	iss, ok := s.issuers[in.SignKeyIssuerID]
	s.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("unknown issuer: %s", in.SignKeyIssuerID)
	}
	entry, err := didwebvh.Update(didwebvh.UpdateParams{
		Log:           in.Log,
		SignKey:       iss.PrivateKey(),
		NewState:      in.NewState,
		UpdateKeys:    in.UpdateKeys,
		NextKeyHashes: in.NextKeyHashes,
		Deactivate:    in.Deactivate,
		Witness:       in.Witness,
		Portable:      in.Portable,
		Watchers:      in.Watchers,
	})
	if err != nil {
		return "", err
	}
	newLog := make([]didwebvh.LogEntry, 0, len(in.Log)+1)
	newLog = append(newLog, in.Log...)
	newLog = append(newLog, *entry)
	b, _ := json.Marshal(map[string]any{"log": newLog})
	return string(b), nil
}

// toolVerifyDIDWebVHLog validates a complete did:webvh log (SCID
// self-certification, entry hash-chaining, sequential versions, monotonic
// versionTime, update-key authorization, pre-rotation commitments) and
// returns the resolved DID document. Structural/signature failures return a
// structured {"valid":false,...} result, matching verify_passport's contract.
func (s *Server) toolVerifyDIDWebVHLog(args json.RawMessage) (string, error) {
	var in struct {
		Log        []didwebvh.LogEntry `json:"log"`
		WitnessLog didwebvh.WitnessLog `json:"witnessLog"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	// VerifyWithWitnesses with a nil/empty WitnessLog behaves exactly like
	// Verify for any log where no entry declares Parameters.Witness, so this
	// one call correctly serves both the witnessed and unwitnessed cases.
	res, err := didwebvh.VerifyWithWitnesses(in.Log, in.WitnessLog)
	if err != nil {
		return verifyResult(false, err.Error()), nil //nolint:nilerr
	}
	b, _ := json.Marshal(map[string]any{
		"valid":       true,
		"did":         res.DID,
		"scid":        res.SCID,
		"document":    res.Document,
		"versionId":   res.VersionID,
		"versionTime": res.VersionTime,
		"deactivated": res.Deactivated,
		"watchers":    res.Watchers,
	})
	return string(b), nil
}

// toolSignWitnessProof produces one witness's Data Integrity proof for a
// did:webvh log entry, per did:webvh v1.0 §Witnesses — previously
// unreachable, since the didwebvh package didn't implement witness support
// at all until this axis. witnessIssuerId reuses the same pre-registered-key
// mechanism as issue_passport/create_did_webvh: an operator registers a
// witness's identity as an Issuer via RegisterIssuer, with its ID set to that
// witness's did:key DID (the spec's own identifier scheme for witnesses —
// registering it as an "Issuer" here is just this server's existing key
// storage/lookup mechanism, not a claim that witnesses issue credentials).
// The caller is responsible for collecting proofs from each required witness
// and assembling them into a WitnessLog (did-witness.json) to pass to
// verify_did_webvh_log's witnessLog argument — this server does not persist
// did-witness.json itself, the same statelessness contract create_did_webvh/
// update_did_webvh already have for the log itself.
func (s *Server) toolSignWitnessProof(args json.RawMessage) (string, error) {
	var in struct {
		WitnessIssuerID      string             `json:"witnessIssuerId"`
		Entry                *didwebvh.LogEntry `json:"entry"`
		PredecessorVersionID string             `json:"predecessorVersionId"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	if in.Entry == nil {
		return "", errors.New("mcp: entry is required")
	}
	s.mu.RLock()
	iss, ok := s.issuers[in.WitnessIssuerID]
	s.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("unknown issuer: %s", in.WitnessIssuerID)
	}
	proof, err := didwebvh.SignWitnessProof(in.Entry, in.PredecessorVersionID, iss.PrivateKey(), iss.ID)
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(map[string]any{"proof": proof})
	return string(b), nil
}

// toolResolveVCTMetadata resolves an SD-JWT-VC `vct` claim to its Type
// Metadata document (draft-ietf-oauth-sd-jwt-vc §Type Metadata) —
// previously only reachable via the vctmeta package directly, despite
// README listing "SD-JWT-VC Type Metadata + schema validation ✅". Only
// safe to expose now that Axis 112 hardened vctmeta's default fetcher
// against SSRF (direct resolution to private/loopback/metadata addresses),
// mirroring resolve_did's relationship to Axis 107.
func (s *Server) toolResolveVCTMetadata(args json.RawMessage) (string, error) {
	var in struct {
		VCT               string `json:"vct"`
		ExpectedIntegrity string `json:"expectedIntegrity"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	if in.VCT == "" {
		return "", errors.New("mcp: vct is required")
	}
	s.mu.RLock()
	fetch := s.vctFetcher
	s.mu.RUnlock()
	tm, err := vctmeta.Resolve(context.Background(), in.VCT, in.ExpectedIntegrity, fetch)
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(map[string]any{
		"vct":         tm.VCT,
		"name":        tm.Name,
		"description": tm.Description,
		"extends":     tm.Extends,
		"hasSchema":   tm.HasSchema(),
		"schema":      tm.Schema,
		"schemaUri":   tm.SchemaURI,
	})
	return string(b), nil
}

// toolValidateClaimsAgainstVCT resolves a vct's Type Metadata (and, if the
// schema is only referenced via schema_uri, fetches that too) and validates
// claims against its JSON Schema — the natural complement to verify_sdjwt:
// after checking the signature, check the disclosed claims actually conform
// to the credential's declared type. Structural/validation failures return a
// structured {"valid":false,...} result, matching verify_passport's contract.
func (s *Server) toolValidateClaimsAgainstVCT(args json.RawMessage) (string, error) {
	var in struct {
		VCT               string         `json:"vct"`
		ExpectedIntegrity string         `json:"expectedIntegrity"`
		Claims            map[string]any `json:"claims"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	if in.VCT == "" {
		return "", errors.New("mcp: vct is required")
	}
	s.mu.RLock()
	fetch := s.vctFetcher
	s.mu.RUnlock()
	tm, err := vctmeta.Resolve(context.Background(), in.VCT, in.ExpectedIntegrity, fetch)
	if err != nil {
		return verifyResult(false, err.Error()), nil //nolint:nilerr
	}
	if err := tm.ResolveAndValidate(context.Background(), in.Claims, fetch); err != nil {
		return verifyResult(false, err.Error()), nil //nolint:nilerr
	}
	return `{"valid":true}`, nil
}

// verifyResult builds a structured {"valid":..,"reason":..} result with the
// reason properly JSON-escaped (never string concatenation — the reason carries
// attacker-controlled error text).
func verifyResult(valid bool, reason string) string {
	b, err := json.Marshal(struct {
		Valid  bool   `json:"valid"`
		Reason string `json:"reason,omitempty"`
	}{Valid: valid, Reason: reason})
	if err != nil {
		return `{"valid":false,"reason":"internal error"}`
	}
	return string(b)
}

func (s *Server) toolAttestRange(args json.RawMessage) (string, error) {
	var in struct {
		AttesterID string  `json:"attesterId"`
		Value      float64 `json:"value"`
		Min        float64 `json:"min"`
		Max        float64 `json:"max"`
		Unit       string  `json:"unit"`
		Name       string  `json:"name"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	if in.Min > in.Max {
		return "", errors.New("mcp: min must be <= max")
	}
	s.mu.RLock()
	att, ok := s.attesters[in.AttesterID]
	s.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("unknown attester: %s", in.AttesterID)
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	stmt := compliance.RangeStatement{Min: in.Min, Max: in.Max, Unit: in.Unit, Name: in.Name}
	commit := compliance.Commit(in.Value, salt, stmt)
	proof, err := att.Attest(commit, in.Value)
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(proof)
	return string(b), nil
}

func (s *Server) toolVerifyRange(args json.RawMessage) (string, error) {
	var in struct {
		ProofJson            string `json:"proofJson"`
		AttesterPublicKeyB64 string `json:"attesterPublicKeyB64"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	var proof compliance.RangeProof
	if err := json.Unmarshal([]byte(in.ProofJson), &proof); err != nil {
		return "", err
	}
	pub, err := base64.StdEncoding.DecodeString(in.AttesterPublicKeyB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return "", errors.New("bad attester key")
	}
	if err := compliance.VerifyRange(&proof, ed25519.PublicKey(pub)); err != nil {
		// 検証失敗は MCP ツールの構造化結果として返す (Go の error ではない)。
		return verifyResult(false, err.Error()), nil //nolint:nilerr
	}
	return `{"valid":true}`, nil
}

func (s *Server) toolRegisterSCITT(args json.RawMessage) (string, error) {
	var in struct {
		IssuerID    string `json:"issuerId"`
		Subject     string `json:"subject"`
		ContentType string `json:"contentType"`
		Payload     string `json:"payload"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	s.mu.RLock()
	iss, ok := s.issuers[in.IssuerID]
	s.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("unknown issuer: %s", in.IssuerID)
	}
	if in.ContentType == "" {
		in.ContentType = "application/octet-stream"
	}
	stmt, err := scitt.SignStatement(iss.PrivateKey(), iss.ID, in.Subject, in.ContentType, []byte(in.Payload))
	if err != nil {
		return "", err
	}
	receipt, err := s.ledger.Register(stmt)
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(map[string]any{"statement": stmt, "receipt": receipt})
	return string(b), nil
}

func (s *Server) toolGetSCITTReceipt(args json.RawMessage) (string, error) {
	var in struct {
		LeafIndex uint64 `json:"leafIndex"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	stmt, receipt, err := s.ledger.Get(in.LeafIndex)
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(map[string]any{
		"statement": stmt,
		"receipt":   receipt,
		"tsKey":     base64.StdEncoding.EncodeToString(s.ledger.PublicKey()),
	})
	return string(b), nil
}

func (s *Server) toolCheckpoint(_ json.RawMessage) (string, error) {
	cp := s.ledger.SignedCheckpoint()
	b, _ := json.Marshal(cp)
	return string(b), nil
}

// toolSearchPassports queries the SCITT ledger's secondary index for statements
// by subject (productId/batteryId) and/or issuer (manufacturer DID) — the DPP
// lifecycle-searchability capability (CEN-CENELEC EN 18222). Returns matching
// {index, issuer, subject, iat, payloadHash} entries; use each index with
// get_scitt_receipt to fetch the full statement + inclusion proof. When both
// subject and issuer are given, returns their intersection (statements matching
// both). At least one filter is required.
func (s *Server) toolSearchPassports(args json.RawMessage) (string, error) {
	var in struct {
		Subject string `json:"subject"`
		Issuer  string `json:"issuer"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	if in.Subject == "" && in.Issuer == "" {
		return "", errors.New("mcp: search_passports requires at least one of subject or issuer")
	}
	var results []scitt.SearchResult
	switch {
	case in.Subject != "" && in.Issuer != "":
		// Intersection: filter the (usually smaller) subject match set by issuer.
		for _, r := range s.ledger.FindBySubject(in.Subject) {
			if r.Issuer == in.Issuer {
				results = append(results, r)
			}
		}
	case in.Subject != "":
		results = s.ledger.FindBySubject(in.Subject)
	default:
		results = s.ledger.FindByIssuer(in.Issuer)
	}
	b, _ := json.Marshal(map[string]any{
		"count":   len(results),
		"results": results,
	})
	return string(b), nil
}

// ============================================================================
// Long-term offline DPP bundle tools (Axis 134)
//
// See the blrcs/bundle package doc for the design rationale: ETSI long-term
// validation needs a trusted timestamp alongside the key chain and revocation
// data, and RFC 4998 requires renewing that timestamp as a chain before the
// in-use algorithms weaken. This server's SCITT ledger acts as the TSA.
// ============================================================================

func (s *Server) toolBuildDPPBundle(args json.RawMessage) (string, error) {
	var in struct {
		Credential string `json:"credential"`
		// IssuerID names a registered issuer whose public key the server looks
		// up. Preferred over IssuerPublicKeyB64: nothing else in the tool
		// surface hands a caller the raw key, so requiring it would make this
		// tool effectively uncallable by an agent.
		IssuerID           string              `json:"issuerId"`
		IssuerPublicKeyB64 string              `json:"issuerPublicKeyB64"`
		StatusToken        string              `json:"statusToken"`
		StatusPublicKeyB64 string              `json:"statusPublicKeyB64"`
		IssuerDIDLog       []didwebvh.LogEntry `json:"issuerDidLog"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	var issuerKey []byte
	switch {
	case in.IssuerID != "":
		s.mu.RLock()
		iss, ok := s.issuers[in.IssuerID]
		s.mu.RUnlock()
		if !ok {
			return "", fmt.Errorf("unknown issuer: %s", in.IssuerID)
		}
		issuerKey = iss.PublicKey()
	case in.IssuerPublicKeyB64 != "":
		k, err := base64.StdEncoding.DecodeString(in.IssuerPublicKeyB64)
		if err != nil {
			return "", fmt.Errorf("mcp: issuerPublicKeyB64: %w", err)
		}
		issuerKey = k
	default:
		return "", errors.New("mcp: either issuerId or issuerPublicKeyB64 is required")
	}
	opts := bundle.BuildOptions{StatusToken: in.StatusToken, IssuerDIDLog: in.IssuerDIDLog}
	if in.StatusPublicKeyB64 != "" {
		sk, err := base64.StdEncoding.DecodeString(in.StatusPublicKeyB64)
		if err != nil {
			return "", fmt.Errorf("mcp: statusPublicKeyB64: %w", err)
		}
		opts.StatusKey = sk
	}
	b, err := bundle.Build(in.Credential, issuerKey, opts)
	if err != nil {
		return "", err
	}
	raw, err := b.Marshal()
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// toolAnchorDPPBundle takes (or renews) the archive timestamp using this
// server's transparency ledger, returning the extended bundle.
func (s *Server) toolAnchorDPPBundle(args json.RawMessage) (string, error) {
	var in struct {
		BundleJSON string `json:"bundleJson"`
		IssuerID   string `json:"issuerId"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	s.mu.RLock()
	iss, ok := s.issuers[in.IssuerID]
	s.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("unknown issuer: %s", in.IssuerID)
	}
	b, err := bundle.Parse([]byte(in.BundleJSON))
	if err != nil {
		return "", err
	}
	if err := b.Anchor(s.ledger, iss.PrivateKey(), iss.ID); err != nil {
		return "", err
	}
	raw, err := b.Marshal()
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func (s *Server) toolVerifyDPPBundle(args json.RawMessage) (string, error) {
	var in struct {
		BundleJSON             string `json:"bundleJson"`
		RequireProvenance      bool   `json:"requireProvenance"`
		RequireRevocationCheck bool   `json:"requireRevocationCheck"`
		RequireTimestamp       bool   `json:"requireTimestamp"`
		MaxStatusAgeSeconds    int    `json:"maxStatusAgeSeconds"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	b, err := bundle.Parse([]byte(in.BundleJSON))
	if err != nil {
		return verifyResult(false, err.Error()), nil //nolint:nilerr
	}
	res, err := bundle.Verify(b, bundle.Options{
		RequireProvenance:      in.RequireProvenance,
		RequireRevocationCheck: in.RequireRevocationCheck,
		RequireTimestamp:       in.RequireTimestamp,
		MaxStatusAge:           time.Duration(in.MaxStatusAgeSeconds) * time.Second,
	})
	if err != nil {
		return verifyResult(false, err.Error()), nil //nolint:nilerr
	}
	out := map[string]any{
		"valid":             true,
		"subject":           res.Claims.Subject,
		"issuer":            res.Claims.Issuer,
		"vct":               res.Claims.VCT,
		"claims":            res.Claims.Claims,
		"checkedProvenance": res.CheckedProvenance,
		"checkedRevocation": res.CheckedRevocation,
		"checkedTimestamp":  res.CheckedTimestamp,
		"revoked":           res.Revoked,
		"anchorCount":       res.AnchorCount,
	}
	if res.CheckedProvenance {
		out["issuerDid"] = res.IssuerDID
	}
	if res.CheckedTimestamp && len(res.AnchorTimes) > 0 {
		out["earliestAnchor"] = res.AnchorTimes[0]
	}
	bs, _ := json.Marshal(out)
	return string(bs), nil
}

// ============================================================================
// SD-JWT tools
// ============================================================================

func (s *Server) toolIssueSDJWT(args json.RawMessage) (string, error) {
	var in struct {
		IssuerID     string         `json:"issuerId"`
		Subject      string         `json:"subject"`
		SDClaims     map[string]any `json:"sdClaims"`
		ClearClaims  map[string]any `json:"clearClaims"`
		ValidForDays int            `json:"validForDays"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	if in.Subject == "" {
		return "", errors.New("mcp: subject is required")
	}
	s.mu.RLock()
	iss, ok := s.issuers[in.IssuerID]
	s.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("unknown issuer: %s", in.IssuerID)
	}
	validFor := time.Duration(in.ValidForDays) * 24 * time.Hour
	if in.ValidForDays == 0 {
		validFor = 365 * 24 * time.Hour
	}
	if in.SDClaims == nil {
		in.SDClaims = map[string]any{}
	}
	if in.ClearClaims == nil {
		in.ClearClaims = map[string]any{}
	}
	// Draws from the same shared status-list index space as issue_passport —
	// revoke_passport and check_revocation work identically regardless of
	// which tool issued the credential.
	index, err := s.allocateStatusIndex()
	if err != nil {
		return "", err
	}
	statusRef := &compliance.StatusRef{URI: s.selfIssuer.ID + "#revocation-list", Index: index}
	sdjwt, discs, err := iss.IssueSDJWTStatus(in.Subject, in.SDClaims, in.ClearClaims, statusRef, validFor)
	if err != nil {
		return "", err
	}
	discNames := make([]string, len(discs))
	for i, d := range discs {
		discNames[i] = d.Name
	}
	b, _ := json.Marshal(map[string]any{
		"sdjwt":             sdjwt,
		"disclosableFields": discNames,
		"statusListIndex":   index,
	})
	return string(b), nil
}

func (s *Server) toolVerifySDJWT(args json.RawMessage) (string, error) {
	var in struct {
		SDJWT              string `json:"sdjwt"`
		IssuerPublicKeyB64 string `json:"issuerPublicKeyB64"`
		ExpectedNonce      string `json:"expectedNonce"`
		ExpectedAudience   string `json:"expectedAudience"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	pub, err := base64.StdEncoding.DecodeString(in.IssuerPublicKeyB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return "", errors.New("bad issuer public key")
	}
	opts := compliance.VerifyOptions{
		ExpectedNonce:    in.ExpectedNonce,
		ExpectedAudience: in.ExpectedAudience,
	}
	vc, err := compliance.VerifySDJWTWithBinding(in.SDJWT, ed25519.PublicKey(pub), opts)
	if err != nil {
		return verifyResult(false, err.Error()), nil //nolint:nilerr
	}
	b, _ := json.Marshal(map[string]any{
		"valid":    true,
		"issuer":   vc.Issuer,
		"subject":  vc.Subject,
		"claims":   vc.Claims,
		"keyBound": vc.KeyBound,
		"issuedAt": vc.IssuedAt,
		"expires":  vc.Expires,
	})
	return string(b), nil
}

func (s *Server) toolCheckRevocation(args json.RawMessage) (string, error) {
	var in struct {
		StatusListTokenJWT     string `json:"statusListTokenJWT"`
		StatusListIssuerKeyB64 string `json:"statusListIssuerKeyB64"`
		StatusIndex            int    `json:"statusIndex"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	pub, err := base64.StdEncoding.DecodeString(in.StatusListIssuerKeyB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return "", errors.New("bad status list issuer key")
	}
	if in.StatusIndex < 0 {
		return "", errors.New("mcp: statusIndex must be non-negative")
	}
	list, _, err := revocation.VerifyStatusListToken(in.StatusListTokenJWT, ed25519.PublicKey(pub), revocation.PurposeRevocation)
	if err != nil {
		return "", fmt.Errorf("status list token invalid: %w", err)
	}
	revoked, err := list.GetStatus(in.StatusIndex)
	if err != nil {
		return "", fmt.Errorf("status index out of range: %w", err)
	}
	b, _ := json.Marshal(map[string]bool{"revoked": revoked})
	return string(b), nil
}

// toolRevokePassport marks a previously-issued passport's status-list index as
// revoked. Uses the same trust model as every other mutating tool in this
// server (issue_passport, register_scitt, etc.): any caller authenticated at
// the transport layer (bearer token) may call it — there is no additional
// per-issuer authorization check here, matching issue_passport's existing
// precedent of trusting the caller-supplied issuerId without cryptographic
// proof of ownership.
func (s *Server) toolRevokePassport(args json.RawMessage) (string, error) {
	var in struct {
		StatusListIndex int `json:"statusListIndex"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	if in.StatusListIndex < 0 {
		return "", errors.New("mcp: statusListIndex must be non-negative")
	}
	if err := s.revokeByIndex(in.StatusListIndex); err != nil {
		return "", err
	}
	return `{"revoked":true}`, nil
}

// toolGetRevocationList issues a freshly-signed status list token for the
// server's current revocation state — the counterpart callers need to
// actually exercise check_revocation, since this server may run over stdio
// (cmd/blrcs-mcp) with no HTTP endpoint to dereference a statusListCredential
// URL from.
func (s *Server) toolGetRevocationList(args json.RawMessage) (string, error) {
	s.mu.RLock()
	list := s.revocationList
	s.mu.RUnlock()
	token, err := list.IssueToken(s.selfIssuer.ID, "blrcs-revocation-list", s.selfIssuer.PrivateKey(), 24*time.Hour)
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(map[string]string{
		"statusListTokenJWT":     token,
		"statusListIssuerKeyB64": base64.StdEncoding.EncodeToString(s.selfIssuer.PublicKey()),
	})
	return string(b), nil
}

// toolCreateCredentialOffer mints a real OpenID4VCI pre-authorized offer that
// a wallet can redeem against the issuer's HTTP endpoints
// (openid4vci.Issuer.Handler(), mounted separately by whoever called
// RegisterVCIIssuer). Requires a VCI issuer to have been registered — without
// this the openid4vci package existed and was fully tested but was reachable
// from zero cmd/ binaries, so this tool would have had nothing to call.
// Embeds a status reference from the same shared index space as
// issue_passport/issue_sdjwt/issue_battery_passport, so revoke_passport/
// check_revocation/get_revocation_list work for VCI-issued credentials too.
func (s *Server) toolCreateCredentialOffer(args json.RawMessage) (string, error) {
	var in struct {
		ConfigID    string         `json:"configId"`
		Subject     string         `json:"subject"`
		SDClaims    map[string]any `json:"sdClaims"`
		ClearClaims map[string]any `json:"clearClaims"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	s.mu.RLock()
	vci := s.vciIssuer
	s.mu.RUnlock()
	if vci == nil {
		return "", errors.New("mcp: no OpenID4VCI issuer registered for this server")
	}
	if in.Subject == "" {
		return "", errors.New("mcp: subject is required")
	}
	if in.SDClaims == nil {
		in.SDClaims = map[string]any{}
	}
	if in.ClearClaims == nil {
		in.ClearClaims = map[string]any{}
	}
	index, err := s.allocateStatusIndex()
	if err != nil {
		return "", err
	}
	status := &compliance.StatusRef{URI: s.selfIssuer.ID + "#revocation-list", Index: index}
	offerURL, code, err := vci.CreateOfferWithOptions(in.ConfigID, in.Subject, in.SDClaims, in.ClearClaims, openid4vci.OfferOptions{Status: status})
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(map[string]any{
		"offerUrl":          offerURL,
		"preAuthorizedCode": code,
		"statusListIndex":   index,
	})
	return string(b), nil
}

// toolCreatePresentationRequest mints a real OpenID4VP authorization request
// a wallet can respond to. Requires a VP verifier to have been registered —
// without this the openid4vp package's request/response protocol existed
// and was fully tested but was reachable only from cmd/blrcs-demo (a
// throwaway demo binary), never cmd/blrcs-mcpd.
func (s *Server) toolCreatePresentationRequest(args json.RawMessage) (string, error) {
	var in struct {
		PresentationDefinition json.RawMessage `json:"presentationDefinition"`
		// AcceptableIssuerKeys maps issuer DID -> base64 Ed25519 public key.
		// PresentationDefinition.AcceptableIssuers is `json:"-"` (deliberately
		// excluded from JSON, since it's meant to be built from trusted Go code
		// rather than deserialized) — this is the JSON-facing equivalent so a
		// tool caller can still supply it.
		AcceptableIssuerKeys map[string]string `json:"acceptableIssuerKeys"`
		// TransactionData — OpenID4VP 1.0 §Transaction Data. Each entry is a
		// plain JSON object (payment/consent details) the wallet must show and
		// the holder must approve; the tool base64url-encodes each per spec so
		// the presentation is cryptographically bound to them.
		TransactionData []json.RawMessage `json:"transactionData"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	s.mu.RLock()
	vp := s.vpVerifier
	s.mu.RUnlock()
	if vp == nil {
		return "", errors.New("mcp: no OpenID4VP verifier registered for this server")
	}
	if len(in.PresentationDefinition) == 0 {
		return "", errors.New("mcp: presentationDefinition is required")
	}
	var def openid4vp.PresentationDefinition
	if err := json.Unmarshal(in.PresentationDefinition, &def); err != nil {
		return "", fmt.Errorf("mcp: bad presentationDefinition: %w", err)
	}
	if len(in.AcceptableIssuerKeys) > 0 {
		def.AcceptableIssuers = make(map[string][]byte, len(in.AcceptableIssuerKeys))
		for did, keyB64 := range in.AcceptableIssuerKeys {
			key, kerr := base64.StdEncoding.DecodeString(keyB64)
			if kerr != nil || len(key) != ed25519.PublicKeySize {
				return "", fmt.Errorf("mcp: acceptableIssuerKeys[%q]: bad public key", did)
			}
			def.AcceptableIssuers[did] = key
		}
	}
	var transactionData []string
	for _, td := range in.TransactionData {
		// Compact each entry (strip caller whitespace) then base64url-encode, so
		// the hash the wallet computes and the verifier expects agree byte-for-byte.
		var compact bytes.Buffer
		if err := json.Compact(&compact, td); err != nil {
			return "", fmt.Errorf("mcp: bad transactionData entry: %w", err)
		}
		transactionData = append(transactionData, base64.RawURLEncoding.EncodeToString(compact.Bytes()))
	}
	reqURL, state, err := vp.CreateRequestTx(def, transactionData)
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(map[string]string{"requestUrl": reqURL, "state": state})
	return string(b), nil
}

// toolGetPresentationResult retrieves a previously-completed OpenID4VP
// verification by state. Returns {"status":"pending"} for a state that has
// not (yet, or ever) completed successfully — including a state that failed
// verification, since the failure detail is deliberately not surfaced here
// (CallbackHandler already returned it directly to the wallet, opaquely, at
// response time; a polling agent gets no additional oracle).
func (s *Server) toolGetPresentationResult(args json.RawMessage) (string, error) {
	var in struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	if in.State == "" {
		return "", errors.New("mcp: state is required")
	}
	s.mu.RLock()
	entry, ok := s.presResults[in.State]
	s.mu.RUnlock()
	if !ok {
		return `{"status":"pending"}`, nil
	}
	b, _ := json.Marshal(map[string]any{
		"status":  "success",
		"subject": entry.vp.Subject,
		"issuer":  entry.vp.Issuer,
		"claims":  entry.vp.Claims,
	})
	return string(b), nil
}

// toolServerCapabilities reports which of this server's optional features are
// actually operational given how it was configured — capability discovery so
// an agent can tell, before calling them, whether create_credential_offer
// (needs a registered OpenID4VCI issuer) or create_presentation_request (needs
// a registered OpenID4VP verifier) will work. Built from real server state via
// the capability package (previously implemented and tested but reachable from
// no binary).
//
// Persistence is deliberately NOT reported here: whether the backing store is
// disk-backed vs in-memory is not self-detectable from inside the Server (the
// in-memory MemoryStorage also implements BlobStorage, so the revocation-store
// handle is non-nil either way) — only the constructing binary knows, via its
// data-dir config. Reporting a guessed value would be worse than omitting it.
func (s *Server) toolServerCapabilities(_ json.RawMessage) (string, error) {
	b, _ := json.Marshal(s.CapabilitiesSnapshot())
	return string(b), nil
}

// CapabilitiesSnapshot builds the same capability report toolServerCapabilities
// returns, exported so a caller with its own HTTP surface (e.g.
// cmd/blrcs-mcpd's /.well-known/blrcs-capabilities.json) can serve identical,
// single-sourced data rather than re-deriving it — the whole point of
// discovery endpoints is that different transports agree.
func (s *Server) CapabilitiesSnapshot() capability.Snapshot {
	s.mu.RLock()
	hasVCI := s.vciIssuer != nil
	hasVP := s.vpVerifier != nil
	s.mu.RUnlock()

	caps := capability.New()
	// Always-present functional capabilities (compiled into every build).
	caps.Set(capability.CapEd25519, true)
	caps.Set(capability.CapDPP, true)         // issue_passport / EU ESPR DPP
	caps.Set(capability.CapBatteryPass, true) // issue_battery_passport / Reg 2023/1542
	caps.Set(capability.CapSCITT, true)       // register_scitt / transparency ledger
	// Config-dependent capabilities (honestly tracked on the Server).
	caps.Set(capability.CapOpenID4VCI, hasVCI)
	caps.Set(capability.CapOpenID4VP, hasVP)
	caps.Seal()

	return caps.Snapshot()
}
