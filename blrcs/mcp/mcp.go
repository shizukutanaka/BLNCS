// Package mcp — BLRCS Model Context Protocol Server
//
// エージェント時代のBLRCS門戸。AI agent (Claude, GPT, Gemini等) から
// BLRCS機能を直接呼び出せる。全呼出はSCITT ledgerに自動監査記録。
//
// プロトコル: MCP 2024-11-05 (JSON-RPC 2.0 over stdio)
//
// 公開ツール:
//
//	issue_passport     — EU DPP発行
//	verify_passport    — DPP検証
//	attest_range       — センサ範囲証明 (値非開示)
//	verify_range       — 範囲証明検証
//	register_scitt     — 透明性ログ登録
//	get_scitt_receipt  — 受領証取得
//	ledger_checkpoint  — 署名済みtree head
//	issue_sdjwt        — SD-JWT VC発行 (選択開示)
//	verify_sdjwt       — SD-JWT VC検証 (exp/KB-JWT込み)
//	check_revocation   — W3C Bitstring Status List 失効確認
package mcp

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"blrcs/compliance"
	"blrcs/revocation"
	"blrcs/scitt"
	"blrcs/storage"
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

type Server struct {
	mu         sync.RWMutex
	issuers    map[string]*compliance.Issuer
	attesters  map[string]*compliance.SensorAttester
	ledger     *scitt.Ledger
	selfIssuer *compliance.Issuer
	limiter    *ToolLimiter // per-tool rate limiter; nil = unlimited
}

func NewServer(tsID, serverDID string) (*Server, error) {
	ledger, err := scitt.NewLedger(tsID)
	if err != nil {
		return nil, err
	}
	return buildServer(tsID, serverDID, ledger)
}

// NewServerWithStorage — 永続化層付き (プロダクション向け)
func NewServerWithStorage(tsID, serverDID string, store storage.Storage) (*Server, error) {
	ledger, err := scitt.NewLedgerWithStorage(tsID, store)
	if err != nil {
		return nil, err
	}
	return buildServer(tsID, serverDID, ledger)
}

func buildServer(tsID, serverDID string, ledger *scitt.Ledger) (*Server, error) {
	selfIss, err := compliance.NewIssuer(serverDID)
	if err != nil {
		return nil, err
	}
	return &Server{
		issuers:    make(map[string]*compliance.Issuer),
		attesters:  make(map[string]*compliance.SensorAttester),
		ledger:     ledger,
		selfIssuer: selfIss,
	}, nil
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
			Name:        "issue_sdjwt",
			Description: "Issue an SD-JWT VC with selective disclosure. sdClaims become selectively disclosable; clearClaims are always visible. Returns the full SD-JWT token and a list of disclosures.",
			InputSchema: rawJSON(`{"type":"object","properties":{"issuerId":{"type":"string"},"subject":{"type":"string"},"sdClaims":{"type":"object","description":"Claims to make selectively disclosable"},"clearClaims":{"type":"object","description":"Claims always visible in the JWT"},"validForDays":{"type":"integer","default":365}},"required":["issuerId","subject","sdClaims"]}`),
		},
		{
			Name:        "verify_sdjwt",
			Description: "Verify an SD-JWT VC signature, expiry, and (if present) KB-JWT holder binding. Returns the verified claims.",
			InputSchema: rawJSON(`{"type":"object","properties":{"sdjwt":{"type":"string","description":"Full SD-JWT presentation string (header.payload.sig~disc...~[kb-jwt])"},"issuerPublicKeyB64":{"type":"string","description":"Base64-encoded Ed25519 issuer public key"},"expectedNonce":{"type":"string","description":"Expected KB-JWT nonce (for OpenID4VP)"},"expectedAudience":{"type":"string","description":"Expected KB-JWT audience"}},"required":["sdjwt","issuerPublicKeyB64"]}`),
		},
		{
			Name:        "check_revocation",
			Description: "Check whether a credential is revoked using a W3C Bitstring Status List token. Returns {revoked:bool}.",
			InputSchema: rawJSON(`{"type":"object","properties":{"statusListTokenJWT":{"type":"string","description":"Status list token (application/statuslist+jwt)"},"statusListIssuerKeyB64":{"type":"string","description":"Base64-encoded Ed25519 public key of status list issuer"},"statusIndex":{"type":"integer","minimum":0,"description":"Bit index of the credential in the status list"}},"required":["statusListTokenJWT","statusListIssuerKeyB64","statusIndex"]}`),
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
	"issue_passport": true,
	"attest_range":   true,
	"register_scitt": true,
	"issue_sdjwt":    true,
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
	case "ledger_checkpoint":
		return s.toolCheckpoint(args)
	case "issue_sdjwt":
		return s.toolIssueSDJWT(args)
	case "verify_sdjwt":
		return s.toolVerifySDJWT(args)
	case "check_revocation":
		return s.toolCheckRevocation(args)
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
	cred, err := iss.Issue(compliance.PassportClaim{
		ProductID:     in.ProductID,
		Category:      in.Category,
		OriginCountry: in.OriginCountry,
		Manufacturer:  in.IssuerID,
		CarbonKgCO2e:  in.CarbonKgCO2e,
		Recyclability: in.Recyclability,
	}, validFor)
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(cred)
	return string(b), nil
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
	sdjwt, discs, err := iss.IssueSDJWT(in.Subject, in.SDClaims, in.ClearClaims, validFor)
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
