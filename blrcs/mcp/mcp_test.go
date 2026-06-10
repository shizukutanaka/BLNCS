package mcp

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"blrcs/compliance"
	"blrcs/scitt"
)

func setupServer(t *testing.T) (*Server, *compliance.Issuer, *compliance.SensorAttester) {
	t.Helper()
	srv, err := NewServer("did:web:ts.blrcs.example", "did:web:blrcs-mcp.example")
	if err != nil {
		t.Fatal(err)
	}
	iss, err := compliance.NewIssuer("did:web:factory.example")
	if err != nil {
		t.Fatal(err)
	}
	att, err := compliance.NewSensorAttester("did:device:sensor-001")
	if err != nil {
		t.Fatal(err)
	}
	srv.RegisterIssuer(iss)
	srv.RegisterAttester(att)
	return srv, iss, att
}

func callRaw(t *testing.T, srv *Server, payload string) map[string]any {
	t.Helper()
	raw := srv.HandleRaw([]byte(payload))
	if raw == nil {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return m
}

func TestInitialize(t *testing.T) {
	srv, _, _ := setupServer(t)
	resp := callRaw(t, srv, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", resp)
	}
	if result["protocolVersion"] != protocolVersion {
		t.Fatalf("protocol: %v", result["protocolVersion"])
	}
}

func TestToolsList(t *testing.T) {
	srv, _, _ := setupServer(t)
	resp := callRaw(t, srv, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
	result := resp["result"].(map[string]any)
	tools := result["tools"].([]any)
	if len(tools) != 7 {
		t.Fatalf("expected 7 tools, got %d", len(tools))
	}
	names := make(map[string]bool)
	for _, tl := range tools {
		names[tl.(map[string]any)["name"].(string)] = true
	}
	for _, want := range []string{"issue_passport", "verify_passport", "attest_range", "verify_range", "register_scitt", "get_scitt_receipt", "ledger_checkpoint"} {
		if !names[want] {
			t.Errorf("tool %s missing", want)
		}
	}
}

func TestIssueAndVerifyPassportRoundTrip(t *testing.T) {
	srv, iss, _ := setupServer(t)
	// Issue via MCP
	issueReq := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"issue_passport","arguments":{"issuerId":"did:web:factory.example","productId":"01034531200000111","category":"textile","originCountry":"JP","carbonKgCO2e":2.4,"recyclability":0.85,"validForDays":365}}}`
	resp := callRaw(t, srv, issueReq)
	result := resp["result"].(map[string]any)
	if result["isError"].(bool) {
		t.Fatalf("issue failed: %v", result["content"])
	}
	content := result["content"].([]any)
	credJson := content[0].(map[string]any)["text"].(string)

	// Verify via MCP
	pubB64 := base64.StdEncoding.EncodeToString(iss.PublicKey())
	verifyReq := map[string]any{
		"jsonrpc": "2.0", "id": 4, "method": "tools/call",
		"params": map[string]any{
			"name": "verify_passport",
			"arguments": map[string]any{
				"credentialJson":     credJson,
				"issuerPublicKeyB64": pubB64,
			},
		},
	}
	reqB, _ := json.Marshal(verifyReq)
	resp = callRaw(t, srv, string(reqB))
	result = resp["result"].(map[string]any)
	if result["isError"].(bool) {
		t.Fatalf("verify error: %v", result["content"])
	}
	text := result["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, `"valid":true`) {
		t.Fatalf("passport invalid: %s", text)
	}
}

func TestAttestAndVerifyRangeRoundTrip(t *testing.T) {
	srv, _, att := setupServer(t)
	attestReq := `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"attest_range","arguments":{"attesterId":"did:device:sensor-001","value":5.5,"min":2.0,"max":8.0,"unit":"celsius","name":"cold_chain"}}}`
	resp := callRaw(t, srv, attestReq)
	proofJson := resp["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)

	pubB64 := base64.StdEncoding.EncodeToString(att.PublicKey())
	verifyReq := map[string]any{
		"jsonrpc": "2.0", "id": 6, "method": "tools/call",
		"params": map[string]any{
			"name":      "verify_range",
			"arguments": map[string]any{"proofJson": proofJson, "attesterPublicKeyB64": pubB64},
		},
	}
	reqB, _ := json.Marshal(verifyReq)
	resp = callRaw(t, srv, string(reqB))
	text := resp["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, `"valid":true`) {
		t.Fatalf("range proof invalid: %s", text)
	}
}

func TestSCITTFullRoundTrip(t *testing.T) {
	srv, _, _ := setupServer(t)
	regReq := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"register_scitt","arguments":{"issuerId":"did:web:factory.example","subject":"shipment-ABC123","contentType":"text/plain","payload":"shipment created"}}}`
	resp := callRaw(t, srv, regReq)
	result := resp["result"].(map[string]any)
	if result["isError"].(bool) {
		t.Fatalf("register failed: %v", result["content"])
	}
	text := result["content"].([]any)[0].(map[string]any)["text"].(string)
	var regResult struct {
		Statement scitt.Statement `json:"statement"`
		Receipt   scitt.Receipt   `json:"receipt"`
	}
	if err := json.Unmarshal([]byte(text), &regResult); err != nil {
		t.Fatal(err)
	}

	// Verify locally
	ledger := srv.Ledger()
	if err := scitt.VerifyReceipt(&regResult.Receipt, regResult.Statement, ledger.PublicKey()); err != nil {
		t.Fatalf("receipt verify: %v", err)
	}

	// Fetch back via MCP (note: get_scitt_receipt uses the live ledger; treat the statement
	// as whatever is at that leaf index — will be auto-audit entry if not the one we want)
	leafIdx := regResult.Receipt.LeafIndex
	getReq := `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"get_scitt_receipt","arguments":{"leafIndex":` + itoa(int(leafIdx)) + `}}}`
	resp = callRaw(t, srv, getReq)
	fetchText := resp["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	var fetch struct {
		Statement scitt.Statement `json:"statement"`
		Receipt   scitt.Receipt   `json:"receipt"`
		TSKey     string          `json:"tsKey"`
	}
	if err := json.Unmarshal([]byte(fetchText), &fetch); err != nil {
		t.Fatal(err)
	}
	tsKey, _ := base64.StdEncoding.DecodeString(fetch.TSKey)
	if err := scitt.VerifyReceipt(&fetch.Receipt, fetch.Statement, ed25519.PublicKey(tsKey)); err != nil {
		t.Fatalf("fetched receipt verify: %v", err)
	}
	if fetch.Statement.Subject != "shipment-ABC123" {
		t.Fatalf("wrong subject fetched: %s", fetch.Statement.Subject)
	}
}

func TestAutoAudit(t *testing.T) {
	srv, _, _ := setupServer(t)

	// Read-only tools must NOT be audited (no ledger growth from reads).
	before := srv.Ledger().Size()
	resp := callRaw(t, srv, `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"ledger_checkpoint","arguments":{}}}`)
	if resp["result"].(map[string]any)["isError"].(bool) {
		t.Fatal("checkpoint tool failed")
	}
	if got := srv.Ledger().Size(); got != before {
		t.Fatalf("read-only tool should not be audited: before=%d after=%d", before, got)
	}

	// A mutating tool (issue_passport) IS audited → ledger grows by 1.
	before = srv.Ledger().Size()
	resp = callRaw(t, srv, `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"issue_passport","arguments":{"issuerId":"did:web:factory.example","productId":"01034531200000111","category":"textile","originCountry":"JP","carbonKgCO2e":2.4,"recyclability":0.85,"validForDays":365}}}`)
	if resp["result"].(map[string]any)["isError"].(bool) {
		t.Fatalf("issue_passport failed: %v", resp["result"])
	}
	if got := srv.Ledger().Size(); got != before+1 {
		t.Fatalf("mutating tool should add 1 audit entry: before=%d after=%d", before, got)
	}
}

func TestUnknownMethod(t *testing.T) {
	srv, _, _ := setupServer(t)
	resp := callRaw(t, srv, `{"jsonrpc":"2.0","id":10,"method":"bogus","params":{}}`)
	errObj := resp["error"].(map[string]any)
	if int(errObj["code"].(float64)) != errMethodNotFound {
		t.Fatalf("want -32601, got %v", errObj["code"])
	}
}

func TestBadJSONRPC(t *testing.T) {
	srv, _, _ := setupServer(t)
	resp := callRaw(t, srv, `{"jsonrpc":"1.0","id":1,"method":"initialize"}`)
	errObj := resp["error"].(map[string]any)
	if int(errObj["code"].(float64)) != errInvalidRequest {
		t.Fatalf("want -32600, got %v", errObj["code"])
	}
}

func TestNotificationNoResponse(t *testing.T) {
	srv, _, _ := setupServer(t)
	// 通知 (ID なし) は応答なし
	resp := srv.HandleRaw([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	if resp != nil {
		t.Fatalf("notification should produce no response: %s", resp)
	}
}

func TestStdioServe(t *testing.T) {
	srv, _, _ := setupServer(t)
	in := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n")
	var out bytes.Buffer
	if err := srv.Serve(in, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"protocolVersion":"`+protocolVersion+`"`) {
		t.Fatalf("unexpected output: %s", out.String())
	}
}

func TestInvalidIssuer(t *testing.T) {
	srv, _, _ := setupServer(t)
	resp := callRaw(t, srv, `{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"issue_passport","arguments":{"issuerId":"did:web:unknown","productId":"P1"}}}`)
	result := resp["result"].(map[string]any)
	if !result["isError"].(bool) {
		t.Fatal("should error on unknown issuer")
	}
}

func TestVerifyPassportFailure(t *testing.T) {
	srv, _, _ := setupServer(t)

	// Issue a valid credential using the demo issuer DID.
	issueResp := callRaw(t, srv, `{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"issue_passport","arguments":{"issuerId":"did:web:factory.example","productId":"VERIFY-FAIL-TEST"}}}`)
	content := issueResp["result"].(map[string]any)["content"].([]any)
	credJson := content[0].(map[string]any)["text"].(string)

	// Use a *different* public key for verification → verification must fail
	// with {"valid":false,...} not an error (key is valid size, wrong content).
	wrongPub, _, _ := ed25519.GenerateKey(nil)
	wrongPubB64 := base64.StdEncoding.EncodeToString([]byte(wrongPub))
	req := map[string]any{
		"jsonrpc": "2.0", "id": 21, "method": "tools/call",
		"params": map[string]any{
			"name": "verify_passport",
			"arguments": map[string]any{
				"credentialJson":     credJson,
				"issuerPublicKeyB64": wrongPubB64,
			},
		},
	}
	reqB, _ := json.Marshal(req)
	resp := callRaw(t, srv, string(reqB))
	result := resp["result"].(map[string]any)
	if result["isError"].(bool) {
		t.Fatal("verify failure should be a structured result, not an MCP error")
	}
	text := result["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, `"valid":false`) {
		t.Fatalf("expected valid:false, got: %s", text)
	}
}

func TestVerifyRangeFailure(t *testing.T) {
	srv, _, att := setupServer(t)

	// Attest a value.
	attestReq := `{"jsonrpc":"2.0","id":22,"method":"tools/call","params":{"name":"attest_range","arguments":{"attesterId":"did:device:sensor-001","value":5.5,"min":2.0,"max":8.0,"unit":"celsius","name":"temp"}}}`
	attestResp := callRaw(t, srv, attestReq)
	proofJson := attestResp["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)

	// Use wrong attester key → verify_range must return valid:false.
	wrongPub, _, _ := ed25519.GenerateKey(nil)
	wrongPubB64 := base64.StdEncoding.EncodeToString([]byte(wrongPub))
	_ = att
	req := map[string]any{
		"jsonrpc": "2.0", "id": 23, "method": "tools/call",
		"params": map[string]any{
			"name": "verify_range",
			"arguments": map[string]any{
				"proofJson":            proofJson,
				"attesterPublicKeyB64": wrongPubB64,
			},
		},
	}
	reqB, _ := json.Marshal(req)
	resp := callRaw(t, srv, string(reqB))
	result := resp["result"].(map[string]any)
	if result["isError"].(bool) {
		t.Fatal("verify_range failure should be structured result, not MCP error")
	}
	text := result["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, `"valid":false`) {
		t.Fatalf("expected valid:false, got: %s", text)
	}
}

func TestSessionStoreGC(t *testing.T) {
	s := &sessionStore{data: make(map[string]*sessionEntry)}
	s.create("sess1", "user1")
	// Artificially age the entry so GC will remove it.
	s.mu.Lock()
	s.data["sess1"].lastSeen = time.Now().Add(-2 * sessionIdleTimeout)
	s.mu.Unlock()
	s.gc()
	s.mu.Lock()
	_, exists := s.data["sess1"]
	s.mu.Unlock()
	if exists {
		t.Error("stale session should have been GC'd")
	}
}

func TestBuildServerInvalidDID(t *testing.T) {
	ledger, _ := scitt.NewLedger("did:web:ts.test")
	// Empty serverDID → compliance.NewIssuer("") should fail
	_, err := buildServer("did:web:ts.test", "", ledger)
	if err == nil {
		t.Fatal("empty serverDID should fail")
	}
}

func TestVerifyResult(t *testing.T) {
	got := verifyResult(true, "")
	if got != `{"valid":true}` {
		t.Errorf("valid result: %s", got)
	}
	got2 := verifyResult(false, "bad sig")
	if !strings.Contains(got2, `"valid":false`) {
		t.Errorf("invalid result: %s", got2)
	}
	if !strings.Contains(got2, "bad sig") {
		t.Errorf("reason missing: %s", got2)
	}
}

func TestNewServerWithEmptyTSID(t *testing.T) {
	// Empty tsID → scitt.NewLedger should fail
	_, err := NewServer("", "did:web:server")
	if err == nil {
		t.Fatal("empty tsID should fail")
	}
}

// itoa — avoid strconv import for simplicity
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 20)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	if neg {
		buf = append([]byte{'-'}, buf...)
	}
	return string(buf)
}
