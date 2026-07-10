package mcp

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"blrcs/compliance"
	"blrcs/scitt"
	"blrcs/storage"
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
	if len(tools) != 29 {
		t.Fatalf("expected 29 tools, got %d", len(tools))
	}
	names := make(map[string]bool)
	for _, tl := range tools {
		names[tl.(map[string]any)["name"].(string)] = true
	}
	for _, want := range []string{"issue_passport", "issue_battery_passport", "verify_passport", "attest_range", "verify_range", "register_scitt", "get_scitt_receipt", "ledger_checkpoint", "issue_sdjwt", "verify_sdjwt", "check_revocation", "revoke_passport", "get_revocation_list", "create_credential_offer", "issue_mdoc", "verify_mdoc", "build_gs1_link", "parse_gs1_link", "create_presentation_request", "get_presentation_result", "resolve_did", "discover_did_services", "verify_passport_by_did", "verify_sdjwt_by_did", "create_did_webvh", "update_did_webvh", "verify_did_webvh_log", "resolve_vct_metadata", "validate_claims_against_vct"} {
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

// TestFailedMutatingCallNotAudited asserts that a *rejected* mutating tool call
// does not append to the transparency ledger. Auditing before dispatch let an
// unauthorized/invalid call (unknown issuer, bad params) pollute the append-only
// log and amplify write cost; audit must happen only after a successful dispatch.
func TestFailedMutatingCallNotAudited(t *testing.T) {
	srv, _, _ := setupServer(t)

	cases := []struct {
		name string
		call string
	}{
		{
			name: "unknown issuer",
			call: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"issue_passport","arguments":{"issuerId":"did:web:not-registered","productId":"p1"}}}`,
		},
		{
			name: "invalid params (negative carbon)",
			call: `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"issue_passport","arguments":{"issuerId":"did:web:factory.example","productId":"p1","carbonKgCO2e":-5}}}`,
		},
		{
			name: "register_scitt unknown issuer",
			call: `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"register_scitt","arguments":{"issuerId":"did:web:not-registered","subject":"s","payload":"data"}}}`,
		},
		{
			name: "issue_sdjwt missing subject",
			call: `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"issue_sdjwt","arguments":{"issuerId":"did:web:factory.example","sdClaims":{"a":1}}}}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := srv.Ledger().Size()
			resp := callRaw(t, srv, tc.call)
			// Must be reported as a tool error...
			if !resp["result"].(map[string]any)["isError"].(bool) {
				t.Fatalf("expected isError=true for %q", tc.name)
			}
			// ...and must NOT have grown the ledger.
			if got := srv.Ledger().Size(); got != before {
				t.Fatalf("failed mutating call polluted ledger: before=%d after=%d", before, got)
			}
		})
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
	_, err := buildServer("did:web:ts.test", "", ledger, storage.NewMemoryStorage())
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

// ============================================================================
// Axis 100: revoke_passport / get_revocation_list lifecycle
// ============================================================================

// toolCall is a small helper for tools/call requests in the tests below.
func toolCall(t *testing.T, srv *Server, id int, name string, args map[string]any) map[string]any {
	t.Helper()
	req := map[string]any{
		"jsonrpc": "2.0", "id": id, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": args},
	}
	b, _ := json.Marshal(req)
	resp := callRaw(t, srv, string(b))
	return resp["result"].(map[string]any)
}

func toolCallText(t *testing.T, result map[string]any) string {
	t.Helper()
	if result["isError"].(bool) {
		t.Fatalf("tool call failed: %v", result["content"])
	}
	return result["content"].([]any)[0].(map[string]any)["text"].(string)
}

// TestIssuePassportEmbedsCredentialStatus verifies issue_passport now embeds
// a credentialStatus (W3C Bitstring Status List entry) into every issued
// credential, so it's revocable.
func TestIssuePassportEmbedsCredentialStatus(t *testing.T) {
	srv, _, _ := setupServer(t)
	result := toolCall(t, srv, 1, "issue_passport", map[string]any{
		"issuerId": "did:web:factory.example", "productId": "P-STATUS-1",
	})
	credJSON := toolCallText(t, result)
	var cred compliance.Credential
	if err := json.Unmarshal([]byte(credJSON), &cred); err != nil {
		t.Fatal(err)
	}
	if cred.Status == nil {
		t.Fatal("issued credential should carry a credentialStatus")
	}
	if cred.Status.StatusListIndex != "0" {
		t.Errorf("first issued credential should get index 0, got %s", cred.Status.StatusListIndex)
	}
}

// TestIssuePassportAllocatesDistinctIndices verifies successive issuances get
// distinct, incrementing status-list indices (no index reuse/collision).
func TestIssuePassportAllocatesDistinctIndices(t *testing.T) {
	srv, _, _ := setupServer(t)
	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		result := toolCall(t, srv, i, "issue_passport", map[string]any{
			"issuerId": "did:web:factory.example", "productId": "P-IDX-" + itoa(i),
		})
		credJSON := toolCallText(t, result)
		var cred compliance.Credential
		if err := json.Unmarshal([]byte(credJSON), &cred); err != nil {
			t.Fatal(err)
		}
		idx := cred.Status.StatusListIndex
		if seen[idx] {
			t.Fatalf("index %s reused across issuances", idx)
		}
		seen[idx] = true
	}
}

// TestRevokePassportEndToEnd exercises the full lifecycle: issue → check
// (not revoked) → revoke → get_revocation_list → check (revoked).
func TestRevokePassportEndToEnd(t *testing.T) {
	srv, _, _ := setupServer(t)

	issueResult := toolCall(t, srv, 1, "issue_passport", map[string]any{
		"issuerId": "did:web:factory.example", "productId": "P-REVOKE-1",
	})
	credJSON := toolCallText(t, issueResult)
	var cred compliance.Credential
	if err := json.Unmarshal([]byte(credJSON), &cred); err != nil {
		t.Fatal(err)
	}
	index := cred.Status.StatusListIndex

	getList := func() (tokenJWT, keyB64 string) {
		t.Helper()
		listResult := toolCall(t, srv, 2, "get_revocation_list", map[string]any{})
		var out struct {
			StatusListTokenJWT     string `json:"statusListTokenJWT"`
			StatusListIssuerKeyB64 string `json:"statusListIssuerKeyB64"`
		}
		if err := json.Unmarshal([]byte(toolCallText(t, listResult)), &out); err != nil {
			t.Fatal(err)
		}
		return out.StatusListTokenJWT, out.StatusListIssuerKeyB64
	}
	checkRevoked := func() bool {
		t.Helper()
		tokenJWT, keyB64 := getList()
		idxInt, _ := jsonNumberToInt(index)
		checkResult := toolCall(t, srv, 3, "check_revocation", map[string]any{
			"statusListTokenJWT": tokenJWT, "statusListIssuerKeyB64": keyB64, "statusIndex": idxInt,
		})
		var out struct {
			Revoked bool `json:"revoked"`
		}
		if err := json.Unmarshal([]byte(toolCallText(t, checkResult)), &out); err != nil {
			t.Fatal(err)
		}
		return out.Revoked
	}

	if checkRevoked() {
		t.Fatal("freshly issued credential should not be revoked")
	}

	idxInt, _ := jsonNumberToInt(index)
	revokeResult := toolCall(t, srv, 4, "revoke_passport", map[string]any{"statusListIndex": idxInt})
	toolCallText(t, revokeResult) // asserts not isError

	if !checkRevoked() {
		t.Fatal("credential should be revoked after revoke_passport")
	}
}

// TestRevokePassportUnknownIndexRejected verifies an out-of-range index is
// rejected rather than silently accepted.
func TestRevokePassportUnknownIndexRejected(t *testing.T) {
	srv, _, _ := setupServer(t)
	result := toolCall(t, srv, 1, "revoke_passport", map[string]any{"statusListIndex": 999999999})
	if !result["isError"].(bool) {
		t.Fatal("revoking an out-of-range index should error")
	}
}

// TestRevokePassportNegativeIndexRejected verifies input validation.
func TestRevokePassportNegativeIndexRejected(t *testing.T) {
	srv, _, _ := setupServer(t)
	result := toolCall(t, srv, 1, "revoke_passport", map[string]any{"statusListIndex": -1})
	if !result["isError"].(bool) {
		t.Fatal("negative statusListIndex should error")
	}
}

// TestRevokePassportIsAudited verifies revoke_passport calls are recorded to
// the transparency log, like other mutating tools.
func TestRevokePassportIsAudited(t *testing.T) {
	srv, _, _ := setupServer(t)
	before := srv.Ledger().Size()

	issueResult := toolCall(t, srv, 1, "issue_passport", map[string]any{
		"issuerId": "did:web:factory.example", "productId": "P-AUDIT-1",
	})
	var cred compliance.Credential
	_ = json.Unmarshal([]byte(toolCallText(t, issueResult)), &cred)
	idxInt, _ := jsonNumberToInt(cred.Status.StatusListIndex)

	toolCall(t, srv, 2, "revoke_passport", map[string]any{"statusListIndex": idxInt})

	after := srv.Ledger().Size()
	if after <= before+1 { // +1 for the issue_passport audit entry itself
		t.Errorf("revoke_passport should add its own ledger entry: before=%d after=%d", before, after)
	}
}

// TestRevocationPersistsAcrossRestart verifies revocation state (list +
// index counter) survives a server restart when backed by FileStorage —
// otherwise a revoked credential would silently un-revoke on every restart.
func TestRevocationPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.NewFileStorage(dir)
	if err != nil {
		t.Fatal(err)
	}
	srv1, err := NewServerWithStorage("did:web:ts.persist.test", "did:web:mcp.persist.test", store)
	if err != nil {
		t.Fatal(err)
	}
	iss, _ := compliance.NewIssuer("did:web:factory.persist.test")
	srv1.RegisterIssuer(iss)

	issueResult := toolCall(t, srv1, 1, "issue_passport", map[string]any{
		"issuerId": "did:web:factory.persist.test", "productId": "P-PERSIST-1",
	})
	var cred compliance.Credential
	_ = json.Unmarshal([]byte(toolCallText(t, issueResult)), &cred)
	idxInt, _ := jsonNumberToInt(cred.Status.StatusListIndex)

	revokeResult := toolCall(t, srv1, 2, "revoke_passport", map[string]any{"statusListIndex": idxInt})
	toolCallText(t, revokeResult)
	store.Close()

	// Reopen against the same directory — simulates a process restart.
	store2, err := storage.NewFileStorage(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store2.Close()
	srv2, err := NewServerWithStorage("did:web:ts.persist.test", "did:web:mcp.persist.test", store2)
	if err != nil {
		t.Fatal(err)
	}

	// The revoked index must still read as revoked after restart.
	getResult := toolCall(t, srv2, 3, "get_revocation_list", map[string]any{})
	var out struct {
		StatusListTokenJWT     string `json:"statusListTokenJWT"`
		StatusListIssuerKeyB64 string `json:"statusListIssuerKeyB64"`
	}
	_ = json.Unmarshal([]byte(toolCallText(t, getResult)), &out)
	checkResult := toolCall(t, srv2, 4, "check_revocation", map[string]any{
		"statusListTokenJWT": out.StatusListTokenJWT, "statusListIssuerKeyB64": out.StatusListIssuerKeyB64, "statusIndex": idxInt,
	})
	var checkOut struct {
		Revoked bool `json:"revoked"`
	}
	_ = json.Unmarshal([]byte(toolCallText(t, checkResult)), &checkOut)
	if !checkOut.Revoked {
		t.Fatal("revocation should survive a server restart")
	}

	// The index counter must also have survived: a second issuance after
	// restart must not reuse index 0 (already assigned to P-PERSIST-1).
	srv2.RegisterIssuer(iss)
	issueResult2 := toolCall(t, srv2, 5, "issue_passport", map[string]any{
		"issuerId": "did:web:factory.persist.test", "productId": "P-PERSIST-2",
	})
	var cred2 compliance.Credential
	_ = json.Unmarshal([]byte(toolCallText(t, issueResult2)), &cred2)
	if cred2.Status.StatusListIndex == cred.Status.StatusListIndex {
		t.Fatal("status index counter should not reset across restart")
	}
}

func jsonNumberToInt(s string) (int, error) {
	n := 0
	neg := false
	for i, c := range s {
		if i == 0 && c == '-' {
			neg = true
			continue
		}
		if c < '0' || c > '9' {
			return 0, errors.New("not a number: " + s)
		}
		n = n*10 + int(c-'0')
	}
	if neg {
		n = -n
	}
	return n, nil
}
