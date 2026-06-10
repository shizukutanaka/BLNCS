package dcapi

import (
	"encoding/json"
	"strings"
	"testing"

	"blrcs/openid4vp"
)

func TestIsSupported(t *testing.T) {
	valid := []Protocol{
		ProtocolOpenID4VPUnsigned,
		ProtocolOpenID4VPSigned,
		ProtocolISOmDoc,
		ProtocolOpenID4VCI,
		"openid4vp-v1-multisigned",
	}
	for _, p := range valid {
		if !IsSupported(p) {
			t.Errorf("should support %s", p)
		}
	}
	invalid := []Protocol{"openid4vp", "custom", "", "OpenID4VP"}
	for _, p := range invalid {
		if IsSupported(p) {
			t.Errorf("should reject %s", p)
		}
	}
}

func TestBuildForVerifier(t *testing.T) {
	def := openid4vp.PresentationDefinition{
		ID:             "eu-battery",
		RequiredClaims: []string{"batteryCategory", "carbonKgCO2e"},
		AcceptableDIDs: []string{"did:web:factory"},
		// AcceptableIssuers (内部map) は wire送信禁止確認
		AcceptableIssuers: map[string][]byte{"did:web:factory": []byte("secret-pubkey-bytes")},
	}
	call, err := BuildForVerifier(def, "nonce-abc", "https://verify.blrcs", "https://verify.blrcs/cb")
	if err != nil {
		t.Fatal(err)
	}
	// 両ブラウザ向け要求が生成される
	if len(call.Digital.Requests) != 2 {
		t.Fatalf("want 2 requests, got %d", len(call.Digital.Requests))
	}

	// Chrome向け openid4vp-v1-unsigned が含まれる
	var foundChrome, foundSafari bool
	for _, r := range call.Digital.Requests {
		if r.Protocol == ProtocolOpenID4VPUnsigned {
			foundChrome = true
			// wire送信禁止フィールド (acceptableIssuers) が含まれていないこと
			if strings.Contains(string(r.Data), "secret-pubkey-bytes") {
				t.Error("CRITICAL: AcceptableIssuers leaked into wire payload")
			}
			// 必要なフィールドがある
			var d map[string]any
			json.Unmarshal(r.Data, &d)
			if d["response_mode"] != "dc_api" {
				t.Errorf("response_mode: %v", d["response_mode"])
			}
			if d["nonce"] != "nonce-abc" {
				t.Errorf("nonce: %v", d["nonce"])
			}
		}
		if r.Protocol == ProtocolISOmDoc {
			foundSafari = true
		}
	}
	if !foundChrome {
		t.Error("Chrome/Firefox payload missing")
	}
	if !foundSafari {
		t.Error("Safari payload missing")
	}
}

func TestBuildForVerifierEmpty(t *testing.T) {
	_, err := BuildForVerifier(openid4vp.PresentationDefinition{ID: "x"}, "nonce", "c", "")
	if err != openid4vp.ErrDefinitionEmpty {
		t.Fatalf("want ErrDefinitionEmpty, got %v", err)
	}
}

func TestExtractVPTokenOpenID4VP(t *testing.T) {
	inner := json.RawMessage(`{"vp_token":"some.sd.jwt~d1~","state":"abc"}`)
	r := &DCAPIResponse{Protocol: ProtocolOpenID4VPUnsigned, Data: inner}
	vp, state, err := r.ExtractVPToken()
	if err != nil {
		t.Fatal(err)
	}
	if vp != "some.sd.jwt~d1~" {
		t.Errorf("vp: %s", vp)
	}
	if state != "abc" {
		t.Errorf("state: %s", state)
	}
}

func TestExtractVPTokenMissing(t *testing.T) {
	r := &DCAPIResponse{
		Protocol: ProtocolOpenID4VPUnsigned,
		Data:     json.RawMessage(`{"state":"only"}`),
	}
	if _, _, err := r.ExtractVPToken(); err == nil {
		t.Fatal("should fail without vp_token")
	}
}

func TestExtractVPTokenMdoc(t *testing.T) {
	// mdoc は base64 CBOR string
	inner, _ := json.Marshal("bW9jay1tZG9jLWJ5dGVz")
	r := &DCAPIResponse{Protocol: ProtocolISOmDoc, Data: inner}
	vp, _, err := r.ExtractVPToken()
	if err != nil {
		t.Fatal(err)
	}
	if vp != "bW9jay1tZG9jLWJ5dGVz" {
		t.Errorf("mdoc raw: %s", vp)
	}
}

func TestExtractVPTokenUnsupported(t *testing.T) {
	r := &DCAPIResponse{Protocol: "unknown-protocol", Data: json.RawMessage(`{}`)}
	if _, _, err := r.ExtractVPToken(); err == nil {
		t.Fatal("should reject unsupported")
	}
}

func TestToJavaScript(t *testing.T) {
	def := openid4vp.PresentationDefinition{
		ID:             "x",
		RequiredClaims: []string{"c"},
		AcceptableDIDs: []string{"did:web:i"},
	}
	call, err := BuildForVerifier(def, "n", "c", "")
	if err != nil {
		t.Fatal(err)
	}
	js := call.ToJavaScript()
	// 出力に navigator.credentials.get と request 定数が含まれる
	if !strings.Contains(js, "navigator.credentials.get") {
		t.Error("missing navigator.credentials.get")
	}
	if !strings.Contains(js, "openid4vp-v1-unsigned") {
		t.Error("missing protocol id")
	}
	if !strings.Contains(js, "org-iso-mdoc") {
		t.Error("missing mdoc protocol id")
	}
}

func TestDetectUserAgent(t *testing.T) {
	cases := []struct {
		ua   string
		want Protocol
	}{
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) AppleWebKit/605.1.15 Version/26.0 Safari/605.1.15", ProtocolISOmDoc},
		{"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/141.0.0.0 Safari/537.36", ProtocolOpenID4VPUnsigned},
		{"Mozilla/5.0 (Windows NT 10.0) Firefox/149.0", ProtocolOpenID4VPUnsigned},
		{"curl/8.0", ProtocolOpenID4VPUnsigned}, // fallback
	}
	for _, c := range cases {
		if got := DetectUserAgent(c.ua); got != c.want {
			t.Errorf("UA %q: got %s want %s", c.ua, got, c.want)
		}
	}
}

// ============================================================================
// DCQL DC-API builder (OpenID4VP v1.0)
// ============================================================================

func TestBuildForVerifierDCQL(t *testing.T) {
	query := openid4vp.DCQLQuery{
		Credentials: []openid4vp.CredentialQuery{{
			ID:     "dpp",
			Format: "dc+sd-jwt",
			Meta:   &openid4vp.CredentialQueryMeta{VCTValues: []string{"https://schema.europa.eu/dpp/sd-jwt-vc/v1"}},
			Claims: []openid4vp.ClaimQuery{{Path: []string{"carbonKgCO2ePerKWh"}}},
		}},
	}
	call, err := BuildForVerifierDCQL(query, "nonce-xyz", "https://verify.blrcs", "https://verify.blrcs/cb")
	if err != nil {
		t.Fatal(err)
	}
	if len(call.Digital.Requests) != 1 {
		t.Fatalf("expected 1 request, got %d", len(call.Digital.Requests))
	}
	body := string(call.Digital.Requests[0].Data)
	if !strings.Contains(body, "dcql_query") {
		t.Error("DC-API body should contain dcql_query")
	}
	if !strings.Contains(body, "dc+sd-jwt") {
		t.Error("DC-API body should carry the credential format")
	}
	if !strings.Contains(body, `"response_mode":"dc_api"`) {
		t.Error("DC-API body should use dc_api response mode")
	}
}

func TestBuildForVerifierDCQLInvalid(t *testing.T) {
	if _, err := BuildForVerifierDCQL(openid4vp.DCQLQuery{}, "n", "c", ""); err == nil {
		t.Error("empty DCQL should fail")
	}
}

func TestBuildForVerifierDCQLNoResponseURI(t *testing.T) {
	query := openid4vp.DCQLQuery{Credentials: []openid4vp.CredentialQuery{{ID: "x", Format: "dc+sd-jwt"}}}
	call, err := BuildForVerifierDCQL(query, "n", "c", "")
	if err != nil {
		t.Fatal(err)
	}
	body := string(call.Digital.Requests[0].Data)
	if strings.Contains(body, "response_uri") {
		t.Error("empty responseURI should be omitted")
	}
}

func TestContainsAny(t *testing.T) {
	// covered via DetectUserAgent, but directly exercise edge cases
	if containsAny("") {
		t.Error("empty string should not contain anything")
	}
	if containsAny("hello", "") {
		t.Error("empty sub should be skipped")
	}
	if !containsAny("Chrome/90", "Chrome") {
		t.Error("should contain Chrome")
	}
	if containsAny("Firefox", "Chrome", "Safari") {
		t.Error("Firefox should not contain Chrome or Safari")
	}
}

func TestExtractNonceAtEnd(t *testing.T) {
	// nonce is last param — no trailing &
	url := "openid4vp://authorize?response_type=vp_token&nonce=abc123"
	nonce := extractNonce(url)
	if nonce != "abc123" {
		t.Errorf("extractNonce: %q", nonce)
	}
}

func TestExtractNonceMissing(t *testing.T) {
	nonce := extractNonce("openid4vp://authorize?response_type=vp_token")
	if nonce != "" {
		t.Errorf("missing nonce should return empty: %q", nonce)
	}
}
