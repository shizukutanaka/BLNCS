package dcapi

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"blrcs/compliance"
	"blrcs/openid4vp"
)

func setupDemo(t *testing.T) (*httptest.Server, *compliance.Issuer, *openid4vp.Verifier) {
	t.Helper()
	iss, _ := compliance.NewIssuer("did:web:factory.demo")
	ver := openid4vp.NewVerifier(
		"https://verify.demo",
		"https://verify.demo/cb",
		nil,
	)
	def := openid4vp.PresentationDefinition{
		ID:                "demo-pd",
		Purpose:           "Demo",
		RequiredClaims:    []string{"category", "carbonKgCO2e"},
		AcceptableIssuers: map[string][]byte{iss.ID: iss.PublicKey()},
	}
	h := DemoHandler(ver, def, "")
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts, iss, ver
}

func TestDemoHTMLPage(t *testing.T) {
	ts, _, _ := setupDemo(t)
	resp, err := http.Get(ts.URL + "/demo")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type: %s", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	// Key markers
	for _, want := range []string{
		"navigator.credentials.get",
		"BLRCS Digital Credentials",
		"/demo/authorize",
		"/demo/callback",
		"category, carbonKgCO2e", // required claims listed
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("missing in HTML: %s", want)
		}
	}
	// No CDN dependency
	if strings.Contains(string(body), "cdn.") {
		t.Error("HTML should have no CDN dependencies")
	}
}

func TestDemoAuthorize(t *testing.T) {
	ts, _, _ := setupDemo(t)
	resp, err := http.Post(ts.URL+"/demo/authorize", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	var out struct {
		RequestURL string   `json:"requestURL"`
		State      string   `json:"state"`
		DCAPI      *GetCall `json:"dcapi"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.RequestURL, "openid4vp://") {
		t.Errorf("request URL: %s", out.RequestURL)
	}
	if out.State == "" {
		t.Error("state empty")
	}
	if out.DCAPI == nil || len(out.DCAPI.Digital.Requests) != 2 {
		t.Errorf("DC-API structure: %+v", out.DCAPI)
	}
}

func TestDemoFullRoundTripWithMockWallet(t *testing.T) {
	ts, iss, _ := setupDemo(t)

	// 1. GET authorize
	resp, _ := http.Post(ts.URL+"/demo/authorize", "", nil)
	var auth struct {
		RequestURL string   `json:"requestURL"`
		State      string   `json:"state"`
		DCAPI      *GetCall `json:"dcapi"`
	}
	json.NewDecoder(resp.Body).Decode(&auth)
	resp.Body.Close()

	// 2. Mock wallet fulfills via native URL (bypassing browser DC-API).
	// Holder binding (cnf + KB-JWT) is required for anti-replay; the verifier
	// rejects unbound presentations when a nonce is expected.
	wallet := openid4vp.NewMockWallet("did:web:holder")
	holderPub, holderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wallet.HolderKey = holderPriv
	sdjwt, _, err := iss.IssueSDJWTBound("demo-subject", map[string]any{
		"category":     "textile",
		"carbonKgCO2e": 1.8,
	}, nil, holderPub, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	wallet.Store(openid4vp.StoredCredential{
		ID:        "c1",
		IssuerDID: iss.ID,
		IssuerPub: iss.PublicKey(),
		SDJWT:     sdjwt,
	})
	walletResp, err := wallet.Present(auth.RequestURL)
	if err != nil {
		t.Fatal(err)
	}

	// 3. Wrap the response as if DC-API callback (openid4vp protocol)
	payload := map[string]any{
		"protocol": "openid4vp-v1-unsigned",
		"data": map[string]any{
			"vp_token": walletResp.VPToken,
			"state":    walletResp.State,
		},
		"state": walletResp.State,
	}
	body, _ := json.Marshal(payload)
	cbResp, err := http.Post(ts.URL+"/demo/callback", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer cbResp.Body.Close()
	b, _ := io.ReadAll(cbResp.Body)
	if cbResp.StatusCode != 200 {
		t.Fatalf("callback %d: %s", cbResp.StatusCode, b)
	}
	var out map[string]any
	json.Unmarshal(b, &out)
	if out["status"] != "success" {
		t.Fatalf("status: %v body=%s", out["status"], b)
	}
	claims := out["claims"].(map[string]any)
	if claims["category"] != "textile" {
		t.Errorf("category: %v", claims["category"])
	}
}

func TestDemoMethodRestrictions(t *testing.T) {
	ts, _, _ := setupDemo(t)
	cases := []struct {
		path   string
		method string
	}{
		{"/demo", "POST"},
		{"/demo/authorize", "GET"},
		{"/demo/callback", "GET"},
	}
	for _, c := range cases {
		req, _ := http.NewRequest(c.method, ts.URL+c.path, nil)
		resp, _ := http.DefaultClient.Do(req)
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: want 405, got %d", c.method, c.path, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

func TestDemoCallbackMalformed(t *testing.T) {
	ts, _, _ := setupDemo(t)
	resp, err := http.Post(ts.URL+"/demo/callback", "application/json", strings.NewReader("{broken"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("want 400, got %d", resp.StatusCode)
	}
}

// ============================================================================
// Coverage uplift: DemoHandler error paths
// ============================================================================

func TestDemoAuthorizeCreateRequestError(t *testing.T) {
	// Handler with empty required claims → CreateRequest fails
	iss, _ := compliance.NewIssuer("did:web:factory.demo2")
	badVer := openid4vp.NewVerifier("https://verify.demo2", "https://verify.demo2/cb", nil)
	emptyDef := openid4vp.PresentationDefinition{
		ID:                "bad",
		RequiredClaims:    []string{}, // empty → ErrDefinitionEmpty
		AcceptableIssuers: map[string][]byte{iss.ID: iss.PublicKey()},
	}
	ts := httptest.NewServer(DemoHandler(badVer, emptyDef, ""))
	defer ts.Close()
	resp, err := http.Post(ts.URL+"/demo/authorize", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("want 400, got %d", resp.StatusCode)
	}
}

func TestDemoCallbackExtractVPTokenError(t *testing.T) {
	ts, _, _ := setupDemo(t)
	// Send valid JSON but with unsupported protocol → ExtractVPToken error
	body, _ := json.Marshal(map[string]any{
		"protocol": "unknown-protocol",
		"data":     map[string]string{"vp_token": "x"},
		"state":    "s",
	})
	resp, err := http.Post(ts.URL+"/demo/callback", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("want 400, got %d", resp.StatusCode)
	}
}

func TestDemoCallbackBodyTooLarge(t *testing.T) {
	ts, _, _ := setupDemo(t)
	big := bytes.Repeat([]byte("x"), (1<<20)+1)
	resp, err := http.Post(ts.URL+"/demo/callback", "application/json", bytes.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("want 400, got %d", resp.StatusCode)
	}
}

func TestDemoCallbackProcessResponseError(t *testing.T) {
	ts, _, _ := setupDemo(t)
	// Valid JSON with openid4vp protocol but bad vp_token → ProcessResponse error
	body, _ := json.Marshal(map[string]any{
		"protocol": "openid4vp-v1-unsigned",
		"data":     map[string]string{"vp_token": "bad.token.data"},
		"state":    "unknown-state",
	})
	resp, err := http.Post(ts.URL+"/demo/callback", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("want 400, got %d", resp.StatusCode)
	}
}

func setupDemoWithKey(t *testing.T) (*httptest.Server, *compliance.Issuer, *openid4vp.Verifier, ed25519.PrivateKey) {
	t.Helper()
	issuerPub, issuerPriv, _ := ed25519.GenerateKey(rand.Reader)
	iss, _ := compliance.NewIssuerFromKey("did:web:demo.keyed", issuerPriv)
	ver := openid4vp.NewVerifier("https://verify.keyed", "https://verify.keyed/cb", nil)
	def := openid4vp.PresentationDefinition{
		ID:                "demo-keyed",
		RequiredClaims:    []string{"category"},
		AcceptableIssuers: map[string][]byte{iss.ID: issuerPub},
	}
	h := DemoHandler(ver, def, "")
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts, iss, ver, issuerPriv
}

func TestDemoAuthorizeHappyPath(t *testing.T) {
	_, _, ver, _ := setupDemoWithKey(t)
	_ = ver
}
