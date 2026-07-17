package compose

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"blrcs/cas"
	"blrcs/compliance"
	"blrcs/didresolver"
	"blrcs/scitt"
	"blrcs/telemetry"
	"blrcs/webhook"
)

// ============================================================================
// Helpers
// ============================================================================

func setup(t *testing.T) (*Composer, *compliance.Issuer, *cas.Provenance) {
	t.Helper()
	iss, err := compliance.NewIssuer("did:web:factory.compose.test")
	if err != nil {
		t.Fatal(err)
	}
	resolver := didresolver.New()
	anchor := didresolver.NewTrustAnchor()
	anchor.AddDID(iss.ID)
	anchor.AddKey(iss.PublicKey())

	store := cas.NewMemoryStore()
	prov := cas.NewProvenance(store)

	tel := telemetry.New(telemetry.NopRecorder{})
	bus := webhook.NewBus(tel)
	bus.AllowPrivateTargets = true // test delivers to httptest (loopback)

	ledger, _ := scitt.NewLedger("did:web:ts.compose.test")

	c := New(Options{
		Issuer:      iss,
		Resolver:    resolver,
		TrustAnchor: anchor,
		Bus:         bus,
		CAS:         store,
		Provenance:  prov,
		Ledger:      ledger,
		Telemetry:   tel,
	})
	return c, iss, prov
}

// ============================================================================
// IssueAndPublish — full E2E
// ============================================================================

func TestIssueAndPublishHappyPath(t *testing.T) {
	c, iss, prov := setup(t)

	res, err := c.IssueAndPublish(context.Background(),
		compliance.PassportClaim{
			ProductID:    "P-COMPOSE-1",
			Category:     "test",
			CarbonKgCO2e: 1.5,
		},
		"compose-receipt-1",
		time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	if res.Credential == nil {
		t.Fatal("nil credential")
	}
	// CAS hash recorded
	if res.Hash == "" {
		t.Error("CAS hash empty")
	}
	// SCITT receipt recorded
	if res.Receipt == nil {
		t.Error("SCITT receipt missing")
	}
	if res.Receipt.LeafIndex != 0 {
		t.Errorf("first leaf: %d", res.Receipt.LeafIndex)
	}

	// Provenance lookup roundtrip
	cred, _, err := c.LookupByExternalID("compose-receipt-1")
	if err != nil {
		t.Fatal(err)
	}
	if cred.Subject.ProductID != "P-COMPOSE-1" {
		t.Errorf("provenance roundtrip: %s", cred.Subject.ProductID)
	}

	// Provenance index sees 1 unique payload
	if prov.Stats().UniquePayloads < 1 {
		t.Errorf("provenance stats: %+v", prov.Stats())
	}

	// Verify with original issuer key works
	if err := compliance.Verify(res.Credential, iss.PublicKey()); err != nil {
		t.Errorf("issued credential should verify: %v", err)
	}
}

func TestIssueAndPublishMissingIssuer(t *testing.T) {
	c := New(Options{}) // no issuer
	_, err := c.IssueAndPublish(context.Background(),
		compliance.PassportClaim{ProductID: "x"}, "id", time.Hour)
	if err == nil || !strings.Contains(err.Error(), "Issuer required") {
		t.Errorf("missing issuer should fail clearly: %v", err)
	}
}

func TestIssueAndPublishContextCancelled(t *testing.T) {
	c, _, _ := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.IssueAndPublish(ctx,
		compliance.PassportClaim{ProductID: "x"}, "id", 0)
	if err != context.Canceled {
		t.Errorf("want context.Canceled, got %v", err)
	}
}

// ============================================================================
// Webhook integration
// ============================================================================

func TestIssueAndPublishFiresWebhook(t *testing.T) {
	c, _, _ := setup(t)

	var receivedEvent atomic.Value
	server := httptest.NewServer(httptest.NewServer(nil).Config.Handler) // placeholder
	server.Close()

	// Real test server
	var hits atomic.Int32
	srv := startCaptureServer(&hits, &receivedEvent)
	defer srv.Close()

	c.opts.Bus.Subscribe("dpp.issued", webhook.Subscriber{
		URL:    srv.URL,
		Secret: []byte("test-secret"),
	})

	_, err := c.IssueAndPublish(context.Background(),
		compliance.PassportClaim{ProductID: "WHK-1"},
		"webhook-target",
		time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Wait briefly for background goroutine
	time.Sleep(200 * time.Millisecond)

	if hits.Load() != 1 {
		t.Errorf("webhook hits: %d (want 1)", hits.Load())
	}
	body, ok := receivedEvent.Load().([]byte)
	if !ok || len(body) == 0 {
		t.Fatal("no webhook payload received")
	}
	var ev webhook.Event
	if err := json.Unmarshal(body, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Type != "dpp.issued" {
		t.Errorf("event type: %s", ev.Type)
	}
}

func startCaptureServer(hits *atomic.Int32, payload *atomic.Value) *httptest.Server {
	return httptest.NewServer(captureHandler{hits: hits, payload: payload})
}

type captureHandler struct {
	hits    *atomic.Int32
	payload *atomic.Value
}

func (c captureHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.hits.Add(1)
	body := make([]byte, r.ContentLength)
	r.Body.Read(body)
	c.payload.Store(body)
	w.WriteHeader(200)
}

// ============================================================================
// VerifyByDID
// ============================================================================

func TestVerifyByDIDHappyPath(t *testing.T) {
	c, iss, _ := setup(t)
	cred, _ := iss.Issue(compliance.PassportClaim{ProductID: "VER-1"}, time.Hour)

	// Fake the DID resolver to return iss.PublicKey
	c.opts.Resolver.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) {
		// Build a DID document with iss public key
		return mockDIDDoc(iss.PublicKey()), nil
	}

	err := c.VerifyByDID(context.Background(), cred, iss.ID)
	if err != nil {
		t.Errorf("verify should pass: %v", err)
	}
}

func TestVerifyByDIDUntrusted(t *testing.T) {
	c, iss, _ := setup(t)
	cred, _ := iss.Issue(compliance.PassportClaim{ProductID: "x"}, time.Hour)

	// Replace trust anchor with empty one
	c.opts.TrustAnchor = didresolver.NewTrustAnchor()
	c.opts.Resolver.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) {
		return mockDIDDoc(iss.PublicKey()), nil
	}

	err := c.VerifyByDID(context.Background(), cred, iss.ID)
	if err == nil {
		t.Error("untrusted DID should fail verification")
	}
}

func TestVerifyByDIDTamperedCredential(t *testing.T) {
	c, iss, _ := setup(t)
	cred, _ := iss.Issue(compliance.PassportClaim{ProductID: "x", CarbonKgCO2e: 1}, time.Hour)
	cred.Subject.CarbonKgCO2e = 999 // tamper

	c.opts.Resolver.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) {
		return mockDIDDoc(iss.PublicKey()), nil
	}
	if err := c.VerifyByDID(context.Background(), cred, iss.ID); err == nil {
		t.Error("tampered credential should fail")
	}
}

func mockDIDDoc(pub ed25519.PublicKey) []byte {
	doc := map[string]any{
		"id": "did:web:factory.compose.test",
		"verificationMethod": []map[string]any{
			{
				"id":         "key-1",
				"type":       "JsonWebKey2020",
				"controller": "x",
				"publicKeyJwk": map[string]any{
					"kty": "OKP",
					"crv": "Ed25519",
					"x":   base64URLEncode(pub),
				},
			},
		},
	}
	b, _ := json.Marshal(doc)
	return b
}

func base64URLEncode(b []byte) string {
	return rawB64(b)
}

func rawB64(b []byte) string {
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	out := make([]byte, 0, (len(b)*8+5)/6)
	for i := 0; i < len(b); i += 3 {
		var n uint32
		var k int
		for j := 0; j < 3 && i+j < len(b); j++ {
			n = (n << 8) | uint32(b[i+j])
			k++
		}
		n <<= uint(24 - k*8)
		for j := 0; j < k+1; j++ {
			out = append(out, alpha[(n>>(18-j*6))&0x3f])
		}
	}
	return string(out)
}

// ============================================================================
// Coverage uplift: VerifySDJWTByDID, LookupByExternalID error
// ============================================================================

func TestVerifySDJWTByDIDHappyPath(t *testing.T) {
	c, iss, _ := setup(t)
	sdjwt, _, _ := iss.IssueSDJWT("subj", map[string]any{"x": 1}, nil, time.Hour)

	c.opts.Resolver.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) {
		return mockDIDDoc(iss.PublicKey()), nil
	}
	vc, err := c.VerifySDJWTByDID(context.Background(), sdjwt, iss.ID)
	if err != nil {
		t.Fatalf("VerifySDJWTByDID: %v", err)
	}
	if vc.Subject != "subj" {
		t.Errorf("subject: %s", vc.Subject)
	}
}

// twoKeyDoc serves a DID document listing two Ed25519 keys (rotation: new+old).
func twoKeyDoc(first, second ed25519.PublicKey) []byte {
	doc := map[string]any{
		"id": "did:web:factory.compose.test",
		"verificationMethod": []map[string]any{
			{"publicKeyJwk": map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64URLEncode(first)}},
			{"publicKeyJwk": map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64URLEncode(second)}},
		},
	}
	b, _ := json.Marshal(doc)
	return b
}

// TestVerifySDJWTByDID_RotationOldKeyStillVerifies — during key rotation the DID
// document lists the new key first and the old key second. A credential signed
// by the OLD key must still verify. The previous single-key resolver returned
// only the first (new) key, so verification failed; the multi-key path tries each.
func TestVerifySDJWTByDID_RotationOldKeyStillVerifies(t *testing.T) {
	c, iss, _ := setup(t)
	// Credential signed by the original (now "old") key.
	sdjwt, _, _ := iss.IssueSDJWT("subj", map[string]any{"x": 1}, nil, time.Hour)

	// Rotation: a new key is published FIRST, the old key remains second.
	rotated, _ := compliance.NewIssuer("did:web:factory.compose.test")
	c.opts.Resolver.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) {
		return twoKeyDoc(rotated.PublicKey(), iss.PublicKey()), nil
	}
	vc, err := c.VerifySDJWTByDID(context.Background(), sdjwt, iss.ID)
	if err != nil {
		t.Fatalf("rotation: credential signed by old (second-listed) key should verify: %v", err)
	}
	if vc.Subject != "subj" {
		t.Errorf("subject: %s", vc.Subject)
	}
}

func TestVerifySDJWTByDIDUntrusted(t *testing.T) {
	c, iss, _ := setup(t)
	sdjwt, _, _ := iss.IssueSDJWT("s", map[string]any{"x": 1}, nil, 0)
	c.opts.TrustAnchor = didresolver.NewTrustAnchor() // empty
	c.opts.Resolver.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) {
		return mockDIDDoc(iss.PublicKey()), nil
	}
	_, err := c.VerifySDJWTByDID(context.Background(), sdjwt, iss.ID)
	if err == nil {
		t.Error("untrusted DID should fail")
	}
}

func TestLookupByExternalIDNotFound(t *testing.T) {
	c, _, _ := setup(t)
	_, _, err := c.LookupByExternalID("nonexistent-id")
	if err == nil {
		t.Error("missing ID should return error")
	}
}

func TestLookupByExternalIDNoProvenance(t *testing.T) {
	c, _, _ := setup(t)
	c.opts.Provenance = nil
	_, _, err := c.LookupByExternalID("any")
	if err == nil {
		t.Error("nil Provenance should error")
	}
}

// ============================================================================
// DiscoverServices — DPP data location discovery (arXiv:2410.15758)
// ============================================================================

func TestDiscoverServices(t *testing.T) {
	c, _, _ := setup(t)
	c.opts.Resolver.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) {
		return []byte(`{
			"id": "did:web:factory.example",
			"verificationMethod": [],
			"service": [
				{"id":"#dpp","type":"DPPService","serviceEndpoint":"https://factory.example/dpp"}
			]
		}`), nil
	}
	services, err := c.DiscoverServices(context.Background(), "did:web:factory.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(services))
	}
	if services[0].Type != "DPPService" {
		t.Errorf("service type: %s", services[0].Type)
	}
}

func TestDiscoverServicesNoResolver(t *testing.T) {
	c, _, _ := setup(t)
	c.opts.Resolver = nil
	_, err := c.DiscoverServices(context.Background(), "did:web:x.example")
	if err == nil {
		t.Error("missing resolver should error")
	}
}

// ============================================================================
// Guard-clause coverage: nil Resolver/TrustAnchor, cancelled context, bad JSON
// ============================================================================

func TestVerifyByDIDNoResolver(t *testing.T) {
	c, iss, _ := setup(t)
	cred, _ := iss.Issue(compliance.PassportClaim{ProductID: "x"}, time.Hour)
	c.opts.Resolver = nil
	if err := c.VerifyByDID(context.Background(), cred, iss.ID); err == nil {
		t.Error("nil Resolver should error")
	}
}

func TestVerifyByDIDNoTrustAnchor(t *testing.T) {
	c, iss, _ := setup(t)
	cred, _ := iss.Issue(compliance.PassportClaim{ProductID: "x"}, time.Hour)
	c.opts.TrustAnchor = nil
	if err := c.VerifyByDID(context.Background(), cred, iss.ID); err == nil {
		t.Error("nil TrustAnchor should error")
	}
}

func TestVerifyByDIDCancelledContext(t *testing.T) {
	c, iss, _ := setup(t)
	cred, _ := iss.Issue(compliance.PassportClaim{ProductID: "x"}, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.VerifyByDID(ctx, cred, iss.ID); err == nil {
		t.Error("cancelled context should error")
	}
}

func TestVerifySDJWTByDIDNoResolver(t *testing.T) {
	c, iss, _ := setup(t)
	sdjwt, _, _ := iss.IssueSDJWT("s", map[string]any{"x": 1}, nil, time.Hour)
	c.opts.Resolver = nil
	if _, err := c.VerifySDJWTByDID(context.Background(), sdjwt, iss.ID); err == nil {
		t.Error("nil Resolver should error")
	}
}

func TestVerifySDJWTByDIDNoTrustAnchor(t *testing.T) {
	c, iss, _ := setup(t)
	sdjwt, _, _ := iss.IssueSDJWT("s", map[string]any{"x": 1}, nil, time.Hour)
	c.opts.TrustAnchor = nil
	if _, err := c.VerifySDJWTByDID(context.Background(), sdjwt, iss.ID); err == nil {
		t.Error("nil TrustAnchor should error")
	}
}

func TestLookupByExternalIDBadJSON(t *testing.T) {
	c, _, prov := setup(t)
	if _, err := prov.Record("bad-json-id", []byte("{not valid json")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.LookupByExternalID("bad-json-id"); err == nil {
		t.Error("bad JSON payload should cause unmarshal error")
	}
}

// ============================================================================
// Axis 97: IssueAndPublish surfaces partial-step failures instead of
// silently swallowing them.
// ============================================================================

// failingStore always fails Put, to simulate a CAS/Provenance backend outage.
type failingStore struct{}

func (failingStore) Put(payload []byte) (cas.Hash, error)    { return "", errFailingStore }
func (failingStore) Get(h cas.Hash) ([]byte, error)          { return nil, errFailingStore }
func (failingStore) Has(h cas.Hash) bool                     { return false }
func (failingStore) Size() int                               { return 0 }
func (failingStore) Iterate(fn func(h cas.Hash) error) error { return nil }

var errFailingStore = errors.New("failingStore: simulated backend outage")

// TestIssueAndPublishCASFailureSurfaced verifies that a CAS.Put failure is
// reported via StepFailures rather than silently leaving res.Hash empty with
// a nil error, which previously looked identical to "CAS not configured".
func TestIssueAndPublishCASFailureSurfaced(t *testing.T) {
	c, _, _ := setup(t)
	c.opts.CAS = failingStore{}
	c.opts.Provenance = nil // avoid a second failure from the same store

	res, err := c.IssueAndPublish(context.Background(),
		compliance.PassportClaim{ProductID: "P-CAS-FAIL"}, "id-cas-fail", time.Hour)
	if err != nil {
		t.Fatalf("Issue itself should still succeed: %v", err)
	}
	if res.Credential == nil {
		t.Fatal("credential should still be issued despite CAS failure")
	}
	if res.Hash != "" {
		t.Errorf("Hash should stay empty when CAS.Put fails, got %q", res.Hash)
	}
	if len(res.StepFailures) != 1 {
		t.Fatalf("want 1 StepFailure, got %d: %v", len(res.StepFailures), res.StepFailures)
	}
	if !errors.Is(res.StepFailures[0], errFailingStore) {
		t.Errorf("StepFailures[0] should wrap the CAS error, got %v", res.StepFailures[0])
	}
}

// TestIssueAndPublishSCITTFailureSurfaced verifies that a rejected SCITT
// registration (e.g. an issuer not on the ledger's trusted-issuer allowlist)
// is reported via StepFailures rather than silently leaving res.Receipt nil
// with a nil error — for a compliance system whose value is the audit trail,
// a failed registration must not look identical to "Ledger not configured".
func TestIssueAndPublishSCITTFailureSurfaced(t *testing.T) {
	c, iss, _ := setup(t)
	// Non-empty trusted-issuer allowlist that excludes our composer's issuer,
	// so Ledger.Register deterministically rejects with ErrUntrustedIssuer.
	c.opts.Ledger.RegisterTrustedIssuer("did:web:someone-else.example", iss.PublicKey())

	res, err := c.IssueAndPublish(context.Background(),
		compliance.PassportClaim{ProductID: "P-SCITT-FAIL"}, "id-scitt-fail", time.Hour)
	if err != nil {
		t.Fatalf("Issue itself should still succeed: %v", err)
	}
	if res.Receipt != nil {
		t.Error("Receipt should stay nil when SCITT registration is rejected")
	}
	if len(res.StepFailures) != 1 {
		t.Fatalf("want 1 StepFailure, got %d: %v", len(res.StepFailures), res.StepFailures)
	}
	if !errors.Is(res.StepFailures[0], scitt.ErrUntrustedIssuer) {
		t.Errorf("StepFailures[0] should wrap ErrUntrustedIssuer, got %v", res.StepFailures[0])
	}
}

// TestIssueAndPublishHappyPathNoStepFailures verifies the all-succeed path
// leaves StepFailures nil (no regression on the common case).
func TestIssueAndPublishHappyPathNoStepFailures(t *testing.T) {
	c, _, _ := setup(t)
	res, err := c.IssueAndPublish(context.Background(),
		compliance.PassportClaim{ProductID: "P-OK"}, "id-ok", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.StepFailures) != 0 {
		t.Errorf("happy path should have no StepFailures, got %v", res.StepFailures)
	}
}
