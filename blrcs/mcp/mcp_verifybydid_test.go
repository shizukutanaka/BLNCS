package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"blrcs/compliance"
	"blrcs/didresolver"
)

// ============================================================================
// Axis 110: verify_passport_by_did / verify_sdjwt_by_did
// ============================================================================

// setupDIDVerifyServer returns a server whose didResolver is mocked to
// resolve issuerDID to iss's public key via a did:web document, avoiding a
// real network round-trip.
func setupDIDVerifyServer(t *testing.T, issuerDID string, iss *compliance.Issuer) *Server {
	t.Helper()
	srv, err := NewServer("did:web:ts.blrcs.example", "did:web:blrcs-mcp.example")
	if err != nil {
		t.Fatal(err)
	}
	srv.didResolver.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) {
		doc := map[string]any{
			"id": issuerDID,
			"verificationMethod": []map[string]any{
				{
					"id":         issuerDID + "#key-1",
					"type":       "JsonWebKey2020",
					"controller": issuerDID,
					"publicKeyJwk": map[string]any{
						"kty": "OKP",
						"crv": "Ed25519",
						"x":   base64.RawURLEncoding.EncodeToString(iss.PublicKey()),
					},
				},
			},
		}
		b, _ := json.Marshal(doc)
		return b, nil
	}
	return srv
}

func TestVerifyPassportByDIDHappyPath(t *testing.T) {
	issuerDID := "did:web:factory.example"
	iss, err := compliance.NewIssuer(issuerDID)
	if err != nil {
		t.Fatal(err)
	}
	srv := setupDIDVerifyServer(t, issuerDID, iss)

	cred, err := iss.Issue(compliance.PassportClaim{ProductID: "P-1", Category: "textile"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	credJSON, _ := json.Marshal(cred)

	result := toolCall(t, srv, 1, "verify_passport_by_did", map[string]any{
		"credentialJson": string(credJSON),
	})
	text := toolCallText(t, result)
	var out struct {
		Valid bool `json:"valid"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatal(err)
	}
	if !out.Valid {
		t.Fatalf("expected valid=true, got %s", text)
	}
}

func TestVerifyPassportByDIDUntrustedRejected(t *testing.T) {
	issuerDID := "did:web:factory.example"
	iss, err := compliance.NewIssuer(issuerDID)
	if err != nil {
		t.Fatal(err)
	}
	srv := setupDIDVerifyServer(t, issuerDID, iss)
	// Replace the default allow-all anchor with a restrictive one that trusts
	// nothing, proving RegisterTrustAnchor actually gates verification.
	srv.RegisterTrustAnchor(didresolver.NewTrustAnchor())

	cred, err := iss.Issue(compliance.PassportClaim{ProductID: "P-1", Category: "textile"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	credJSON, _ := json.Marshal(cred)

	result := toolCall(t, srv, 1, "verify_passport_by_did", map[string]any{
		"credentialJson": string(credJSON),
	})
	text := toolCallText(t, result)
	var out struct {
		Valid bool `json:"valid"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatal(err)
	}
	if out.Valid {
		t.Fatal("untrusted issuer DID should not verify")
	}
}

func TestVerifyPassportByDIDMissingIssuer(t *testing.T) {
	srv, _, _ := setupServer(t)
	result := toolCall(t, srv, 1, "verify_passport_by_did", map[string]any{
		"credentialJson": `{"credentialSubject":{}}`,
	})
	if !result["isError"].(bool) {
		t.Fatal("credential with no issuer should error")
	}
}

func TestVerifySDJWTByDIDHappyPath(t *testing.T) {
	issuerDID := "did:web:factory.example"
	iss, err := compliance.NewIssuer(issuerDID)
	if err != nil {
		t.Fatal(err)
	}
	srv := setupDIDVerifyServer(t, issuerDID, iss)

	sdjwt, _, err := iss.IssueSDJWT("subject-1", map[string]any{"category": "textile"}, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	result := toolCall(t, srv, 1, "verify_sdjwt_by_did", map[string]any{
		"sdjwt":     sdjwt,
		"issuerDid": issuerDID,
	})
	text := toolCallText(t, result)
	var out struct {
		Valid bool `json:"valid"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatal(err)
	}
	if !out.Valid {
		t.Fatalf("expected valid=true, got %s", text)
	}
}

func TestVerifySDJWTByDIDMissingIssuerDID(t *testing.T) {
	srv, _, _ := setupServer(t)
	result := toolCall(t, srv, 1, "verify_sdjwt_by_did", map[string]any{"sdjwt": "x.y.z"})
	if !result["isError"].(bool) {
		t.Fatal("missing issuerDid should error")
	}
}

// TestVerifyByDIDToolsNotAudited verifies these are pure/read-only tools with
// no ledger side effects, matching verify_passport/verify_sdjwt.
func TestVerifyByDIDToolsNotAudited(t *testing.T) {
	issuerDID := "did:web:factory.example"
	iss, err := compliance.NewIssuer(issuerDID)
	if err != nil {
		t.Fatal(err)
	}
	srv := setupDIDVerifyServer(t, issuerDID, iss)
	cred, err := iss.Issue(compliance.PassportClaim{ProductID: "P-1", Category: "textile"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	credJSON, _ := json.Marshal(cred)

	before := srv.Ledger().Size()
	toolCall(t, srv, 1, "verify_passport_by_did", map[string]any{"credentialJson": string(credJSON)})
	after := srv.Ledger().Size()
	if after != before {
		t.Errorf("verify_passport_by_did should not be audited: before=%d after=%d", before, after)
	}
}
