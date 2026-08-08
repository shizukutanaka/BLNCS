package mcp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

// ============================================================================
// Axis 134: build_dpp_bundle / anchor_dpp_bundle / verify_dpp_bundle
// ============================================================================

func issueSDJWTFor(t *testing.T, srv *Server, issuerID, subject string) string {
	t.Helper()
	res := toolCall(t, srv, 1, "issue_sdjwt", map[string]any{
		"issuerId": issuerID, "subject": subject,
		"sdClaims":     map[string]any{"carbonKgCO2ePerKWh": 42.0},
		"clearClaims":  map[string]any{"batteryCategory": "ev"},
		"validForDays": 3650,
	})
	var out struct {
		SDJWT string `json:"sdjwt"`
	}
	if err := json.Unmarshal([]byte(toolCallText(t, res)), &out); err != nil {
		t.Fatal(err)
	}
	if out.SDJWT == "" {
		t.Fatalf("no sdjwt: %s", toolCallText(t, res))
	}
	return out.SDJWT
}

// TestDPPBundleLifecycleViaMCP runs the real flow a recycler or customs officer
// would rely on: issue, package, timestamp, then verify with no connectivity.
func TestDPPBundleLifecycleViaMCP(t *testing.T) {
	srv, iss, _ := setupServer(t)
	sdjwt := issueSDJWTFor(t, srv, iss.ID, "battery-001")

	// Build by issuerId — the server resolves the key, so an agent never needs
	// the raw bytes.
	built := toolCall(t, srv, 2, "build_dpp_bundle", map[string]any{
		"credential": sdjwt, "issuerId": iss.ID,
	})
	bundleJSON := toolCallText(t, built)

	// Anchor supplies the long-term-validation timestamp.
	anchored := toolCall(t, srv, 3, "anchor_dpp_bundle", map[string]any{
		"bundleJson": bundleJSON, "issuerId": iss.ID,
	})
	anchoredJSON := toolCallText(t, anchored)
	if anchoredJSON == bundleJSON {
		t.Fatal("anchoring should have changed the bundle")
	}

	verified := toolCall(t, srv, 4, "verify_dpp_bundle", map[string]any{
		"bundleJson": anchoredJSON, "requireTimestamp": true,
	})
	var out struct {
		Valid             bool   `json:"valid"`
		Subject           string `json:"subject"`
		CheckedTimestamp  bool   `json:"checkedTimestamp"`
		CheckedRevocation bool   `json:"checkedRevocation"`
		AnchorCount       int    `json:"anchorCount"`
	}
	if err := json.Unmarshal([]byte(toolCallText(t, verified)), &out); err != nil {
		t.Fatal(err)
	}
	if !out.Valid || !out.CheckedTimestamp || out.AnchorCount != 1 {
		t.Fatalf("anchored bundle should verify with a timestamp: %s", toolCallText(t, verified))
	}
	if out.Subject != "battery-001" {
		t.Errorf("subject: got %q", out.Subject)
	}
	// No status snapshot was embedded — that must be reported, never assumed.
	if out.CheckedRevocation {
		t.Error("revocation must not be reported as checked without a snapshot")
	}
}

// TestBundleRenewalViaMCP proves anchoring twice builds the RFC 4998 chain.
func TestBundleRenewalViaMCP(t *testing.T) {
	srv, iss, _ := setupServer(t)
	sdjwt := issueSDJWTFor(t, srv, iss.ID, "battery-002")
	built := toolCall(t, srv, 1, "build_dpp_bundle", map[string]any{
		"credential":         sdjwt,
		"issuerPublicKeyB64": base64.StdEncoding.EncodeToString(iss.PublicKey()),
	})
	j := toolCallText(t, built)
	for i := 0; i < 2; i++ {
		j = toolCallText(t, toolCall(t, srv, 2+i, "anchor_dpp_bundle",
			map[string]any{"bundleJson": j, "issuerId": iss.ID}))
	}
	res := toolCall(t, srv, 9, "verify_dpp_bundle", map[string]any{"bundleJson": j, "requireTimestamp": true})
	var out struct {
		Valid       bool `json:"valid"`
		AnchorCount int  `json:"anchorCount"`
	}
	if err := json.Unmarshal([]byte(toolCallText(t, res)), &out); err != nil {
		t.Fatal(err)
	}
	if !out.Valid || out.AnchorCount != 2 {
		t.Fatalf("renewed chain should verify with 2 anchors: %s", toolCallText(t, res))
	}
}

// TestVerifyDPPBundleFailsClosed proves require* turns missing evidence into an
// explicit failure rather than a silent pass.
func TestVerifyDPPBundleFailsClosed(t *testing.T) {
	srv, iss, _ := setupServer(t)
	sdjwt := issueSDJWTFor(t, srv, iss.ID, "battery-003")
	built := toolCall(t, srv, 1, "build_dpp_bundle", map[string]any{
		"credential":         sdjwt,
		"issuerPublicKeyB64": base64.StdEncoding.EncodeToString(iss.PublicKey()),
	})
	for _, flag := range []string{"requireRevocationCheck", "requireTimestamp", "requireProvenance"} {
		res := toolCall(t, srv, 2, "verify_dpp_bundle", map[string]any{
			"bundleJson": toolCallText(t, built), flag: true,
		})
		var out struct {
			Valid bool `json:"valid"`
		}
		if err := json.Unmarshal([]byte(toolCallText(t, res)), &out); err != nil {
			t.Fatal(err)
		}
		if out.Valid {
			t.Errorf("%s with no evidence must fail", flag)
		}
	}
}

func TestVerifyDPPBundleRejectsGarbage(t *testing.T) {
	srv, _, _ := setupServer(t)
	res := toolCall(t, srv, 1, "verify_dpp_bundle", map[string]any{"bundleJson": "not a bundle"})
	var out struct {
		Valid bool `json:"valid"`
	}
	if err := json.Unmarshal([]byte(toolCallText(t, res)), &out); err != nil {
		t.Fatal(err)
	}
	if out.Valid {
		t.Fatal("garbage must not verify")
	}
}

// TestBuildBundleRequiresAnIssuer proves the tool rejects a call that names
// neither an issuerId nor a raw key, rather than building an unusable bundle.
func TestBuildBundleRequiresAnIssuer(t *testing.T) {
	srv, iss, _ := setupServer(t)
	sdjwt := issueSDJWTFor(t, srv, iss.ID, "battery-004")
	if res := toolCall(t, srv, 1, "build_dpp_bundle", map[string]any{"credential": sdjwt}); !res["isError"].(bool) {
		t.Fatal("build with no issuer should error")
	}
}

// TestBuildBundleByIssuerIDMatchesRawKey proves the issuerId path produces a
// bundle equivalent to passing the raw key.
func TestBuildBundleByIssuerIDMatchesRawKey(t *testing.T) {
	srv, iss, _ := setupServer(t)
	sdjwt := issueSDJWTFor(t, srv, iss.ID, "battery-005")
	byID := toolCallText(t, toolCall(t, srv, 1, "build_dpp_bundle",
		map[string]any{"credential": sdjwt, "issuerId": iss.ID}))
	byKey := toolCallText(t, toolCall(t, srv, 2, "build_dpp_bundle",
		map[string]any{"credential": sdjwt, "issuerPublicKeyB64": base64.StdEncoding.EncodeToString(iss.PublicKey())}))
	var a, b map[string]any
	if err := json.Unmarshal([]byte(byID), &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(byKey), &b); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(a["issuerKey"]) != fmt.Sprint(b["issuerKey"]) {
		t.Error("issuerId and raw-key paths should embed the same key")
	}
}
