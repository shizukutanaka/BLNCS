package semconv

import (
	"strings"
	"testing"
)

func TestStandardKeysMatchOTel(t *testing.T) {
	// Standard OTel keys must match the spec verbatim.
	cases := map[string]string{
		ServiceName:    "service.name",
		ServiceVersion: "service.version",
		ErrorType:      "error.type",
		HTTPMethod:     "http.request.method",
		HTTPStatusCode: "http.response.status_code",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("OTel key drift: %q != %q", got, want)
		}
	}
}

func TestDomainKeysAreNamespaced(t *testing.T) {
	// All BLRCS-specific keys must carry the vendor prefix.
	keys := []string{Issuer, Subject, ProductID, Attester, RangeName, SDClaimsCount, CredentialVCT, LedgerTSID, TreeSize, BatteryID}
	for _, k := range keys {
		if !strings.HasPrefix(k, "blrcs.") {
			t.Errorf("domain key %q missing blrcs. prefix", k)
		}
		// OTel keys are lowercase dotted, no camelCase
		if strings.ToLower(k) != k {
			t.Errorf("key %q should be lowercase (OTel convention)", k)
		}
	}
}

func TestHelperConstructors(t *testing.T) {
	if a := IssuerAttr("did:web:x"); a.Key != Issuer || a.Value.String() != "did:web:x" {
		t.Errorf("IssuerAttr wrong: %+v", a)
	}
	if a := ProductIDAttr("04012345678901"); a.Key != ProductID {
		t.Errorf("ProductIDAttr key: %s", a.Key)
	}
	if a := SDClaimsCountAttr(3); a.Key != SDClaimsCount || a.Value.Int64() != 3 {
		t.Errorf("SDClaimsCountAttr wrong: %+v", a)
	}
	if a := TreeSizeAttr(42); a.Key != TreeSize || a.Value.Uint64() != 42 {
		t.Errorf("TreeSizeAttr wrong: %+v", a)
	}
	if a := VCTAttr("https://schema.europa.eu/dpp/sd-jwt-vc/v1"); a.Key != CredentialVCT {
		t.Errorf("VCTAttr key: %s", a.Key)
	}
	if a := SubjectAttr("s"); a.Key != Subject {
		t.Errorf("SubjectAttr key: %s", a.Key)
	}
	if a := AttesterAttr("did:device:1"); a.Key != Attester {
		t.Errorf("AttesterAttr key: %s", a.Key)
	}
	if a := RangeNameAttr("temp"); a.Key != RangeName {
		t.Errorf("RangeNameAttr key: %s", a.Key)
	}
	if a := LedgerTSIDAttr("ts1"); a.Key != LedgerTSID {
		t.Errorf("LedgerTSIDAttr key: %s", a.Key)
	}
	if a := ErrorTypeAttr("timeout"); a.Key != ErrorType {
		t.Errorf("ErrorTypeAttr key: %s", a.Key)
	}
}

func TestNoDuplicateKeys(t *testing.T) {
	all := []string{
		ServiceName, ServiceVersion, ErrorType, ErrorMessage, HTTPMethod, HTTPStatusCode,
		Issuer, Subject, ProductID, Attester, RangeName, SDClaimsCount,
		CredentialVCT, LedgerTSID, TreeSize, BatteryID,
	}
	seen := map[string]bool{}
	for _, k := range all {
		if seen[k] {
			t.Errorf("duplicate key: %q", k)
		}
		seen[k] = true
	}
}
