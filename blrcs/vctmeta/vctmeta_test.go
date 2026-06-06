package vctmeta

import (
	"context"
	"testing"
)

const vctURL = "https://schema.europa.eu/dpp/sd-jwt-vc/v1"

var sampleMeta = []byte(`{"vct":"https://schema.europa.eu/dpp/sd-jwt-vc/v1","name":"EU DPP","description":"Digital Product Passport","schema_uri":"https://schema.europa.eu/dpp/schema.json"}`)

func memFetcher(data []byte) FetchFunc {
	return func(_ context.Context, _ string) ([]byte, error) { return data, nil }
}

func TestIntegrityRoundTrip(t *testing.T) {
	integ := Integrity(sampleMeta)
	if err := VerifyIntegrity(sampleMeta, integ); err != nil {
		t.Fatalf("matching integrity should verify: %v", err)
	}
	if err := VerifyIntegrity([]byte("tampered"), integ); err != ErrIntegrityMismatch {
		t.Fatalf("tampered data: want ErrIntegrityMismatch, got %v", err)
	}
}

func TestVerifyIntegrityBadFormat(t *testing.T) {
	for _, bad := range []string{"", "sha256", "md5-abc", "sha256-", "sha256-!!!notb64"} {
		if err := VerifyIntegrity(sampleMeta, bad); err == nil {
			t.Errorf("VerifyIntegrity(%q) should fail", bad)
		}
	}
}

func TestResolveRequiresHTTPS(t *testing.T) {
	if _, err := Resolve(context.Background(), "urn:example:type", "", memFetcher(sampleMeta)); err != ErrNotHTTPS {
		t.Fatalf("non-https vct: want ErrNotHTTPS, got %v", err)
	}
}

func TestResolveHappyPathWithIntegrity(t *testing.T) {
	integ := Integrity(sampleMeta)
	tm, err := Resolve(context.Background(), vctURL, integ, memFetcher(sampleMeta))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if tm.Name != "EU DPP" || tm.SchemaURI == "" {
		t.Errorf("metadata not parsed: %+v", tm)
	}
	if len(tm.Raw) == 0 {
		t.Error("Raw bytes should be retained for caching/rehashing")
	}
}

func TestResolveIntegrityMismatch(t *testing.T) {
	// Credential pins an integrity for different bytes → fetched metadata rejected.
	wrong := Integrity([]byte(`{"vct":"x"}`))
	if _, err := Resolve(context.Background(), vctURL, wrong, memFetcher(sampleMeta)); err != ErrIntegrityMismatch {
		t.Fatalf("want ErrIntegrityMismatch, got %v", err)
	}
}

func TestResolveNoIntegritySkipsCheck(t *testing.T) {
	// Empty expectedIntegrity → fetch + parse without verification.
	tm, err := Resolve(context.Background(), vctURL, "", memFetcher(sampleMeta))
	if err != nil || tm.VCT != vctURL {
		t.Fatalf("resolve without integrity: tm=%+v err=%v", tm, err)
	}
}
