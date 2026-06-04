package revocation

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"testing"
)

// TestDecodeBitstringRejectsDecompressionBomb — a small gzip payload that
// inflates past the decoded-size cap must be rejected instead of exhausting
// memory via the previous unbounded io.ReadAll.
func TestDecodeBitstringRejectsDecompressionBomb(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	// Zeros compress to near nothing; this is the classic bomb shape.
	if _, err := gz.Write(make([]byte, maxDecodedListBytes+1)); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(buf.Bytes())
	if len(encoded) > maxEncodedListBytes {
		t.Fatalf("test payload unexpectedly large: %d", len(encoded))
	}
	if _, err := DecodeBitstringStatusList(PurposeRevocation, encoded); err == nil {
		t.Fatal("decompression bomb should be rejected")
	}
}

// TestDecodeBitstringRejectsOversizedInput — an over-long base64 input is
// rejected before any decompression work.
func TestDecodeBitstringRejectsOversizedInput(t *testing.T) {
	huge := make([]byte, maxEncodedListBytes+1)
	for i := range huge {
		huge[i] = 'A'
	}
	if _, err := DecodeBitstringStatusList(PurposeRevocation, string(huge)); err == nil {
		t.Fatal("oversized encodedList should be rejected")
	}
}

// TestDecodeBitstringNormalRoundTripStillWorks — the guard must not break the
// ordinary encode/decode path.
func TestDecodeBitstringNormalRoundTripStillWorks(t *testing.T) {
	list := NewBitstringStatusList(PurposeRevocation, MinBitstringSize)
	if err := list.SetStatus(42, true); err != nil {
		t.Fatal(err)
	}
	encoded, err := list.EncodedList()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeBitstringStatusList(PurposeRevocation, encoded)
	if err != nil {
		t.Fatalf("normal round-trip failed: %v", err)
	}
	on, err := decoded.GetStatus(42)
	if err != nil {
		t.Fatal(err)
	}
	if !on {
		t.Error("status bit 42 should be set after round-trip")
	}
}
