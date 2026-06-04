package revocation

import (
	"testing"
)

func TestBitstringMinSize(t *testing.T) {
	// Requesting fewer than minimum should round up to herd-privacy minimum
	bsl := NewBitstringStatusList(PurposeRevocation, 100)
	if bsl.Capacity() < MinBitstringSize {
		t.Errorf("capacity %d below herd-privacy minimum %d", bsl.Capacity(), MinBitstringSize)
	}
}

func TestBitstringSetGet(t *testing.T) {
	bsl := NewBitstringStatusList(PurposeRevocation, MinBitstringSize)
	indices := []int{0, 1, 7, 8, 100, 1000, 131071}
	for _, idx := range indices {
		if err := bsl.SetStatus(idx, true); err != nil {
			t.Fatalf("SetStatus(%d): %v", idx, err)
		}
	}
	for _, idx := range indices {
		on, err := bsl.GetStatus(idx)
		if err != nil {
			t.Fatalf("GetStatus(%d): %v", idx, err)
		}
		if !on {
			t.Errorf("index %d should be set", idx)
		}
	}
	// Unset index should be false
	on, _ := bsl.GetStatus(50)
	if on {
		t.Error("index 50 should be unset")
	}
}

func TestBitstringClear(t *testing.T) {
	bsl := NewBitstringStatusList(PurposeSuspension, MinBitstringSize)
	bsl.SetStatus(42, true)
	on, _ := bsl.GetStatus(42)
	if !on {
		t.Fatal("42 should be set")
	}
	bsl.SetStatus(42, false)
	on, _ = bsl.GetStatus(42)
	if on {
		t.Error("42 should be cleared")
	}
}

func TestBitstringOutOfRange(t *testing.T) {
	bsl := NewBitstringStatusList(PurposeRevocation, MinBitstringSize)
	if err := bsl.SetStatus(-1, true); err == nil {
		t.Error("negative index should error")
	}
	if err := bsl.SetStatus(99999999, true); err == nil {
		t.Error("oversized index should error")
	}
	if _, err := bsl.GetStatus(-1); err == nil {
		t.Error("negative GetStatus should error")
	}
	if _, err := bsl.GetStatus(99999999); err == nil {
		t.Error("oversized GetStatus should error")
	}
}

func TestBitstringEncodeRoundTrip(t *testing.T) {
	bsl := NewBitstringStatusList(PurposeRevocation, MinBitstringSize)
	revoked := []int{3, 17, 256, 4095, 100000}
	for _, idx := range revoked {
		bsl.SetStatus(idx, true)
	}

	encoded, err := bsl.EncodedList()
	if err != nil {
		t.Fatal(err)
	}
	if encoded == "" {
		t.Fatal("encoded list empty")
	}

	// Decode and verify same bits
	decoded, err := DecodeBitstringStatusList(PurposeRevocation, encoded)
	if err != nil {
		t.Fatal(err)
	}
	for _, idx := range revoked {
		on, _ := decoded.GetStatus(idx)
		if !on {
			t.Errorf("decoded index %d should be revoked", idx)
		}
	}
	// Non-revoked stays false
	on, _ := decoded.GetStatus(5)
	if on {
		t.Error("index 5 should not be revoked after round-trip")
	}
}

func TestBitstringEncodeCompresses(t *testing.T) {
	// An all-zero 16KB bitstring should compress to a tiny encoded string
	bsl := NewBitstringStatusList(PurposeRevocation, MinBitstringSize)
	encoded, err := bsl.EncodedList()
	if err != nil {
		t.Fatal(err)
	}
	// 16KB of zeros gzips to well under 200 bytes
	if len(encoded) > 200 {
		t.Errorf("all-zero bitstring should compress small, got %d bytes", len(encoded))
	}
}

func TestDecodeBitstringEmpty(t *testing.T) {
	if _, err := DecodeBitstringStatusList(PurposeRevocation, ""); err == nil {
		t.Error("empty encoded list should error")
	}
}

func TestDecodeBitstringBadBase64(t *testing.T) {
	if _, err := DecodeBitstringStatusList(PurposeRevocation, "!!!not-base64!!!"); err == nil {
		t.Error("invalid base64 should error")
	}
}

func TestBitstringPurpose(t *testing.T) {
	bsl := NewBitstringStatusList(PurposeSuspension, MinBitstringSize)
	if bsl.Purpose() != PurposeSuspension {
		t.Errorf("purpose: %s", bsl.Purpose())
	}
}
