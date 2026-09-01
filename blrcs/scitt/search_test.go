package scitt

import (
	"crypto/ed25519"
	"testing"

	"blrcs/storage"
)

// ============================================================================
// Axis 132: lifecycle search secondary index (EN 18222)
// ============================================================================

func TestFindBySubjectAndIssuer(t *testing.T) {
	ledger, _ := NewLedger("ts-search")
	priv, _ := mustIssuer(t, "acme")
	priv2, _ := mustIssuer(t, "globex")

	// acme issues two statements about product-1 and one about product-2;
	// globex issues one about product-1.
	mustRegister(t, ledger, priv, "did:web:acme", "product-1", "p-a1")
	mustRegister(t, ledger, priv, "did:web:acme", "product-1", "p-a2")
	mustRegister(t, ledger, priv, "did:web:acme", "product-2", "p-a3")
	mustRegister(t, ledger, priv2, "did:web:globex", "product-1", "p-g1")

	if got := ledger.FindBySubject("product-1"); len(got) != 3 {
		t.Errorf("product-1: want 3 statements, got %d", len(got))
	}
	if got := ledger.FindBySubject("product-2"); len(got) != 1 {
		t.Errorf("product-2: want 1, got %d", len(got))
	}
	if got := ledger.FindBySubject("nonexistent"); len(got) != 0 {
		t.Errorf("nonexistent subject: want 0, got %d", len(got))
	}
	acme := ledger.FindByIssuer("did:web:acme")
	if len(acme) != 3 {
		t.Errorf("did:web:acme: want 3, got %d", len(acme))
	}
	// Results carry the leaf index for get-by-index and preserve registration order.
	if len(acme) == 3 && (acme[0].Index != 0 || acme[1].Index != 1 || acme[2].Index != 2) {
		t.Errorf("issuer results should be in registration order: %+v", acme)
	}
	if got := ledger.FindByIssuer("did:web:globex"); len(got) != 1 || got[0].Subject != "product-1" {
		t.Errorf("globex results wrong: %+v", got)
	}
}

// TestSearchIndexRebuiltOnReplay proves the secondary indexes are rebuilt when a
// ledger is reconstructed from persistent storage (not just maintained live).
func TestSearchIndexRebuiltOnReplay(t *testing.T) {
	store := storage.NewMemoryStorage()
	ledger, err := NewLedgerWithStorage("ts-replay", store)
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := mustIssuer(t, "acme")
	mustRegister(t, ledger, priv, "did:web:acme", "battery-7", "b7")
	mustRegister(t, ledger, priv, "did:web:acme", "battery-7", "b7-update")

	// Reopen the ledger against the same storage — indexes must be rebuilt on replay.
	reopened, err := NewLedgerWithStorage("ts-replay", store)
	if err != nil {
		t.Fatal(err)
	}
	got := reopened.FindBySubject("battery-7")
	if len(got) != 2 {
		t.Fatalf("after replay, battery-7: want 2, got %d", len(got))
	}
	if got := reopened.FindByIssuer("did:web:acme"); len(got) != 2 {
		t.Errorf("after replay, did:web:acme: want 2, got %d", len(got))
	}
}

// mustRegister signs and registers a statement, failing the test on error.
func mustRegister(t *testing.T, ledger *Ledger, priv ed25519.PrivateKey, issuer, subject, payload string) {
	t.Helper()
	stmt, err := SignStatement(priv, issuer, subject, "application/vc+json", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Register(stmt); err != nil {
		t.Fatal(err)
	}
}
