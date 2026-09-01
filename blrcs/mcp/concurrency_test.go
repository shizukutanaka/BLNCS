package mcp

import (
	"fmt"
	"sync"
	"testing"

	"blrcs/compliance"
)

// TestServerConcurrentUse establishes, rather than assumes, that a Server can be
// used from several goroutines at once. Axis 158 wanted to document the type as
// "safe for concurrent use" and could not: nothing in the tree exercised it.
// Softening the sentence was the honest short-term move; this test is the one
// that earns the claim back.
//
// It runs under `go test -race`, which `make verify` always sets, so an
// unsynchronised read or write of the Server's registries fails the gate rather
// than surfacing as a rare production heisenbug.
func TestServerConcurrentUse(t *testing.T) {
	srv, err := NewServer("did:web:ts.example", "did:web:server.example")
	if err != nil {
		t.Fatal(err)
	}

	const workers = 8
	var wg sync.WaitGroup

	// Writers: register issuers and attesters while everything else runs.
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				iss, err := compliance.NewIssuer(fmt.Sprintf("did:web:issuer-%d-%d.example", w, i))
				if err != nil {
					t.Errorf("NewIssuer: %v", err)
					return
				}
				srv.RegisterIssuer(iss)
			}
		}(w)
	}

	// Readers: capability snapshots take the read lock over the same state.
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				_ = srv.CapabilitiesSnapshot()
			}
		}()
	}

	// Dispatchers: full JSON-RPC requests, the path a real client drives.
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if got := srv.HandleRaw([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)); len(got) == 0 {
					t.Error("tools/list returned an empty response")
					return
				}
			}
		}()
	}

	wg.Wait()

	// The registrations must all have landed: a lost update would mean the
	// writers raced even if the detector saw no unsynchronised access.
	if snap := srv.CapabilitiesSnapshot(); len(snap.Available) == 0 {
		t.Fatal("capability snapshot is empty after concurrent registration")
	}
	srv.mu.RLock()
	n := len(srv.issuers)
	srv.mu.RUnlock()
	if want := workers * 20; n != want {
		t.Fatalf("registered issuers = %d, want %d (a registration was lost)", n, want)
	}
}
