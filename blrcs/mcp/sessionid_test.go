package mcp

import (
	"errors"
	"strings"
	"testing"
)

func TestNewSessionIDShapeAndUniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		id, err := newSessionID()
		if err != nil {
			t.Fatal(err)
		}
		if len(id) != 32 || id == strings.Repeat("0", 32) {
			t.Fatalf("bad session id %q", id)
		}
		if seen[id] {
			t.Fatalf("duplicate session id %q", id)
		}
		seen[id] = true
	}
}

// An entropy failure must surface as an error, never as a usable all-zero ID
// that every client would then share.
func TestNewSessionIDFailsClosedOnEntropyError(t *testing.T) {
	orig := randRead
	randRead = func([]byte) (int, error) { return 0, errors.New("no entropy") }
	defer func() { randRead = orig }()
	id, err := newSessionID()
	if err == nil || id != "" {
		t.Fatalf("want error and empty id, got %q, %v", id, err)
	}
}
