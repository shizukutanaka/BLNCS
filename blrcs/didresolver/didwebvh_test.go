package didresolver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"blrcs/didwebvh"
)

// ============================================================================
// Axis 126: did:webvh live HTTP resolution
// ============================================================================

// buildWebVHLog creates a genesis did:webvh log entry embedding a Ed25519
// verificationMethod (so parseDIDDocumentAll can extract a key) and returns
// the DID, the resolved public key, and the JSONL-encoded log body a mock
// HTTPFetcher would serve.
func buildWebVHLog(t *testing.T, didPath string) (did string, pub ed25519.PublicKey, jsonl []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, updatePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	genesis, did, err := didwebvh.Create(didwebvh.CreateParams{
		DIDPath:   didPath,
		UpdateKey: updatePriv,
		StateExtra: map[string]any{
			"verificationMethod": []map[string]any{
				{
					"id":   "#key-1",
					"type": "JsonWebKey2020",
					"publicKeyJwk": map[string]any{
						"kty": "OKP",
						"crv": "Ed25519",
						"x":   base64.RawURLEncoding.EncodeToString(pub),
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = priv // holder key unused; only its public form is embedded in the document
	line, err := json.Marshal(genesis)
	if err != nil {
		t.Fatal(err)
	}
	return did, pub, append(line, '\n')
}

func TestResolveDIDWebVH(t *testing.T) {
	did, pub, jsonl := buildWebVHLog(t, "example.com:dids:issuer")

	var fetchedURL string
	r := New()
	r.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) {
		fetchedURL = url
		return jsonl, nil
	}

	resolved, err := r.Resolve(context.Background(), did)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !equalKeys(resolved, pub) {
		t.Error("key mismatch")
	}
	wantURL := "https://example.com/dids/issuer/did.jsonl"
	if fetchedURL != wantURL {
		t.Errorf("URL: got %s want %s", fetchedURL, wantURL)
	}
}

func TestResolveDIDWebVHDefaultPath(t *testing.T) {
	did, _, jsonl := buildWebVHLog(t, "example.com")

	var fetchedURL string
	r := New()
	r.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) {
		fetchedURL = url
		return jsonl, nil
	}
	if _, err := r.Resolve(context.Background(), did); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := "https://example.com/.well-known/did.jsonl"
	if fetchedURL != want {
		t.Errorf("URL: got %s want %s", fetchedURL, want)
	}
}

func TestResolveDIDWebVHPortEncoding(t *testing.T) {
	did, _, jsonl := buildWebVHLog(t, "example.com%3A3000:dids:issuer")

	var fetchedURL string
	r := New()
	r.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) {
		fetchedURL = url
		return jsonl, nil
	}
	if _, err := r.Resolve(context.Background(), did); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := "https://example.com:3000/dids/issuer/did.jsonl"
	if fetchedURL != want {
		t.Errorf("URL: got %s want %s", fetchedURL, want)
	}
}

// TestResolveDIDWebVHTrailingNewlineTolerated proves the JSONL parser skips
// blank lines (e.g. a trailing newline after the last entry).
func TestResolveDIDWebVHTrailingNewlineTolerated(t *testing.T) {
	did, pub, jsonl := buildWebVHLog(t, "example.com:dids:issuer")
	jsonl = append(jsonl, '\n', '\n') // extra blank lines

	r := New()
	r.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) { return jsonl, nil }
	resolved, err := r.Resolve(context.Background(), did)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !equalKeys(resolved, pub) {
		t.Error("key mismatch")
	}
}

func TestResolveDIDWebVHFetchError(t *testing.T) {
	r := New()
	r.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) {
		return nil, errors.New("network down")
	}
	_, err := r.Resolve(context.Background(), "did:webvh:Qm123:example.com")
	if !errors.Is(err, ErrFetchFailed) {
		t.Fatalf("want ErrFetchFailed, got %v", err)
	}
}

func TestResolveDIDWebVHMalformedJSONL(t *testing.T) {
	r := New()
	r.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) {
		return []byte("not json\n"), nil
	}
	_, err := r.Resolve(context.Background(), "did:webvh:Qm123:example.com")
	if err == nil {
		t.Fatal("malformed did.jsonl should error")
	}
}

func TestResolveDIDWebVHEmptyLog(t *testing.T) {
	r := New()
	r.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) {
		return []byte("\n\n"), nil
	}
	_, err := r.Resolve(context.Background(), "did:webvh:Qm123:example.com")
	if !errors.Is(err, ErrMalformedDID) {
		t.Fatalf("empty log: want ErrMalformedDID, got %v", err)
	}
}

// TestResolveDIDWebVHTamperedEntryRejected proves a log that fails
// didwebvh.Verify (here: a tampered genesis entry breaking the SCID
// self-certification check) is rejected, not silently trusted.
func TestResolveDIDWebVHTamperedEntryRejected(t *testing.T) {
	did, _, jsonl := buildWebVHLog(t, "example.com:dids:issuer")
	// Corrupt the JSON to flip a state field without updating the hash chain.
	tampered := bytes.Replace(jsonl, []byte("\"id\""), []byte("\"idx\""), 1)

	r := New()
	r.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) { return tampered, nil }
	if _, err := r.Resolve(context.Background(), did); err == nil {
		t.Fatal("tampered log should fail didwebvh.Verify")
	}
}

// TestResolveDIDWebVHSCIDMismatchRejected proves that a server serving a
// perfectly valid, self-consistent log for a DIFFERENT SCID than the one
// requested is rejected — didwebvh.Verify alone only checks the log's
// internal self-consistency, not that it matches the DID actually asked for.
func TestResolveDIDWebVHSCIDMismatchRejected(t *testing.T) {
	realDID, _, _ := buildWebVHLog(t, "example.com:dids:real")
	_, _, otherJSONL := buildWebVHLog(t, "example.com:dids:real") // different SCID, same path shape

	r := New()
	r.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) { return otherJSONL, nil }
	if _, err := r.Resolve(context.Background(), realDID); !errors.Is(err, ErrMalformedDID) {
		t.Fatalf("scid mismatch: want ErrMalformedDID, got %v", err)
	}
}

func TestResolveDIDWebVHMissingSCID(t *testing.T) {
	r := New()
	if _, err := r.Resolve(context.Background(), "did:webvh::example.com"); !errors.Is(err, ErrMalformedDID) {
		t.Fatalf("empty scid segment: want ErrMalformedDID, got %v", err)
	}
	if _, err := r.Resolve(context.Background(), "did:webvh:Qm123"); !errors.Is(err, ErrMalformedDID) {
		t.Fatalf("no domain segment: want ErrMalformedDID, got %v", err)
	}
}

// ============================================================================
// ResolveServices for did:webvh
// ============================================================================

func TestResolveServicesDIDWebVH(t *testing.T) {
	_, updatePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	genesis, did, err := didwebvh.Create(didwebvh.CreateParams{
		DIDPath:   "example.com:dids:issuer",
		UpdateKey: updatePriv,
		StateExtra: map[string]any{
			"service": []map[string]any{
				{"id": "#dpp", "type": "DPPService", "serviceEndpoint": "https://example.com/dpp"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	line, err := json.Marshal(genesis)
	if err != nil {
		t.Fatal(err)
	}

	r := New()
	r.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) { return line, nil }
	services, err := r.ResolveServices(context.Background(), did)
	if err != nil {
		t.Fatalf("ResolveServices: %v", err)
	}
	if len(services) != 1 || services[0].ServiceEndpoint != "https://example.com/dpp" {
		t.Errorf("services: %+v", services)
	}
}

func TestResolveServicesDIDWebVHFetchError(t *testing.T) {
	r := New()
	r.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) {
		return nil, errors.New("network down")
	}
	_, err := r.ResolveServices(context.Background(), "did:webvh:Qm123:example.com")
	if !errors.Is(err, ErrFetchFailed) {
		t.Fatalf("want ErrFetchFailed, got %v", err)
	}
}
