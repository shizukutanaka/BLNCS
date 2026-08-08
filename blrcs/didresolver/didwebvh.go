package didresolver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"

	"blrcs/didwebvh"
)

// ============================================================================
// did:webvh resolution
//
// Verified against the canonical spec source
// (https://identity.foundation/didwebvh/v1.0/, mirrored at
// https://raw.githubusercontent.com/decentralized-identity/didwebvh/main/spec/specification.md)
// before implementing — same discipline used for witness.go and the Portable
// enforcement in didwebvh/resolve.go this session.
// ============================================================================

// didWebVHLogURL implements the spec's did:webvh-to-HTTPS transformation:
//
//	did:webvh:{SCID}:example.com:dids:issuer  -> https://example.com/dids/issuer/did.jsonl
//	did:webvh:{SCID}:example.com              -> https://example.com/.well-known/did.jsonl
//	did:webvh:{SCID}:example.com%3A3000:p     -> https://example.com:3000/p/did.jsonl
//
// The first colon-delimited segment after "did:webvh:" is the SCID; the rest
// is the domain (optionally with a %3A-encoded port) and path, with ':'
// separators becoming '/' in the URL.
func didWebVHLogURL(identifier string) (scid, url string, err error) {
	parts := strings.Split(identifier, ":")
	if len(parts) < 2 || parts[0] == "" {
		return "", "", fmt.Errorf("%w: did:webvh requires {scid}:{domain}", ErrMalformedDID)
	}
	scid = parts[0]
	domain := strings.ReplaceAll(parts[1], "%3A", ":")
	if domain == "" {
		return "", "", fmt.Errorf("%w: did:webvh empty domain segment", ErrMalformedDID)
	}
	if len(parts) == 2 {
		return scid, "https://" + domain + "/.well-known/did.jsonl", nil
	}
	pathParts := parts[2:]
	for _, p := range pathParts {
		if p == "" || p == "." || p == ".." {
			return "", "", fmt.Errorf("%w: invalid did:webvh path segment %q", ErrMalformedDID, p)
		}
	}
	return scid, "https://" + domain + "/" + strings.Join(pathParts, "/") + "/did.jsonl", nil
}

// parseDIDWebVHLog decodes a fetched did.jsonl body (text/jsonl: one LogEntry
// JSON object per line) into a log. Blank lines are skipped for tolerance of
// a trailing newline.
func parseDIDWebVHLog(body []byte) ([]didwebvh.LogEntry, error) {
	var log []didwebvh.LogEntry
	scanner := bufio.NewScanner(bytes.NewReader(body))
	// did.jsonl lines can be long once a log has many entries with proofs; the
	// default bufio.Scanner token limit (64KiB) is already generous relative to
	// the resolver's own 64KiB whole-response cap (see fetchWithClient), so no
	// larger buffer is needed.
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var entry didwebvh.LogEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			return nil, fmt.Errorf("didresolver: parse did.jsonl line: %w", err)
		}
		log = append(log, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("didresolver: read did.jsonl: %w", err)
	}
	if len(log) == 0 {
		return nil, fmt.Errorf("%w: did.jsonl has no entries", ErrMalformedDID)
	}
	return log, nil
}

// resolveDIDWebVHAll fetches and verifies a did:webvh log over HTTPS and
// returns every Ed25519 key in the resolved (latest) DID document.
//
// Verification: didwebvh.Verify checks the log's internal self-consistency
// (SCID self-certification, entry hash-chaining, update-key authorization,
// pre-rotation, Portable enforcement) but has no knowledge of which DID the
// caller asked to resolve — a malicious server could serve a perfectly valid
// log for a DIFFERENT SCID at the same URL. This function additionally
// confirms the verified log's SCID matches the SCID segment parsed from the
// did:webvh identifier itself, closing that gap. It deliberately does NOT
// enforce any witness requirement (matching plain didwebvh.Verify, not
// VerifyWithWitnesses) — a caller needing witness enforcement should fetch
// did-witness.json separately and call VerifyWithWitnesses directly.
func (r *Resolver) resolveDIDWebVHAll(ctx context.Context, identifier string) ([]ed25519.PublicKey, error) {
	docBody, err := r.didWebVHDocument(ctx, identifier)
	if err != nil {
		return nil, err
	}
	return parseDIDDocumentAll(docBody)
}

// didWebVHDocument performs the full did:webvh resolution (fetch the log, verify
// the hash chain, check the SCID matches the DID that was asked for) and returns
// the resolved DID document as JSON. Split out of resolveDIDWebVHAll so that
// both the Ed25519-typed and the algorithm-tagged key APIs share one
// implementation of the security-critical part.
func (r *Resolver) didWebVHDocument(ctx context.Context, identifier string) ([]byte, error) {
	scid, url, err := didWebVHLogURL(identifier)
	if err != nil {
		return nil, err
	}
	body, err := r.HTTPFetcher(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFetchFailed, err)
	}
	log, err := parseDIDWebVHLog(body)
	if err != nil {
		return nil, err
	}
	res, err := didwebvh.Verify(log)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFetchFailed, err)
	}
	if res.SCID != scid {
		return nil, fmt.Errorf("%w: did.jsonl at %s resolves to scid %q, requested %q", ErrMalformedDID, url, res.SCID, scid)
	}
	docBody, err := json.Marshal(res.Document)
	if err != nil {
		return nil, fmt.Errorf("didresolver: re-encode did:webvh document: %w", err)
	}
	return docBody, nil
}

// resolveDIDWebVHServices fetches and verifies a did:webvh log and returns
// the service endpoints declared in the resolved DID document, mirroring
// ResolveServices' did:web behavior.
func (r *Resolver) resolveDIDWebVHServices(ctx context.Context, identifier string) ([]Service, error) {
	scid, url, err := didWebVHLogURL(identifier)
	if err != nil {
		return nil, err
	}
	body, err := r.HTTPFetcher(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFetchFailed, err)
	}
	log, err := parseDIDWebVHLog(body)
	if err != nil {
		return nil, err
	}
	res, err := didwebvh.Verify(log)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFetchFailed, err)
	}
	if res.SCID != scid {
		return nil, fmt.Errorf("%w: did.jsonl at %s resolves to scid %q, requested %q", ErrMalformedDID, url, res.SCID, scid)
	}
	docBody, err := json.Marshal(res.Document)
	if err != nil {
		return nil, fmt.Errorf("didresolver: re-encode did:webvh document: %w", err)
	}
	var doc didDocument
	if err := json.Unmarshal(docBody, &doc); err != nil {
		return nil, fmt.Errorf("didresolver: parse did:webvh document: %w", err)
	}
	out := make([]Service, 0, len(doc.Service))
	for _, s := range doc.Service {
		out = append(out, Service(s))
	}
	return out, nil
}
