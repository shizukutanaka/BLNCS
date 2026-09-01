package bundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"blrcs/compliance"
	"blrcs/didwebvh"
	"blrcs/revocation"
	"blrcs/scitt"
)

// ============================================================================
// Axis 134: long-term, offline-verifiable DPP bundle
// ============================================================================

const statusListURL = "https://issuer.example/status/1"

func issueCredential(t *testing.T, iss *compliance.Issuer, statusIdx int) string {
	t.Helper()
	sdjwt, _, err := iss.IssueSDJWTStatus(
		"battery-001",
		map[string]any{"carbonKgCO2ePerKWh": 42.0},
		map[string]any{"batteryCategory": "ev"},
		&compliance.StatusRef{URI: statusListURL, Index: statusIdx},
		365*24*time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	return sdjwt
}

// statusSnapshot signs a status-list token; revokedIdx >= 0 flips that bit.
func statusSnapshot(t *testing.T, revokedIdx int) (string, ed25519.PublicKey) {
	t.Helper()
	list := revocation.NewBitstringStatusList(revocation.PurposeRevocation, 128)
	if revokedIdx >= 0 {
		if err := list.SetStatus(revokedIdx, true); err != nil {
			t.Fatal(err)
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	token, err := list.IssueToken("did:web:issuer.example", statusListURL, priv, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return token, pub
}

// timestampAuthority spins up a SCITT ledger acting as the TSA, plus a
// submitter key.
func timestampAuthority(t *testing.T) (*scitt.Ledger, ed25519.PrivateKey) {
	t.Helper()
	ledger, err := scitt.NewLedger("did:web:ts.example")
	if err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return ledger, priv
}

// webvhLogFor builds a did:webvh log whose update key is a compliance Issuer's
// key, so the log genuinely authorizes that issuer.
func webvhLogFor(t *testing.T) ([]didwebvh.LogEntry, *compliance.Issuer) {
	t.Helper()
	iss, err := compliance.NewIssuer("did:web:factory.example")
	if err != nil {
		t.Fatal(err)
	}
	genesis, _, err := didwebvh.Create(didwebvh.CreateParams{
		DIDPath:   "example.com:dids:factory",
		UpdateKey: iss.PrivateKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return []didwebvh.LogEntry{*genesis}, iss
}

func TestBundleRoundTripAndVerify(t *testing.T) {
	iss, err := compliance.NewIssuer("did:web:factory.example")
	if err != nil {
		t.Fatal(err)
	}
	token, statusKey := statusSnapshot(t, -1)
	b, err := Build(issueCredential(t, iss, 7), iss.PublicKey(),
		BuildOptions{StatusToken: token, StatusKey: statusKey})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(raw) // must survive serialization — that's the point
	if err != nil {
		t.Fatal(err)
	}
	res, err := Verify(parsed, Options{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.CheckedRevocation || res.Revoked {
		t.Errorf("expected a completed, negative revocation check: %+v", res)
	}
	if res.Claims == nil || res.Claims.Subject != "battery-001" {
		t.Errorf("claims not recovered: %+v", res.Claims)
	}
}

// TestVerifyMakesNoNetworkCalls is the load-bearing test: a fully-evidenced
// bundle must verify with the network hard-disabled.
func TestVerifyMakesNoNetworkCalls(t *testing.T) {
	log, iss := webvhLogFor(t)
	token, statusKey := statusSnapshot(t, -1)
	ledger, submitter := timestampAuthority(t)

	b, err := Build(issueCredential(t, iss, 7), iss.PublicKey(), BuildOptions{
		IssuerDIDLog: log, StatusToken: token, StatusKey: statusKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Anchor(ledger, submitter, "did:web:factory.example"); err != nil {
		t.Fatal(err)
	}

	restore := failOnDial(t) // any outbound dial now fails the test
	defer restore()

	res, err := Verify(b, Options{
		RequireProvenance: true, RequireRevocationCheck: true, RequireTimestamp: true,
	})
	if err != nil {
		t.Fatalf("offline verify failed: %v", err)
	}
	if !res.CheckedProvenance || !res.CheckedRevocation || !res.CheckedTimestamp {
		t.Errorf("all three LTV components should have been checked: %+v", res)
	}
}

// TestAnchorProvidesLTVTimestamp proves the anchor supplies the ETSI LTV
// component the naive design lacked: a trusted time at which the credential
// provably already existed.
func TestAnchorProvidesLTVTimestamp(t *testing.T) {
	iss, _ := compliance.NewIssuer("did:web:factory.example")
	ledger, submitter := timestampAuthority(t)
	b, _ := Build(issueCredential(t, iss, 7), iss.PublicKey(), BuildOptions{})

	before := time.Now().UTC().Add(-time.Second)
	if err := b.Anchor(ledger, submitter, "did:web:factory.example"); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(b, Options{RequireTimestamp: true})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.AnchorCount != 1 {
		t.Fatalf("want 1 anchor, got %d", res.AnchorCount)
	}
	if res.AnchorTimes[0].Before(before) {
		t.Errorf("anchor time %v predates the anchoring call", res.AnchorTimes[0])
	}
}

// TestRenewChainsEvidence is the RFC 4998 property: a renewal anchor is taken
// over the evidence INCLUDING the previous anchors, so the new timestamp
// carries the old ones forward.
func TestRenewChainsEvidence(t *testing.T) {
	iss, _ := compliance.NewIssuer("did:web:factory.example")
	ledger, submitter := timestampAuthority(t)
	b, _ := Build(issueCredential(t, iss, 7), iss.PublicKey(), BuildOptions{})

	if err := b.Anchor(ledger, submitter, "did:web:factory.example"); err != nil {
		t.Fatal(err)
	}
	first := b.Anchors[0].EvidenceDigest
	if err := b.Renew(ledger, submitter, "did:web:factory.example"); err != nil {
		t.Fatal(err)
	}
	if len(b.Anchors) != 2 {
		t.Fatalf("want 2 anchors after renewal, got %d", len(b.Anchors))
	}
	// The renewal must attest DIFFERENT evidence — namely evidence that now
	// includes anchor 0. Equal digests would mean the renewal ignored the prior
	// anchor and proves nothing about it.
	if b.Anchors[1].EvidenceDigest == first {
		t.Error("renewal digest equals the original: the chain does not carry prior evidence forward")
	}
	res, err := Verify(b, Options{RequireTimestamp: true})
	if err != nil {
		t.Fatalf("verify renewed chain: %v", err)
	}
	if res.AnchorCount != 2 {
		t.Errorf("want 2 verified anchors, got %d", res.AnchorCount)
	}
	if res.AnchorTimes[1].Before(res.AnchorTimes[0]) {
		t.Error("anchor times should be non-decreasing")
	}
}

// TestTamperAfterAnchorDetected proves the anchor actually binds the evidence:
// mutating the bundle after anchoring breaks the chain.
func TestTamperAfterAnchorDetected(t *testing.T) {
	log, iss := webvhLogFor(t)
	ledger, submitter := timestampAuthority(t)
	b, _ := Build(issueCredential(t, iss, 7), iss.PublicKey(), BuildOptions{IssuerDIDLog: log})
	if err := b.Anchor(ledger, submitter, "did:web:factory.example"); err != nil {
		t.Fatal(err)
	}
	// Strip the provenance log after the fact.
	b.IssuerDIDLog = nil
	if _, err := Verify(b, Options{}); !errors.Is(err, ErrAnchorChainBroken) {
		t.Fatalf("post-anchor tampering should break the chain, got %v", err)
	}
}

// TestReorderedAnchorsRejected proves the chain is ordered: swapping anchors
// breaks the prefix relationship each one attests.
func TestReorderedAnchorsRejected(t *testing.T) {
	iss, _ := compliance.NewIssuer("did:web:factory.example")
	ledger, submitter := timestampAuthority(t)
	b, _ := Build(issueCredential(t, iss, 7), iss.PublicKey(), BuildOptions{})
	if err := b.Anchor(ledger, submitter, "did:web:x"); err != nil {
		t.Fatal(err)
	}
	if err := b.Renew(ledger, submitter, "did:web:x"); err != nil {
		t.Fatal(err)
	}
	b.Anchors[0], b.Anchors[1] = b.Anchors[1], b.Anchors[0]
	if _, err := Verify(b, Options{}); !errors.Is(err, ErrAnchorChainBroken) {
		t.Fatalf("reordered anchors should be rejected, got %v", err)
	}
}

// TestForeignAnchorRejected proves an anchor from an unrelated bundle cannot be
// stapled on to fake long-term evidence.
func TestForeignAnchorRejected(t *testing.T) {
	ledger, submitter := timestampAuthority(t)
	issA, _ := compliance.NewIssuer("did:web:a.example")
	issB, _ := compliance.NewIssuer("did:web:b.example")

	other, _ := Build(issueCredential(t, issB, 3), issB.PublicKey(), BuildOptions{})
	if err := other.Anchor(ledger, submitter, "did:web:b.example"); err != nil {
		t.Fatal(err)
	}
	mine, _ := Build(issueCredential(t, issA, 7), issA.PublicKey(), BuildOptions{})
	mine.Anchors = other.Anchors // steal a genuine, ledger-signed anchor

	if _, err := Verify(mine, Options{}); !errors.Is(err, ErrAnchorChainBroken) {
		t.Fatalf("foreign anchor should be rejected, got %v", err)
	}
}

func TestVerifyDetectsRevoked(t *testing.T) {
	iss, _ := compliance.NewIssuer("did:web:factory.example")
	token, statusKey := statusSnapshot(t, 7)
	b, _ := Build(issueCredential(t, iss, 7), iss.PublicKey(),
		BuildOptions{StatusToken: token, StatusKey: statusKey})
	res, err := Verify(b, Options{})
	if !errors.Is(err, ErrRevoked) {
		t.Fatalf("want ErrRevoked, got %v", err)
	}
	if res == nil || !res.Revoked {
		t.Errorf("result should record the revocation: %+v", res)
	}
}

// TestMissingEvidenceFailsClosed proves silence is never read as success.
func TestMissingEvidenceFailsClosed(t *testing.T) {
	iss, _ := compliance.NewIssuer("did:web:factory.example")
	b, _ := Build(issueCredential(t, iss, 7), iss.PublicKey(), BuildOptions{})

	for name, opts := range map[string]Options{
		"revocation": {RequireRevocationCheck: true},
		"provenance": {RequireProvenance: true},
		"timestamp":  {RequireTimestamp: true},
	} {
		if _, err := Verify(b, opts); !errors.Is(err, ErrCheckUnavailable) {
			t.Errorf("required %s with no evidence: want ErrCheckUnavailable, got %v", name, err)
		}
	}
	res, err := Verify(b, Options{})
	if err != nil {
		t.Fatalf("permissive verify: %v", err)
	}
	if res.CheckedRevocation || res.CheckedProvenance || res.CheckedTimestamp {
		t.Errorf("nothing should be reported as checked: %+v", res)
	}
}

func TestStaleStatusSnapshotRejected(t *testing.T) {
	iss, _ := compliance.NewIssuer("did:web:factory.example")
	token, statusKey := statusSnapshot(t, -1)
	b, _ := Build(issueCredential(t, iss, 7), iss.PublicKey(),
		BuildOptions{StatusToken: token, StatusKey: statusKey})
	res, err := Verify(b, Options{Now: time.Now().Add(time.Hour), MaxStatusAge: time.Minute})
	if !errors.Is(err, ErrStatusStale) {
		t.Fatalf("want ErrStatusStale, got %v", err)
	}
	if res == nil || !res.StatusStale {
		t.Errorf("result should flag staleness: %+v", res)
	}
}

func TestTamperedCredentialRejected(t *testing.T) {
	iss, _ := compliance.NewIssuer("did:web:factory.example")
	b, _ := Build(issueCredential(t, iss, 7), iss.PublicKey(), BuildOptions{})
	b.Credential = strings.Replace(b.Credential, "a", "b", 1)
	if _, err := Verify(b, Options{}); err == nil {
		t.Fatal("tampered credential must not verify")
	}
}

func TestWrongIssuerKeyRejected(t *testing.T) {
	iss, _ := compliance.NewIssuer("did:web:factory.example")
	other, _ := compliance.NewIssuer("did:web:evil.example")
	b, _ := Build(issueCredential(t, iss, 7), other.PublicKey(), BuildOptions{})
	if _, err := Verify(b, Options{}); err == nil {
		t.Fatal("credential verified under the wrong issuer key")
	}
}

// TestStapledForeignDIDLogRejected proves the provenance check is real.
func TestStapledForeignDIDLogRejected(t *testing.T) {
	foreignLog, _ := webvhLogFor(t)
	iss, _ := compliance.NewIssuer("did:web:factory.example")
	b, _ := Build(issueCredential(t, iss, 7), iss.PublicKey(), BuildOptions{IssuerDIDLog: foreignLog})
	if _, err := Verify(b, Options{}); !errors.Is(err, ErrIssuerKeyNotInLog) {
		t.Fatalf("want ErrIssuerKeyNotInLog, got %v", err)
	}
}

func TestProvenanceCheckedWhenKeyMatchesLog(t *testing.T) {
	log, iss := webvhLogFor(t)
	b, _ := Build(issueCredential(t, iss, 7), iss.PublicKey(), BuildOptions{IssuerDIDLog: log})
	res, err := Verify(b, Options{RequireProvenance: true})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.CheckedProvenance || res.IssuerDID == "" {
		t.Errorf("provenance should be established: %+v", res)
	}
}

func TestRenewRequiresExistingAnchor(t *testing.T) {
	iss, _ := compliance.NewIssuer("did:web:factory.example")
	ledger, submitter := timestampAuthority(t)
	b, _ := Build(issueCredential(t, iss, 7), iss.PublicKey(), BuildOptions{})
	if err := b.Renew(ledger, submitter, "did:web:x"); !errors.Is(err, ErrMalformed) {
		t.Fatalf("renewing an un-anchored bundle should fail, got %v", err)
	}
}

func TestParseRejectsBadVersionAndShape(t *testing.T) {
	for _, in := range []string{`{"version":"nope"}`, `{"version":"` + Version + `"}`, "not json"} {
		if _, err := Parse([]byte(in)); !errors.Is(err, ErrMalformed) {
			t.Errorf("input %q should be rejected, got %v", in, err)
		}
	}
}

func TestBuildValidation(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Build("", pub, BuildOptions{}); !errors.Is(err, ErrMalformed) {
		t.Error("empty credential should be rejected")
	}
	if _, err := Build("x", []byte("short"), BuildOptions{}); !errors.Is(err, ErrMalformed) {
		t.Error("short issuer key should be rejected")
	}
}
