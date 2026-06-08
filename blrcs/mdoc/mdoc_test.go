package mdoc

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func testKeys(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func sampleParams(issuerPriv ed25519.PrivateKey, deviceKey ed25519.PublicKey) IssueParams {
	now := time.Now().UTC()
	return IssueParams{
		DocType: "org.iso.18013.5.1.mDL",
		NameSpaces: map[string][]Element{
			"org.iso.18013.5.1": {
				{Identifier: "family_name", Value: "Tanaka"},
				{Identifier: "given_name", Value: "Shizuku"},
				{Identifier: "age_over_18", Value: true},
				{Identifier: "birth_year", Value: uint64(1990)},
			},
		},
		Validity: ValidityInfo{
			Signed:     now,
			ValidFrom:  now.Add(-time.Hour),
			ValidUntil: now.Add(365 * 24 * time.Hour),
		},
		DeviceKey:  deviceKey,
		IssuerPriv: issuerPriv,
	}
}

func TestIssueVerifyRoundtrip(t *testing.T) {
	issuerPriv, issuerPub := testKeys(t)
	_, devicePub := testKeys(t)

	cred, err := Issue(sampleParams(issuerPriv, devicePub))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(cred) == 0 {
		t.Fatal("empty credential")
	}

	doc, err := Verify(cred, issuerPub, time.Now())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if doc.DocType != "org.iso.18013.5.1.mDL" {
		t.Errorf("docType: %q", doc.DocType)
	}
	ns := doc.NameSpaces["org.iso.18013.5.1"]
	if ns["family_name"] != "Tanaka" {
		t.Errorf("family_name: %v", ns["family_name"])
	}
	if ns["age_over_18"] != true {
		t.Errorf("age_over_18: %v", ns["age_over_18"])
	}
	if by, _ := ns["birth_year"].(uint64); by != 1990 {
		t.Errorf("birth_year: %v", ns["birth_year"])
	}
	if doc.DeviceKey == nil || !doc.DeviceKey.Equal(devicePub) {
		t.Errorf("device key not recovered correctly")
	}
}

func TestVerifyWrongIssuerKey(t *testing.T) {
	issuerPriv, _ := testKeys(t)
	_, wrongPub := testKeys(t)

	cred, _ := Issue(sampleParams(issuerPriv, nil))
	if _, err := Verify(cred, wrongPub, time.Now()); err == nil {
		t.Error("verification with wrong issuer key should fail")
	}
}

func TestVerifyTampered(t *testing.T) {
	issuerPriv, issuerPub := testKeys(t)
	cred, _ := Issue(sampleParams(issuerPriv, nil))

	// Flip a byte somewhere in the body (likely a namespace element)
	tampered := make([]byte, len(cred))
	copy(tampered, cred)
	tampered[20] ^= 0xff

	if _, err := Verify(tampered, issuerPub, time.Now()); err == nil {
		t.Error("tampered credential should fail")
	}
}

func TestVerifyExpired(t *testing.T) {
	issuerPriv, issuerPub := testKeys(t)
	p := sampleParams(issuerPriv, nil)
	now := time.Now().UTC()
	p.Validity = ValidityInfo{
		Signed:     now.Add(-48 * time.Hour),
		ValidFrom:  now.Add(-48 * time.Hour),
		ValidUntil: now.Add(-24 * time.Hour), // expired yesterday
	}
	cred, _ := Issue(p)

	if _, err := Verify(cred, issuerPub, now); err != ErrExpired {
		t.Errorf("want ErrExpired, got %v", err)
	}
}

func TestVerifyNotYetValid(t *testing.T) {
	issuerPriv, issuerPub := testKeys(t)
	p := sampleParams(issuerPriv, nil)
	now := time.Now().UTC()
	p.Validity = ValidityInfo{
		Signed:     now,
		ValidFrom:  now.Add(24 * time.Hour), // valid tomorrow
		ValidUntil: now.Add(48 * time.Hour),
	}
	cred, _ := Issue(p)

	if _, err := Verify(cred, issuerPub, now); err != ErrNotYetValid {
		t.Errorf("want ErrNotYetValid, got %v", err)
	}
}

func TestIssueNoElements(t *testing.T) {
	issuerPriv, _ := testKeys(t)
	p := sampleParams(issuerPriv, nil)
	p.NameSpaces = map[string][]Element{}
	if _, err := Issue(p); err != ErrNoElements {
		t.Errorf("want ErrNoElements, got %v", err)
	}
}

func TestIssueNoDeviceKey(t *testing.T) {
	issuerPriv, issuerPub := testKeys(t)
	cred, err := Issue(sampleParams(issuerPriv, nil))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Verify(cred, issuerPub, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if doc.DeviceKey != nil {
		t.Error("expected nil device key")
	}
}

// ============================================================================
// Selective disclosure
// ============================================================================

func TestSelectiveDisclosure(t *testing.T) {
	issuerPriv, issuerPub := testKeys(t)
	cred, _ := Issue(sampleParams(issuerPriv, nil))

	// Holder reveals only family_name + age_over_18
	presented, err := Present(cred, map[string][]string{
		"org.iso.18013.5.1": {"family_name", "age_over_18"},
	})
	if err != nil {
		t.Fatalf("Present: %v", err)
	}

	doc, err := Verify(presented, issuerPub, time.Now())
	if err != nil {
		t.Fatalf("Verify presented: %v", err)
	}
	ns := doc.NameSpaces["org.iso.18013.5.1"]
	if len(ns) != 2 {
		t.Errorf("expected 2 disclosed elements, got %d: %v", len(ns), ns)
	}
	if ns["family_name"] != "Tanaka" {
		t.Errorf("family_name missing: %v", ns)
	}
	if _, ok := ns["given_name"]; ok {
		t.Error("given_name should not be disclosed")
	}
	if _, ok := ns["birth_year"]; ok {
		t.Error("birth_year should not be disclosed")
	}
}

func TestSelectiveDisclosureDropsNamespace(t *testing.T) {
	issuerPriv, issuerPub := testKeys(t)
	cred, _ := Issue(sampleParams(issuerPriv, nil))

	// Reveal nothing → empty nameSpaces, but issuerAuth still verifies
	presented, err := Present(cred, map[string][]string{})
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	doc, err := Verify(presented, issuerPub, time.Now())
	if err != nil {
		t.Fatalf("Verify empty disclosure: %v", err)
	}
	if len(doc.NameSpaces) != 0 {
		t.Errorf("expected no namespaces, got %v", doc.NameSpaces)
	}
	// docType + validity still attested
	if doc.DocType != "org.iso.18013.5.1.mDL" {
		t.Errorf("docType lost: %q", doc.DocType)
	}
}

func TestPresentedStillDigestChecked(t *testing.T) {
	// After selective disclosure, a tampered disclosed value must still be caught.
	issuerPriv, issuerPub := testKeys(t)
	cred, _ := Issue(sampleParams(issuerPriv, nil))

	presented, _ := Present(cred, map[string][]string{
		"org.iso.18013.5.1": {"family_name"},
	})

	// Corrupt the presented bytes
	tampered := make([]byte, len(presented))
	copy(tampered, presented)
	// flip a byte near the start (in the namespace item region)
	tampered[10] ^= 0x01

	if _, err := Verify(tampered, issuerPub, time.Now()); err == nil {
		t.Error("tampered presented credential should fail")
	}
}

// ============================================================================
// Multi-namespace
// ============================================================================

func TestMultiNamespace(t *testing.T) {
	issuerPriv, issuerPub := testKeys(t)
	now := time.Now().UTC()
	cred, err := Issue(IssueParams{
		DocType: "eu.europa.ec.dpp.1",
		NameSpaces: map[string][]Element{
			"eu.europa.ec.dpp.1": {
				{Identifier: "product_id", Value: "04012345678901"},
				{Identifier: "carbon_kg", Value: uint64(48)},
			},
			"eu.europa.ec.battery.1": {
				{Identifier: "recyclability_pct", Value: uint64(82)},
			},
		},
		Validity:   ValidityInfo{Signed: now, ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour)},
		IssuerPriv: issuerPriv,
	})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Verify(cred, issuerPub, now)
	if err != nil {
		t.Fatal(err)
	}
	if doc.NameSpaces["eu.europa.ec.dpp.1"]["product_id"] != "04012345678901" {
		t.Errorf("product_id: %v", doc.NameSpaces["eu.europa.ec.dpp.1"])
	}
	if doc.NameSpaces["eu.europa.ec.battery.1"]["recyclability_pct"].(uint64) != 82 {
		t.Errorf("recyclability: %v", doc.NameSpaces["eu.europa.ec.battery.1"])
	}
}
