package mdoc_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"time"

	"blrcs/mdoc"
)

// Example shows the full mdoc lifecycle: an issuer issues a credential, a holder
// selectively discloses a subset, and a verifier validates the disclosure.
func Example() {
	// Issuer and holder keys.
	issuerPub, issuerPriv, _ := ed25519.GenerateKey(rand.Reader)
	devicePub, _, _ := ed25519.GenerateKey(rand.Reader)

	now := time.Now().UTC()

	// 1. Issuer issues a mobile driving licence with four data elements.
	cred, err := mdoc.Issue(mdoc.IssueParams{
		DocType: "org.iso.18013.5.1.mDL",
		NameSpaces: map[string][]mdoc.Element{
			"org.iso.18013.5.1": {
				{Identifier: "family_name", Value: "Tanaka"},
				{Identifier: "given_name", Value: "Shizuku"},
				{Identifier: "age_over_18", Value: true},
				{Identifier: "birth_date", Value: "1990-04-01"},
			},
		},
		Validity: mdoc.ValidityInfo{
			Signed:     now,
			ValidFrom:  now,
			ValidUntil: now.Add(365 * 24 * time.Hour),
		},
		DeviceKey:  devicePub,
		IssuerPriv: issuerPriv,
	})
	if err != nil {
		panic(err)
	}

	// 2. Holder discloses only age_over_18 to a bar.
	presented, err := mdoc.Present(cred, map[string][]string{
		"org.iso.18013.5.1": {"age_over_18"},
	})
	if err != nil {
		panic(err)
	}

	// 3. Verifier validates issuer signature, digests, and validity window.
	doc, err := mdoc.Verify(presented, issuerPub, now)
	if err != nil {
		panic(err)
	}

	ns := doc.NameSpaces["org.iso.18013.5.1"]
	fmt.Printf("docType=%s disclosed=%d age_over_18=%v\n", doc.DocType, len(ns), ns["age_over_18"])
	// Output: docType=org.iso.18013.5.1.mDL disclosed=1 age_over_18=true
}
