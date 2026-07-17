package revocation_test

import (
	"fmt"

	"blrcs/revocation"
)

// Demonstrates the W3C Bitstring Status List v1.0 revocation flow.
func Example_bitstringStatusList() {
	// Issuer maintains a status list; each credential maps to a bit index.
	list := revocation.NewBitstringStatusList(revocation.PurposeRevocation, revocation.MinBitstringSize)

	// Credential at index 42 gets revoked.
	list.SetStatus(42, true)

	// Publish: GZIP + base64url-encoded bitstring (what verifiers fetch).
	encoded, _ := list.EncodedList()
	fmt.Println("encoded list non-empty:", encoded != "")

	// A verifier fetches and decodes the list, then checks a credential's bit.
	verifierView, _ := revocation.DecodeBitstringStatusList(revocation.PurposeRevocation, encoded)

	revoked, _ := verifierView.GetStatus(42)
	active, _ := verifierView.GetStatus(43)
	fmt.Println("index 42 revoked:", revoked)
	fmt.Println("index 43 revoked:", active)
	// Output:
	// encoded list non-empty: true
	// index 42 revoked: true
	// index 43 revoked: false
}
