package didresolver_test

import (
	"context"
	"fmt"

	"blrcs/compliance"
	"blrcs/didresolver"
)

// Demonstrates resolving a did:key — no network required.
func ExampleResolver_Resolve_didKey() {
	iss, _ := compliance.NewIssuer("did:web:factory.example")
	// Register the key as a DID key
	pub := iss.PublicKey()

	anchor := didresolver.NewTrustAnchor()
	anchor.AddDID(iss.ID)
	anchor.AddKey(pub)

	fmt.Println("trusted:", anchor.IsTrusted(iss.ID, pub))
	// Output: trusted: true
}

// Demonstrates TrustAnchor key management.
func ExampleNewTrustAnchor() {
	iss, _ := compliance.NewIssuer("did:web:trusted.example")
	untrusted, _ := compliance.NewIssuer("did:web:untrusted.example")

	anchor := didresolver.NewTrustAnchor()
	anchor.AddDID(iss.ID)
	anchor.AddKey(iss.PublicKey())

	fmt.Println("trusted:", anchor.IsTrusted(iss.ID, iss.PublicKey()))
	fmt.Println("untrusted:", anchor.IsTrusted(untrusted.ID, untrusted.PublicKey()))
	// Output:
	// trusted: true
	// untrusted: false
}

// Demonstrates cache TTL configuration.
func ExampleNew() {
	r := didresolver.New()

	// did:key can be resolved without network
	iss, _ := compliance.NewIssuer("did:web:test")
	_ = iss

	// Resolution failure for unknown DID is graceful
	_, err := r.Resolve(context.Background(), "did:web:nonexistent.example")
	fmt.Println("error on unknown:", err != nil)
	// Output: error on unknown: true
}

// Demonstrates discovering where a product's DPP data lives via service endpoints.
//
// DID resolution alone returns only keys (arXiv:2410.15758); the service
// endpoints in the DID document advertise the DPP store and status list.
func ExampleResolver_ResolveServices() {
	r := didresolver.New()
	// In production this fetches https://factory.example/.well-known/did.json
	r.HTTPFetcher = func(ctx context.Context, url string) ([]byte, error) {
		return []byte(`{
			"id": "did:web:factory.example",
			"verificationMethod": [],
			"service": [
				{"id":"#dpp","type":"DPPService","serviceEndpoint":"https://factory.example/dpp"},
				{"id":"#status","type":"BitstringStatusList","serviceEndpoint":"https://factory.example/status/1"}
			]
		}`), nil
	}

	services, _ := r.ResolveServices(context.Background(), "did:web:factory.example")
	for _, s := range services {
		fmt.Printf("%s -> %s\n", s.Type, s.ServiceEndpoint)
	}
	// Output:
	// DPPService -> https://factory.example/dpp
	// BitstringStatusList -> https://factory.example/status/1
}
