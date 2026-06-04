package scitt_test

import (
	"fmt"

	"blrcs/compliance"
	"blrcs/scitt"
)

func Example_transparencyLog() {
	iss, _ := compliance.NewIssuer("did:web:factory.example")
	ledger, _ := scitt.NewLedger("did:web:ts.example")
	defer ledger.Close()
	payload := []byte(`{"productID":"P1"}`)
	stmt, _ := scitt.SignStatement(iss.PrivateKey(), iss.ID, "P1", "application/vc+json", payload)
	receipt, _ := ledger.Register(stmt)
	err := scitt.VerifyReceipt(receipt, stmt, ledger.PublicKey())
	fmt.Println("inclusion proven:", err == nil)
	// Output: inclusion proven: true
}

// Demonstrates an auditor proving the log is append-only (non-equivocation).
//
// SCITT's core guarantee: an issuer cannot rewrite history. An auditor who saw
// the tree at size m can later verify size n still contains the same prefix.
func Example_consistencyProof() {
	iss, _ := compliance.NewIssuer("did:web:factory.example")
	ledger, _ := scitt.NewLedger("did:web:ts.example")
	defer ledger.Close()

	// Auditor observes the log at size 3.
	for i := 0; i < 3; i++ {
		stmt, _ := scitt.SignStatement(iss.PrivateKey(), iss.ID, "item", "text/plain", []byte{byte(i)})
		ledger.Register(stmt)
	}
	oldRoot := ledger.Root()

	// Log grows to size 7.
	for i := 3; i < 7; i++ {
		stmt, _ := scitt.SignStatement(iss.PrivateKey(), iss.ID, "item", "text/plain", []byte{byte(i)})
		ledger.Register(stmt)
	}
	newRoot := ledger.Root()

	// Auditor proves the size-3 tree is a prefix of the size-7 tree.
	proof, _ := ledger.ConsistencyProof(3, 7)
	err := scitt.VerifyConsistency(3, 7, oldRoot, newRoot, proof)
	fmt.Println("append-only verified:", err == nil)
	// Output: append-only verified: true
}
