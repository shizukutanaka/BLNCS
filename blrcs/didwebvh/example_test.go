package didwebvh_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"time"

	"blrcs/didwebvh"
	"blrcs/multiformats"
)

// Example demonstrates the did:webvh lifecycle: create a self-certifying DID,
// rotate to a pre-committed key, then verify the full verifiable history.
func Example() {
	// Genesis update key, and a pre-rotation key committed up front.
	_, genesisKey, _ := ed25519.GenerateKey(rand.Reader)
	rotPub, rotKey, _ := ed25519.GenerateKey(rand.Reader)
	rotMultikey := multiformats.EncodeEd25519Multikey(rotPub)

	now := time.Now().UTC()

	genesis, did, err := didwebvh.Create(didwebvh.CreateParams{
		DIDPath:       "example.com:dids:org-1",
		UpdateKey:     genesisKey,
		NextKeyHashes: []string{didwebvh.KeyHash(rotMultikey)},
		VersionTime:   now,
	})
	if err != nil {
		panic(err)
	}
	log := []didwebvh.LogEntry{*genesis}

	// Rotate authority to the pre-committed key.
	upd, err := didwebvh.Update(didwebvh.UpdateParams{
		Log:         log,
		SignKey:     genesisKey, // genesis key authorizes this entry
		NewState:    map[string]any{"id": did, "service": []any{"https://example.com/dpp"}},
		UpdateKeys:  []string{rotMultikey},
		VersionTime: now.Add(time.Hour),
	})
	if err != nil {
		panic(err)
	}
	log = append(log, *upd)
	_ = rotKey

	res, err := didwebvh.Verify(log)
	if err != nil {
		panic(err)
	}
	fmt.Printf("entries=%d version=%s deactivated=%v scid_in_did=%v\n",
		len(log), res.VersionID[:1], res.Deactivated,
		res.SCID != "" && contains(res.DID, res.SCID))
	// Output: entries=2 version=2 deactivated=false scid_in_did=true
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
