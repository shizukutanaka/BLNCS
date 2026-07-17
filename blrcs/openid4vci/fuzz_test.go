package openid4vci

import "testing"

// FuzzVerifyProofJWT fuzzes the OpenID4VCI proof-of-possession parser, which
// consumes the attacker-suppliable proof JWT (header/jwk/payload/signature). It is
// white-box (same package) so it can target verifyProofJWT directly. 絶対条件: any
// input must fail safe — return an error, never panic.
func FuzzVerifyProofJWT(f *testing.F) {
	f.Add("")
	f.Add("a.b.c")
	f.Add("...")
	f.Add("e30.e30.")               // base64url("{}").base64url("{}").empty
	f.Add("not-base64.@@@.$$$")     // invalid base64 segments
	f.Add(string(make([]byte, 64))) // raw zero bytes

	f.Fuzz(func(t *testing.T, proofJWT string) {
		_, _ = verifyProofJWT(proofJWT, "nonce", "https://issuer.example")
	})
}
