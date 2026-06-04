// Package compliance provides EU ESPR Digital Product Passport and Battery Passport
// credential issuance, verification, SD-JWT selective disclosure, ZK range proofs,
// and GS1 Digital Link URI handling.
//
// Core types: Issuer, Credential, PassportClaim, BatteryPassportClaim.
// Key operations: Issue, Verify, IssueSDJWT, VerifySDJWT, Present, Commit, Attest, VerifyRange.
//
// All cryptographic operations use Ed25519 (stdlib crypto/ed25519). Zero external dependencies.
package compliance
