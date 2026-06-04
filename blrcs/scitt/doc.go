// Package scitt implements IETF Supply Chain Integrity, Transparency, and Trust
// with a RFC 6962-compatible Merkle tree transparency log.
//
// Core types: Ledger, Statement, Receipt.
// Key operations: Register, Get, VerifyReceipt, VerifyInclusion.
//
// Ledger supports both in-memory and persistent (FileStorage) backends.
package scitt
