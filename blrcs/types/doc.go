// Package types provides strongly-typed domain primitives for BLRCS.
//
// All types enforce invariants at construction time — invalid states cannot be represented.
// Types: DID, GTIN (14-digit normalized), CountryCode (ISO 3166-1), CarbonFootprint
// (non-negative kg CO2e), Percent (0..100), Duration (non-negative).
//
// Each type supports JSON marshal/unmarshal with re-validation on decode.
package types
