// Package errkit provides structured errors with operation chains, classification codes,
// public/detail message separation, retryable flag, and HTTP status mapping.
//
// Compatible with errors.Is and errors.As for type-safe error handling.
// Sentinel constructors: NotFound, Unauthorized, Forbidden, InvalidInput, etc.
package errkit
