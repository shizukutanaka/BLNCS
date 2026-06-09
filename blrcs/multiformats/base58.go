// Package multiformats — zero-dependency base58btc, multihash, and JCS
// (RFC 8785) primitives.
//
// These are the interop building blocks required by did:webvh
// (base58btc(multihash(sha-256(JCS(entry))))) and Data Integrity proofs, kept
// in one small package so higher layers (a future didwebvh resolver) can depend
// on validated primitives rather than re-deriving them.
package multiformats

import "errors"

// base58btcAlphabet is the Bitcoin/IPFS base58 alphabet.
const base58btcAlphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// maxBase58Input bounds decode input length. Base58 decode is O(n²); legitimate
// inputs (32-byte keys → ~44 chars, 34-byte multihash → ~46 chars, 64-byte sigs
// → ~88 chars) are tiny, so an 8 KiB cap rejects adversarial oversized strings
// well before the quadratic cost matters.
const maxBase58Input = 8192

// base58Inverse maps each ASCII byte to its base58 digit value, or -1. Built
// once at init so decoding does not linear-scan the alphabet per character.
var base58Inverse = func() [256]int8 {
	var t [256]int8
	for i := range t {
		t[i] = -1
	}
	for i := 0; i < len(base58btcAlphabet); i++ {
		t[base58btcAlphabet[i]] = int8(i)
	}
	return t
}()

// ErrInvalidBase58 is returned when decoding a string with a non-alphabet character.
var ErrInvalidBase58 = errors.New("multiformats: invalid base58btc character")

// ErrBase58TooLong is returned when decode input exceeds maxBase58Input.
var ErrBase58TooLong = errors.New("multiformats: base58 input too long")

// Base58Encode encodes bytes to a base58btc string (Bitcoin alphabet).
func Base58Encode(input []byte) string {
	if len(input) == 0 {
		return ""
	}

	// Count leading zero bytes — each maps to a leading '1'.
	zeros := 0
	for zeros < len(input) && input[zeros] == 0 {
		zeros++
	}

	// Convert the base-256 number to base-58 via repeated division.
	// Work on a copy so the input is not mutated.
	buf := make([]byte, len(input))
	copy(buf, input)

	// Output is built in reverse.
	out := make([]byte, 0, len(input)*138/100+1)
	start := zeros
	for start < len(buf) {
		remainder := 0
		for i := start; i < len(buf); i++ {
			acc := remainder*256 + int(buf[i])
			buf[i] = byte(acc / 58)
			remainder = acc % 58
		}
		out = append(out, base58btcAlphabet[remainder])
		// Advance past any new leading zeros produced by the division.
		for start < len(buf) && buf[start] == 0 {
			start++
		}
	}

	// Add leading '1's for the leading zero bytes.
	res := make([]byte, 0, zeros+len(out))
	for i := 0; i < zeros; i++ {
		res = append(res, '1')
	}
	// Reverse the base-58 digits into place.
	for i := len(out) - 1; i >= 0; i-- {
		res = append(res, out[i])
	}
	return string(res)
}

// Base58Decode decodes a base58btc string back to bytes.
func Base58Decode(input string) ([]byte, error) {
	if input == "" {
		return []byte{}, nil
	}
	if len(input) > maxBase58Input {
		return nil, ErrBase58TooLong
	}

	// Count leading '1's — each maps to a leading zero byte.
	zeros := 0
	for zeros < len(input) && input[zeros] == '1' {
		zeros++
	}

	// Decode base-58 digits into a base-256 big-endian number.
	buf := make([]byte, 0, len(input))
	for i := zeros; i < len(input); i++ {
		val := int(base58Inverse[input[i]])
		if val < 0 {
			return nil, ErrInvalidBase58
		}
		carry := val
		for j := 0; j < len(buf); j++ {
			carry += 58 * int(buf[j])
			buf[j] = byte(carry & 0xff)
			carry >>= 8
		}
		for carry > 0 {
			buf = append(buf, byte(carry&0xff))
			carry >>= 8
		}
	}

	// buf is little-endian; build the result big-endian with leading zeros.
	res := make([]byte, 0, zeros+len(buf))
	for i := 0; i < zeros; i++ {
		res = append(res, 0)
	}
	for i := len(buf) - 1; i >= 0; i-- {
		res = append(res, buf[i])
	}
	return res, nil
}
