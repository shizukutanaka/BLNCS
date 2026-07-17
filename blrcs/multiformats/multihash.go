package multiformats

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

// Multicodec identifiers (subset; see the multicodec table).
const (
	codecSHA2256 = 0x12 // sha2-256
	sha256Len    = 0x20 // 32 bytes
)

// ErrBadMultihash is returned when parsing a malformed multihash.
var ErrBadMultihash = errors.New("multiformats: malformed multihash")

// ErrUnsupportedCodec is returned by ParseMultihashSHA256 when the multihash
// codec is not sha2-256 (0x12). Accepting non-SHA256 codecs silently would
// allow a hash-algorithm-substitution attack: an attacker presents a multihash
// over a weaker or different algorithm (e.g. SHA-1, blake2b) that the caller
// then uses for integrity checking without realising the algorithm changed.
var ErrUnsupportedCodec = errors.New("multiformats: unsupported multihash codec (only sha2-256 accepted)")

// MultihashSHA256 wraps raw data in a SHA-256 multihash:
//
//	0x12 (sha2-256) || 0x20 (length=32) || sha256(data)
func MultihashSHA256(data []byte) []byte {
	sum := sha256.Sum256(data)
	mh := make([]byte, 0, 2+sha256Len)
	mh = append(mh, codecSHA2256, sha256Len)
	mh = append(mh, sum[:]...)
	return mh
}

// HashThenBase58 computes base58btc(multihash-sha256(data)) — the encoding used
// by did:webvh for SCID and entryHash values (e.g. "Qm…").
func HashThenBase58(data []byte) string {
	return Base58Encode(MultihashSHA256(data))
}

// ParseMultihash validates a multihash and returns its codec, digest length, and
// digest bytes. It does NOT enforce a specific codec — use ParseMultihashSHA256
// when sha2-256 is the only acceptable algorithm.
func ParseMultihash(mh []byte) (codec int, digest []byte, err error) {
	if len(mh) < 2 {
		return 0, nil, ErrBadMultihash
	}
	codec = int(mh[0])
	length := int(mh[1])
	if len(mh)-2 != length {
		return 0, nil, fmt.Errorf("%w: declared length %d, have %d", ErrBadMultihash, length, len(mh)-2)
	}
	return codec, mh[2:], nil
}

// ParseMultihashSHA256 is like ParseMultihash but additionally enforces that
// the codec is sha2-256 (0x12) and the digest is exactly 32 bytes. Use this
// wherever the caller requires SHA-256 specifically; it prevents an attacker
// from substituting a weaker algorithm (e.g. 0x11 = sha1) in the codec byte.
func ParseMultihashSHA256(mh []byte) (digest []byte, err error) {
	codec, d, err := ParseMultihash(mh)
	if err != nil {
		return nil, err
	}
	if codec != codecSHA2256 {
		return nil, fmt.Errorf("%w: got 0x%02x, want 0x%02x (sha2-256)", ErrUnsupportedCodec, codec, codecSHA2256)
	}
	if len(d) != sha256Len {
		return nil, fmt.Errorf("%w: sha2-256 digest must be 32 bytes, have %d", ErrBadMultihash, len(d))
	}
	return d, nil
}
