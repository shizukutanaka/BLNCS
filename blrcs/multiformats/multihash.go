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
// digest bytes.
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
