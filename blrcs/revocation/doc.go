// Package revocation provides credential status tracking via two models:
//
//   - Entry-based signed list (List/SignedList): fast internal lookup with
//     structured reasons, signed and SCITT-anchorable.
//   - W3C Bitstring Status List v1.0 (BitstringStatusList): the current
//     standard — a GZIP-compressed, base64url-encoded bitstring for
//     interoperable, herd-private status distribution. Supersedes StatusList2021.
package revocation
