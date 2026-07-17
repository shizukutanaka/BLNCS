# ADR-0002: Secure-by-default holder binding and credential lifecycle

Status: Accepted
Date: 2026-06

## Context

An issuer-signed credential with no holder binding is a **bearer token**: anyone who
captures a presentation can replay it to another verifier. An early iteration of the
OpenID4VP verifier generated a `nonce` but never bound the presentation to it (the
code even noted "nonce verification simplified for MVP"), so anti-replay rested
entirely on one-time `state` consumption. For an implementation that targets the
eIDAS 2.0 / EUDI Wallet ecosystem and EU DPP/Battery passports, that is too weak:

- A `vp_token` observed on the wire (or a logged request) could be re-presented.
- A pre-authorized OpenID4VCI offer (a QR code) could be redeemed by whoever
  photographed it.
- A revoked credential still verified, because the verifier never consulted status.
- A future-dated (`validFrom` in the future) W3C VC verified, because only
  `validUntil` was checked.

The cross-cutting question: should these protections be opt-in (preserving the
permissive MVP behavior) or on-by-default (forcing callers to opt out for bearer
flows)?

## Decision

The credential lifecycle is **secure-by-default**. Specifically:

1. **Holder binding is required by default.** `openid4vp.NewVerifier` sets
   `RequireKeyBinding = true`. SD-JWT presentations must carry a KB-JWT signed by the
   `cnf` key and bound to the request `nonce` + verifier `client_id`
   (`VerifySDJWTWithBinding`). mdoc presentations must carry ISO 18013-5 §9.1.3
   device authentication bound to a session transcript (`VerifyDocument`). Callers
   accept bearer credentials only by explicitly setting `RequireKeyBinding = false`.

2. **Issuance binds automatically where the protocol allows it.** OpenID4VCI
   `IssueCredentialWithProof` binds the issued credential to the key the wallet
   proved possession of (the whole point of proof-of-possession), rather than
   discarding it and emitting a bearer credential.

3. **The DCQL query is enforced, not just transmitted.** `ProcessResponse` checks the
   presented credential against `dcql_query` (§6.1 credential queries and §6.2
   `credential_sets`, with the spec's `required: true` default honored). DCQL trust
   anchors come from `Verifier.TrustedIssuers`, since the query carries no keys.

4. **Revocation is checkable in-flow and fails closed.** Verified presentations expose
   the `status_list` reference; a configured `RevocationChecker` rejects revoked
   credentials with `ErrCredentialRevoked` before state is consumed.

5. **Both temporal bounds are enforced** (`validFrom` and `validUntil`) for W3C VC and
   SD-JWT, with a small clock-skew leeway on the not-yet-valid bound.

6. **Pre-authorized offers can be PIN-bound** (`tx_code`) with constant-time
   comparison and an attempt limit (`MaxTxCodeAttempts`, default 5) that burns the
   code on repeated failures.

## Rationale

- **Default-on, opt-out.** Security defaults that must be switched on are usually left
  off. The replay/interception risks above are silent — nothing fails loudly when a
  bearer credential is accepted — so the safe state must be the default. The opt-outs
  exist for legitimate local/bearer flows and are named explicitly at the call site.
- **Network-free verification core.** Revocation needs the status list, which lives at
  a URL. Rather than make the verifier perform I/O (and become hard to test and
  sandbox), the `RevocationChecker` callback delegates the fetch to the caller. The
  verification core stays pure; the integration test wires a real list through it.
- **Backward compatibility without weakening defaults.** New behavior was added
  through new optional fields, methods, and sentinels (`TrustedIssuers`,
  `RevocationChecker`, `OfferOptions`, `VerifyAt`, `IssueSDJWTBoundStatus`,
  `CreateOfferWithTxCode`) so the existing test suite keeps compiling. The single
  deliberate *behavior* change is `RequireKeyBinding` defaulting to `true`.

## Consequences

- **Behavior change (intended):** code that relied on the verifier accepting unbound
  presentations must now either issue holder-bound credentials or set
  `RequireKeyBinding = false`. The permissive end-to-end path remains available and is
  still covered by `TestTriangle_IssuerWalletVerifier`; the hardened path is covered
  by `TestHardenedTriangle_*`.
- **Revocation requires the caller to fetch the status list.** Without a configured
  `RevocationChecker`, the verifier surfaces `VerifiedPresentation.Status` but does not
  reject revoked credentials — the relying party must check, or set the hook.

## Known limitations (accepted)

1. **One credential per presentation.** `AuthorizationResponse` carries a single
   `vp_token`, so a `dcql_query` requesting several credentials is enforced against the
   one presented credential (a multi-id `credential_set` option that needs two distinct
   credentials is correctly rejected as unsatisfiable). Full multi-credential responses
   (the OpenID4VP v1.0 `vp_token` map keyed by credential-query id) are a larger
   wire-model change deferred until a concrete multi-credential use case lands.

2. **mdoc device authentication uses an opaque session transcript.** The caller
   supplies the bytes the session is bound to (e.g. an OpenID4VP handover or a hash of
   nonce+audience); both sides must agree on them. A full ISO 18013-5 SessionTranscript
   negotiation (DeviceEngagement / EReaderKey handover) is out of scope for the
   reference implementation.

3. **KB-JWT freshness rests on one-time state + state TTL,** not a separate maximum
   KB-JWT age. `VerifyOptions.MaxKBAge` exists for callers who want an explicit bound;
   the verifier does not set one by default because consumed-once `state` with a short
   TTL already bounds the replay window.
