# BLRCS 指示書 — Sonnet track (small/medium, well-scoped axes)

This document tells a **Claude Sonnet** session how to continue improving
BLRCS. Every task here has a precise spec, an existing in-repo pattern to
mirror, and low architectural risk — ideal for autonomous execution with the
standard discipline below. Pick the top unstarted task, complete it fully
(including tests + E2E + commit + push + CHANGELOG), then take the next.

See `docs/PRODUCT_ASSESSMENT.md` for the why. See `docs/INSTRUCTIONS_OPUS.md`
for the large/architectural tracks — do **not** start those here.

---

## Working discipline (MANDATORY for every task)

1. **Branch.** Work on `claude/deepresearch-ultrathink-improve-YbA9t`. If that
   branch's PR was already merged to `main`, restart it fresh:
   `git fetch origin main && git checkout -B claude/deepresearch-ultrathink-improve-YbA9t origin/main`.
   Never push to `main` directly; never force-push; never touch the legacy
   Python tree at the repo root.

2. **Spec first.** BEFORE writing code, verify the exact wire format against
   the primary spec. `openid.net` returns HTTP 403 from this environment — use
   raw GitHub spec mirrors (e.g.
   `raw.githubusercontent.com/decentralized-identity/didwebvh/main/spec/specification.md`,
   `raw.githubusercontent.com/openid/OpenID4VP/main/...`) or converge on
   multiple secondary sources. Do not guess field names.

3. **Implement**, matching surrounding code's idiom, comment density, and
   naming. Reuse existing helpers (named per task below) rather than adding new
   ones.

4. **Verify — all of these must pass, in this order:**
   ```
   cd blrcs
   go build ./... && go vet ./... && gofmt -l .   # gofmt must print nothing
   go test -race -count=1 ./...
   golangci-lint run ./...                          # must be "0 issues"
   ```

5. **E2E against a real binary.** Build and drive `cmd/blrcs-mcp` (stdio
   JSON-RPC) or `cmd/blrcs-mcpd` (HTTP) and exercise the new behavior against
   the running process — not just unit tests. (For a pure library change with
   no tool surface, a package-level integration test over the real transport,
   like `openid4vci`'s httptest.Server tests, satisfies this.)

6. **Commit** with a why-focused, multi-paragraph message. Number the change
   as the next Axis (the last shipped is **Axis 132**; start at **133**).
   End the message with the repo's standard Co-Authored-By / Claude-Session
   trailers (copy the format from recent commits: `git log -1`).

7. **Push** with retry+backoff:
   `for i in 1 2 3 4; do git push -u origin claude/deepresearch-ultrathink-improve-YbA9t && break || sleep $((2**i)); done`.

8. **CHANGELOG** entry as a **separate** follow-up commit under
   `## [Unreleased]` → `### Added` or `### Fixed`, then push again.

9. If you add an MCP tool: update the `toolDefs()` list, the `dispatch()`
   switch, the package doc-comment tool list in `mcp/mcp.go`, the
   `auditableTool` map if it mutates state, and the **tool count in
   `mcp/mcp_test.go` `TestToolsList`** (currently 34).

---

## Tasks (in recommended order)

### S1 — mdoc `transaction_data` binding (format parity with SD-JWT)

- **Why:** SD-JWT already binds `transaction_data` into the KB-JWT (Axis 114);
  mdoc device auth has no equivalent, so a payment/QES authorization can't be
  bound to an mdoc presentation.
- **Spec:** OpenID4VP 1.0 §Transaction Data + OpenID4VC HAIP; for mdoc the
  hashes travel in the device-signed structure. Verify the exact placement
  against the spec before coding.
- **Files:** `mdoc/deviceauth.go` (`SignDeviceAuth`/`VerifyDeviceAuth` — note
  they currently have zero `transaction` references). Add optional
  `transactionDataHashes` params via new `*WithTx` variants so the existing
  signatures stay backward-compatible.
- **Mirror:** `compliance/extensions.go` Axis 114 pattern
  (`PresentWithKeyBindingTx`, `verifyTransactionDataHashes`,
  `ExpectedTransactionData`), and the `*WithAlgs` backward-compatible-variant
  pattern from Axis 124 (`cbor.Verify1WithAlgs`).
- **Accept:** new tests proving a tx-bound device signature verifies only when
  the verifier supplies matching transaction_data, and that plain
  `VerifyDeviceAuth` is unchanged.

### S2 — did:webvh `/whois` discovery

- **Why:** did:webvh v1.0 defines a `/whois` lookup returning a Verifiable
  Presentation with the DID as `credentialSubject`, signed by the DID's
  current key — a decentralized trust-registry capability. Currently absent
  (`grep -r whois` → nothing).
- **Spec:** did:webvh v1.0 §whois (raw GitHub mirror).
- **Files:** new `didwebvh/whois.go`; expose via an MCP tool in `mcp/mcp.go`.
- **Reuse:** the existing VP/VC issuance in `compliance` and the did:webvh key
  handling; the MCP issuer-key lookup pattern from `toolSignWitnessProof`.
- **Accept:** build a whois VP for a DID, verify it resolves and is signed by
  the current update key; MCP round-trip test + E2E over stdio.

### S3 — DCQL `trusted_authorities` §6.1.1 (structural)

- **Why:** flagged out-of-MVP in-code at `openid4vp/dcql.go:179`. Lets a
  verifier constrain acceptable issuer trust frameworks directly in the query.
- **Scope caution:** BLRCS has no ETSI TL / OpenID Federation / IACA
  infrastructure, so implement the **structure + validation + issuer-identifier
  matching** only, and clearly document that full trust-framework chain
  resolution (per the `aki`/`etsi_tl`/`openid_federation` type semantics) is a
  separate concern. Do NOT fabricate trust resolution that isn't real.
- **Files:** `openid4vp/dcql.go` — add `TrustedAuthorities` to `CredentialQuery`,
  validate the type/values shape, and gate a credential on its `iss` appearing
  in the allowed set.
- **Mirror:** the `claim_sets` addition from Axis 128 (same file: struct field
  + `Validate()` rules + matching in `credentialSatisfiesQuery`).
- **Accept:** tests for parse/validate + an issuer inside/outside the allowed
  set.

### S4 — `verifier_info` request parameter carry

- **Why:** OpenID4VP 1.0 §5 renamed `verifier_attestation(s)` →
  `verifier_info` (an array of verifier attestations wallets evaluate). Absent
  (`grep -r verifier_info` → nothing); only the `verifier_attestation` client_id
  prefix's non-emptiness is checked (`openid4vp/clientid.go:21`).
- **Files:** `openid4vp/openid4vp.go` (carry `verifier_info` on the
  AuthorizationRequest through both the plain and JAR-signed paths, like Axis
  114 threaded `transaction_data`).
- **Scope caution:** carrying + structural parsing is the clean deliverable;
  full `typ=verifier-attestation+jwt` chain-to-trust-root verification is
  Opus-track (overlaps RP registration). Document the boundary.
- **Accept:** verifier_info round-trips through request build/parse and the JAR
  path.

### S5 — kms crypto-agility honesty (ADR-0001 correction) — ✅ DONE (Axis 149)

- **Resolved by deletion, not by either option offered here.** The task proposed
  (a) correcting the ADR text or (b) parameterising `kms`'s size checks. The
  measured answer was that `kms` had zero non-test importers and was reachable
  from no binary, so option (b) would have been optimising a part that should
  not exist. Axis 149 deleted the package (with 12 others) and amended
  `docs/adr/0001` to name the seams that actually provide agility — the
  `jwsSigner` interface, the COSE algorithm registry, `RegisterJWSVerifier` with
  per-call `AllowedAlgs`, and `ecdsakey`. Both halves of the acceptance
  criterion hold: ADR and code agree, and no test needed changing.

### S6 — `eddsa-jcs-2022` Data Integrity suite for `compliance.Credential`

- **Why:** issued DPP VCs use pre-Data-Integrity `Ed25519Signature2020`
  (`compliance/compliance.go:82,148,193`), while a correct `eddsa-jcs-2022`
  implementation already exists in-repo (`didwebvh/proof.go` +
  `multiformats/jcs.go`), scoped only to DID-log entries.
- **Files:** `compliance/compliance.go` — add an opt-in `eddsa-jcs-2022`
  proof type reusing `multiformats/jcs.go` canonicalization; keep
  `Ed25519Signature2020` for backward compatibility (do not break existing
  verification).
- **Accept:** a credential issued with the new suite verifies via the reused
  JCS machinery; existing Ed25519Signature2020 tests still pass.

### S7 — make BLRCS CI actually run

- **Why:** `blrcs/.github/workflows/ci.yml` never executes — GitHub only runs
  workflows at the **repo root** `.github/workflows/`. Since blrcs is a
  subdirectory of a repo whose root workflows target the legacy Python
  project, add a **root-level** workflow (distinct filename, e.g.
  `blrcs-go-ci.yml`) that `cd blrcs` and runs build/vet/gofmt/test/lint,
  triggered only on changes under `blrcs/**` (path filter) so it never
  interferes with the Python workflows.
- **Scope caution:** this touches the **repo root**, outside `blrcs/`. This is
  the one Sonnet task allowed to add a root file; keep it purely additive and
  path-scoped. Do not modify existing root workflows.
- **Accept:** the workflow file is valid YAML, path-filtered to `blrcs/**`, and
  mirrors the local verification commands exactly.

---

## Notes

- Numbering is shared with the Opus track — check `git log` and `CHANGELOG.md`
  for the highest Axis number before claiming one.
- If a task turns out larger than "small/medium" once you open the spec (e.g.
  verifier_info drags in full trust-root verification), stop at the clean
  boundary, ship that, and note the remainder for the Opus track rather than
  expanding scope.
