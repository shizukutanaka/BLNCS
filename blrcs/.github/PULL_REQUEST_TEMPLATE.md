<!-- Thank you for contributing to BLRCS. Please complete the checklist below. -->

## Summary

<!-- What does this change do, and why? Link any related issue. -->

Closes #

## Type of change

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change (a `feat!`/`fix!` requiring a major version bump)
- [ ] Standards-conformance change (W3C / IETF / GS1 / EU regulation)
- [ ] Documentation only

## Standards / regulatory impact

<!-- If this touches credential formats, revocation, transparency, or DPP data
     models, name the spec and section (e.g. "W3C VC 2.0 §4.7", "ESPR Art. 9.2d"). -->

## Checklist

- [ ] `make precommit` passes (fmt, dup-check, vet, full test suite)
- [ ] New exported symbols are documented (doc comment per `golint`)
- [ ] Tests added/updated; coverage not reduced for the touched package
- [ ] Zero new external dependencies (stdlib + `crypto/ed25519` only)
- [ ] `CHANGELOG.md` updated under `## [Unreleased]`
- [ ] For credential/format changes: a `conformance/` vector was added or updated
- [ ] Race detector clean for any package with concurrency (`go test -race`)

## Notes for reviewers

<!-- Anything tricky, trade-offs taken, or follow-ups deliberately deferred. -->
