# Contributing to BLRCS

Thank you for your interest in contributing. BLRCS implements EU regulatory
standards (ESPR Digital Product Passport, Battery Regulation 2023/1542) in
production-grade Go — please read this guide before submitting changes.

## Prerequisites

- Go 1.22+
- No other tools required — BLRCS has zero external dependencies

## Getting Started

```bash
git clone https://github.com/shizukutanaka/blrcs
cd blrcs
go test ./...          # all 700+ tests must pass
go vet ./...           # must be warning-free
```

## Development Workflow

```bash
make test              # run full test suite
make cover             # coverage report
make bench             # performance baselines
make fuzz              # fuzz all parsers (30s each)
make doctor            # self-diagnostic (13 checks, <10ms)
make build             # compile all binaries
```

## Coding Standards

### Zero external dependencies

BLRCS uses only the Go standard library and `crypto/ed25519`. **Do not add external imports.** If you think an external package is genuinely necessary, open an issue first.

### Design principles

Code follows three design philosophies:
- **Carmack** — direct, high-performance, measure before optimising
- **Martin** — single responsibility, clean interfaces
- **Pike** — simplicity, clear names, obvious control flow

### Error handling

Use `errkit` for all public API error returns at boundary layers (`ctx/`, `compose/`). Internal packages (`compliance/`, `scitt/`, etc.) may use `errors.New` / `fmt.Errorf`.

```go
// ✅ boundary layer
return nil, errkit.E(errkit.OpDPPIssue, errkit.CodeInvalidInput, "productID required", nil)

// ✅ internal package
return nil, errors.New("compliance: proof missing")
```

### Testing requirements

- All new public functions need at least one unit test
- New packages need an `Example_*` function for godoc
- Concurrent code must pass `go test -race`
- Coverage must not decrease below the current floor for any package

```bash
# Check race detector
go test -race ./...

# Check coverage doesn't regress
go test -cover ./...
```

### Code formatting

```bash
gofmt -s -w .
go vet ./...
```

Both must be clean before submitting.

### Documentation

Every exported function, type, and package must have a doc comment. Every package needs a `doc.go` file explaining its purpose and design rationale.

## Pull Request Process

1. **Fork** and create a feature branch from `main`
2. **Implement** with tests (coverage must not regress)
3. **Run** `make ci` locally — all checks must pass
4. **Sign** your commits (GPG or SSH signing)
5. **Submit** PR with:
   - Clear title (follows Conventional Commits: `feat:`, `fix:`, `docs:`, etc.)
   - Description explaining *why*, not just *what*
   - Link to any related issues

### PR size guidance

- Prefer small, focused PRs
- Large refactors: open an issue to discuss before coding
- New packages: require design discussion in an issue first

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(scitt): add Merkle proof streaming API
fix(compliance): reject negative carbon footprint at parse time
docs(types): add Example_ functions for DID and GTIN
test(mcp): add HTTP handler auth rejection coverage
chore(ci): bump Go version to 1.23
```

Breaking changes: append `!` after type: `feat!(api): rename VerifyDPP to Verify`

## Standards Compliance

BLRCS implements international standards. When modifying compliance-related code:
- Cite the specific clause of the standard (e.g. "ESPR Art.9 §2(b)")
- Reference the RFC or spec version
- Add a conformance test vector if possible

## Security Reports

**Do not open public issues for security vulnerabilities.** See [SECURITY.md](SECURITY.md).

## Code of Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

By contributing, you agree that your contributions will be licensed under the
project's [MIT License](LICENSE).
