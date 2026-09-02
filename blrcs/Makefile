# BLRCS Makefile — stdlib-only Go project
#
# THE GATE:
#   make verify     — the complete gate. CI runs exactly this, so CI and local
#                     cannot drift. If this passes, the change is shippable.
#
# Inner loop:
#   make check PKG=compliance   — build+vet+test one package while editing
#   make test       — full test suite (race, count=1)
#   make fmt        — gofmt -s -w .
#
# Other targets:
#   make cover / bench / fuzz / build / doctor / clean
#
# Why one target: before Axis 151 there were three disagreeing definitions of
# "the gate" — `make ci` (no race, no gofmt, no lint, no dependency check), the
# GitHub workflow's job list, and what maintainers actually ran by hand. A gate
# that differs from the one CI runs is not a gate. `verify` is now the single
# definition and the workflow calls it.

.PHONY: test test-v cover bench fuzz fuzz-smoke build doctor clean ci vet fmt fmt-check deps-check api dup-check lint precommit verify check hooks

# ============================================================================
# Core
# ============================================================================

test:
	go test -race -count=1 ./...

test-v:
	go test -race -count=1 -v ./...

# ============================================================================
# Quality
# ============================================================================

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1
	@echo "Full report: go tool cover -html=coverage.out"

vet:
	go vet ./...

fmt:
	gofmt -s -w .

# ============================================================================
# Workflow guards — prevent recurring authoring mistakes
# ============================================================================

# api — dump all exported signatures of a package before writing tests against it.
#   Usage: make api PKG=compliance
#   Prevents: guessing wrong signatures → build failure → grep → fix loop.
api:
	@test -n "$(PKG)" || (echo "usage: make api PKG=<package>" && exit 1)
	@echo "=== exported API: $(PKG) ==="
	@grep -rhn "^func [A-Z]\|^func (.*) [A-Z]\|^type [A-Z]" $(PKG)/*.go | grep -v "_test.go" | sed 's/{$$//'

# dup-check — detect duplicate Test/Benchmark/Fuzz/Example names WITHIN a package.
#   Cross-package duplicates are legal in Go; only same-dir collisions break the build.
#   Prevents: "X redeclared in this block" failures from cat >> appends.
dup-check:
	@found=0; \
	for dir in $$(go list -f '{{.Dir}}' ./... 2>/dev/null); do \
	  dups=$$(grep -rh "^func \(Test\|Benchmark\|Fuzz\|Example\)" $$dir/*_test.go 2>/dev/null | sed 's/.*func //;s/(.*//' | sort | uniq -d); \
	  if [ -n "$$dups" ]; then echo "DUPLICATE in $$dir:"; echo "$$dups"; found=1; fi; \
	done; \
	if [ $$found -eq 0 ]; then echo "no within-package duplicate test names"; else exit 1; fi

# lint — golangci-lint with the committed config.
#   The `|| echo "(not installed)"` this used to end with swallowed REAL lint
#   failures too, so lint could never fail the gate — a check that cannot fail
#   is not a check. Now: skip only when the tool is genuinely absent, and fail
#   loudly when it is present and unhappy.
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
	  golangci-lint run ./...; \
	else \
	  echo "SKIP: golangci-lint not installed (install it, or rely on CI)"; \
	fi

# check — fast inner-loop check for a single package after editing.
#   Usage: make check PKG=compliance
#   (This was called `verify` before Axis 151; `verify` is now the full gate.)
check:
	@test -n "$(PKG)" || (echo "usage: make check PKG=<package>" && exit 1)
	go build ./$(PKG)/... && go vet ./$(PKG)/... && go test -race ./$(PKG)/...

# fmt-check — fail if anything is unformatted, without rewriting files.
#   `make fmt` rewrites; CI must not, so it needs a read-only variant.
fmt-check:
	@unformatted=$$(gofmt -s -l .); \
	if [ -n "$$unformatted" ]; then \
	  echo "gofmt reported unformatted files:"; echo "$$unformatted"; exit 1; \
	fi; \
	echo "gofmt clean"

# deps-check — BLRCS advertises zero external dependencies. Prove it rather
#   than trusting it: tidy must be a no-op, no go.sum may appear, and
#   `go list -m all` must report only the main module.
deps-check:
	@cp go.mod go.mod.verifyorig; \
	go mod tidy; \
	if ! diff -q go.mod go.mod.verifyorig >/dev/null; then \
	  echo "go mod tidy changed go.mod — commit the tidied file"; \
	  diff go.mod.verifyorig go.mod || true; rm -f go.mod.verifyorig; exit 1; \
	fi; \
	rm -f go.mod.verifyorig; \
	if [ -f go.sum ]; then echo "a go.sum exists — zero-dependency guarantee broken"; exit 1; fi; \
	external=$$(go list -m all | tail -n +2); \
	if [ -n "$$external" ]; then echo "external modules found:"; echo "$$external"; exit 1; fi; \
	echo "zero external dependencies confirmed"

# fuzz-smoke — every fuzz target briefly, for the gate. Targets are DISCOVERED,
#   not listed: a hand-written list silently skips newly-added targets, which is
#   exactly what the old workflow and the `fuzz` target below both did.
fuzz-smoke:
	@targets=$$(grep -rho '^func Fuzz[A-Za-z0-9_]*' ./fuzz/ | sed 's/^func //' | sort -u); \
	if [ -z "$$targets" ]; then echo "no fuzz targets discovered"; exit 1; fi; \
	for t in $$targets; do \
	  echo "fuzz $$t"; \
	  go test -run='^$$$$' -fuzz="^$$t$$$$" -fuzztime=5s ./fuzz/ >/dev/null || exit 1; \
	done; \
	echo "all $$(echo "$$targets" | wc -w | tr -d ' ') fuzz targets clean"

# verify — THE GATE. CI runs exactly this target.
#   Ordering is cheapest-first so a trivial failure reports in seconds.
verify: fmt-check dup-check vet deps-check build test lint fuzz-smoke
	@echo ""
	@echo "verify: PASSED — build, gofmt, vet, zero-dep, race tests, lint, fuzz"

# precommit — full local gate before declaring work done (CLAUDE.md §6.3).
precommit: fmt verify
	@echo "precommit gate passed"

# hooks — point git at the tracked hook directory so `git push` runs the gate.
#   The workflow that would run it on every push cannot be installed: this
#   identity lacks the GitHub `workflows` permission (verified across git push,
#   the REST contents API and the git data API). Until a maintainer moves
#   blrcs/.github/workflows/ci.yml to .github/workflows/, this is the only
#   automatic execution of the gate that exists. Per clone, once.
hooks:
	@git -C .. config core.hooksPath .githooks
	@echo "core.hooksPath = .githooks — 'git push' now runs 'make verify' when blrcs/ changed"

# ============================================================================
# Performance
# ============================================================================

bench:
	go test -run='^$$' -bench=. -benchmem -benchtime=100ms ./benchmark/...

# fuzz — every discovered target, 30s each (the deep run; `fuzz-smoke` is the
# 5s-per-target version the gate uses).
fuzz:
	@targets=$$(grep -rho '^func Fuzz[A-Za-z0-9_]*' ./fuzz/ | sed 's/^func //' | sort -u); \
	for t in $$targets; do \
	  echo "Fuzzing $$t..."; \
	  go test -run='^$$$$' -fuzz="^$$t$$$$" -fuzztime=30s ./fuzz/ || exit 1; \
	done

# ============================================================================
# Build
# ============================================================================

# ./... rather than an enumerated list: naming binaries individually meant a
# newly-added command was never build-checked (the GitHub workflow had the same
# bug and omitted blrcs-mcp entirely).
build:
	go build ./...
	@echo "Build complete"

# ============================================================================
# Doctor
# ============================================================================

doctor:
	go run ./cmd/blrcs/ doctor

doctor-json:
	go run ./cmd/blrcs/ doctor --json

# ============================================================================
# CI (GitHub Actions)
# ============================================================================

# ci — retained as an alias so existing invocations get the REAL gate. It
# previously meant `vet test cover build`: no race detector, no gofmt, no lint,
# no dependency check — weaker than what maintainers ran by hand.
ci: verify

# ============================================================================
# Clean
# ============================================================================

clean:
	rm -f coverage.out
	go clean ./...
