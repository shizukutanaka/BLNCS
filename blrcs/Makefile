# BLRCS Makefile — stdlib-only Go project
#
# Primary targets:
#   make test       — full test suite
#   make cover      — coverage report
#   make bench      — benchmarks
#   make fuzz       — fuzz all parsers (30s each)
#   make build      — compile all binaries
#   make doctor     — self-diagnostic
#   make clean      — remove build artifacts
#
# CI target:
#   make ci         — test + cover + vet + build (GitHub Actions)

.PHONY: test cover bench fuzz build doctor clean ci vet fmt api dup-check lint precommit verify

# ============================================================================
# Core
# ============================================================================

test:
	go test ./...

test-v:
	go test -v ./...

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
lint:
	golangci-lint run ./... || echo "(golangci-lint not installed; CI runs it)"

# verify — fast inner-loop check for a single package after editing.
#   Usage: make verify PKG=compliance
verify:
	@test -n "$(PKG)" || (echo "usage: make verify PKG=<package>" && exit 1)
	go build ./$(PKG)/... && go vet ./$(PKG)/... && go test ./$(PKG)/...

# precommit — full local gate before declaring work done (CLAUDE.md §6.3).
precommit: fmt dup-check vet test
	@echo "precommit gate passed"

# ============================================================================
# Performance
# ============================================================================

bench:
	go test -run='^$$' -bench=. -benchmem -benchtime=100ms ./benchmark/...

fuzz:
	@echo "Fuzzing DID..."
	go test -run='^$$' -fuzz=FuzzDID -fuzztime=30s ./fuzz/
	@echo "Fuzzing GTIN..."
	go test -run='^$$' -fuzz=FuzzGTIN -fuzztime=30s ./fuzz/
	@echo "Fuzzing SD-JWT..."
	go test -run='^$$' -fuzz=FuzzSDJWT -fuzztime=30s ./fuzz/

# ============================================================================
# Build
# ============================================================================

build:
	go build ./cmd/blrcs/
	go build ./cmd/blrcs-mcpd/
	go build ./cmd/blrcs-demo/
	go build ./cmd/blrcs-mcp/
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

ci: vet test cover build
	@echo "CI passed"

# ============================================================================
# Clean
# ============================================================================

clean:
	rm -f coverage.out
	go clean ./...
