# BLRCS Development Workflow

Conventions that keep the inner loop fast and prevent the recurring mistakes
this codebase has hit. Aligns with CLAUDE.md §3 (PIPELINE) and §6 (CODE QUALITY).

## Inner loop (editing one package)

```
make api PKG=<pkg>      # 1. dump exported signatures BEFORE writing tests
# ... write code/tests ...
make verify PKG=<pkg>   # 2. build + vet + test that package only (fast)
```

`make api` exists because the single biggest time sink has been writing tests
against guessed signatures, hitting a build failure, then grepping for the real
one. Read the signatures first. Value-vs-pointer returns and struct field names
(`PresentationDefinition` not `Definition`, `StepsCompleted` not
`CompletedSteps`) are the usual traps.

## Before declaring work done

```
make precommit   # fmt + dup-check + vet + test (full)
```

`dup-check` catches duplicate `Test*`/`Benchmark*` names within a package — the
failure mode of appending with `cat >>`. Append, then run it before building.

## Authoring tests — checklist

1. `make api PKG=<pkg>` — confirm exact signatures, return arity, field names.
2. Append tests; do **not** reuse an existing function name in the same package.
3. Add the import you need (`context`/`fmt`/`errors`/`time`/`net/http`) — missing
   imports are the second most common build break.
4. `make verify PKG=<pkg>` before touching anything else.

## Coverage floors that are structural, not laziness

Do not chase these to 100% — the uncovered lines require unreachable conditions:

- `doctor` ~79% — error branches need OS-level crypto failure.
- `conformance` ~72% — bounded by the number of reference vectors.
- `mcp` ~85% — SSE streaming paths are not unit-testable.
- `ctx` ~81% — error wrapping paths need the underlying primitive to fail.

Add a genuine reachable test instead of contorting these.

## Filesystem reset recovery

If `/home/claude/blrcs` is lost mid-session, the last-known-good tree lives in
`/mnt/user-data/outputs`. Recovery:

1. `apt-get install -y golang-go` (if `go` is gone); verify `go version`.
2. `mkdir -p /home/claude/blrcs` and create `go.mod` (`module blrcs` / `go 1.22`).
3. Copy package dirs from `/mnt/user-data/outputs/<pkg>/*.go`. Top-level `.go`
   files in the outputs root belong to their packages (e.g. `scitt.go` →
   `scitt/`, `mcp.go`+`http.go` → `mcp/`, `main.go` → `cmd/blrcs-mcp/`).
4. Remove any stray root-level `.go` files after sorting them into packages.
5. `make build && make test` to confirm the tree is whole.
