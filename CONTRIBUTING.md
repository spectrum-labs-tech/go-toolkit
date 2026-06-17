# Contributing

## Running tests

Unit tests (no network, no keys):

```
go test ./...
```

Or via Task:

```
task test
```

## Adding a package

1. Create `pkg/<name>/` with at least one `.go` source file.
2. Add a corresponding `<name>_test.go` covering the main happy path and at least one failure case.
3. Run `go vet ./...` and `go test ./...` before submitting.

## Code style

- Standard `gofmt` / `goimports` formatting (`task fmt`).
- All exported types and functions must have a doc comment.
- No global mutable state. Package-level vars should be unexported constants or errors.
- Security-sensitive packages (`pkg/jwt`, `pkg/ginmiddleware`) must have tests that explicitly cover rejection of malformed, expired, and cross-type tokens.

## Pull requests

- Keep each PR focused on one package or one feature.
- All unit tests must pass: `go test -race ./...`
- No new linter warnings: `go vet ./...`
