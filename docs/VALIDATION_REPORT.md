# opredir 0.5.1 — Validation Report

Validation is performed locally against the source in this release package.

## Static and unit checks

| Check | Result |
|---|---|
| `gofmt` | Passed |
| `go test ./...` | Passed |
| `go test -race ./...` | Passed |
| `go vet ./...` | Passed |
| Linux amd64 build | Passed |
| Root CLI help (`opredir -h`) | Passed |
| Version command (`opredir version`) | Passed |

## CLI shape

The primary workflow is invoked directly with `opredir -d ...` or `opredir -l ...`. The standalone `scan`, `generate`, and `verify` subcommands are not exposed. Payload generation and redirect verification remain internal stages of the automatic workflow. The optional `request` command is retained only for replaying an existing JSONL test-case file; `ui-demo` uses mock data only.

## Automated local integration tests

The Go integration tests start loopback-only HTTP test servers, issue requests through the root CLI handler, confirm a matching external redirect response, and check that confirmed findings are printed by default. A separate test checks that `-hide` suppresses finding details on the console while keeping the finding in the detailed report.

## Scope and limits

- No live third-party targets were tested.
- Requests remain restricted to the exact target authority, and HTTP redirects are not followed.
- Browser-only/DOM-based redirects are not confirmed by the HTTP engine.
