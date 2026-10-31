# opredir 0.1.0 — Validation Report

Validation performed in the build container on 2026-10-31.

## Static and unit checks

| Check | Result |
|---|---|
| `gofmt` | Passed |
| `go test ./...` | Passed |
| `go test -race ./...` | Passed |
| `go vet ./...` | Passed |
| Linux amd64 build | Passed |
| Windows amd64 cross-build | Passed |
| CLI `version` command | Passed |
| CLI command help | Passed |

## Local end-to-end request test

A temporary HTTP server bound only to `127.0.0.1:18999` returned a `302` and a `Location` pointing to `https://redirect-marker.invalid/landing`.

`opredir generate` created one test case, and `opredir request` sent it with `--authorized --scope-host 127.0.0.1`.

Observed result:

- HTTP status: `302`
- Captured Location: `https://redirect-marker.invalid/landing`
- `redirect_followed`: `false`
- Remote address: loopback (`127.0.0.1:18999`)
- Exactly one request reached the mock server; the external Location was not requested.

## Scope guard tests

- Request command without `--authorized`: rejected.
- Target host outside `--scope-host`: rejected before network activity.
- Request URL authority differing from `target_url`: rejected before network activity.
- Custom `Host` header override: rejected.

## Not yet validated

- No live third-party targets were tested.
- The previous Flask lab was not launched in this container; Flask/Docker runtime was unavailable. The HTTP engine was tested against a loopback-only Go `httptest`/mock server.
- No Open Redirect verdict is produced yet; the Verification Engine is the next development phase.
