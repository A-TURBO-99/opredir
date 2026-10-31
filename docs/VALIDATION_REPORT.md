# opredir 0.2.0 — Validation Report

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
| CLI version and usage | Passed |
| `-d` scan input | Passed |
| `-l` list input | Passed |

## End-to-end scan test (loopback only)

A temporary Python HTTP server bound to `127.0.0.1` accepted a generated request, read the `url` query parameter, and responded with a `302 Location` pointing to that exact supplied destination. The test was run twice: once using `-d http://127.0.0.1:<ephemeral-port>/redirect`, and once using a one-line `-l` file containing the same endpoint.

Both runs produced:

- one generated case and one captured response;
- HTTP 302 with external `Location` matching the supplied payload host;
- finding classification `confirmed_open_redirect`;
- `confirmed: true` and `redirect_followed: false`.

The mock server was local and ephemeral; no external destination was contacted.

## Verification unit coverage

- Matching external `Location` => confirmed.
- Relative `Location` resolving to same origin => not confirmed.
- External but uncorrelated `Location` => manual-review classification.
- Matching `Refresh` header => confirmed refresh redirect.
- Reflected payload with no navigation => reflection-only.
- JavaScript navigation-looking body => unconfirmed browser candidate.
- Same host with scheme change => not treated as external Open Redirect.
- Request errors => request_error.

## Scope controls

- Scan requires `--authorized`.
- `-d` derives one exact hostname scope.
- `-l` derives exact hostname scope from each listed subdomain/endpoint; wildcard expansion is not performed.
- The request engine still refuses any generated Request URL whose scheme, hostname or effective port differs from its Target URL.
- HTTP redirects are not followed.

## Not yet validated / limitations

- No live third-party targets were tested.
- No browser automation or real DOM data-flow analysis is included.
- URL parsing uses Go `net/url`; differences with browser WHATWG parsing and complex IDN/IP normalization can remain inconclusive.
- Multi-hop redirect chains are not followed or evaluated.
- The full 724-payload corpus was not executed during the end-to-end test; the test used one local case to verify the complete pipeline safely.

## CLI flag update (0.4.0)

- `-d` selects one domain/endpoint.
- `-l` selects a file of subdomains/endpoints.
- `-dl` sets the minimum delay between request starts.
- `-t` sets the concurrent worker count.
- Both `-d` and `-l` workflows were smoke-tested against a loopback-only HTTP redirect lab with `-dl 0s`; each produced one captured 302 response and a confirmed test finding.
