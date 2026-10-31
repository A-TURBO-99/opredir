# opredir

GitHub repository (intended): https://github.com/A-TURBO-99/opredir  
Author: **A-TURBO-99**

`opredir` is a Go-based Open Redirect research and testing tool. Version 0.4.2 provides the Go-based scan workflow, response Verification Engine, and consistent CLI flags: `-d` for a domain, `-l` for a target list, `-dl` for delay, and `-t` for worker threads.

> Use only against systems you own or are explicitly authorized to test. Active scan/request commands require an authorization acknowledgement and a bounded host scope derived from `-d` / `-l` or explicit `--scope-host` values. The tool never follows HTTP redirects.

## Current status

- [x] Go CLI and project structure (`opredir`)
- [x] Read the editable parameter wordlist (`data/parameters.txt`)
- [x] Read the cleaned URL-value corpus (`data/payloads/url_value_candidates.json`)
- [x] Resolve runtime placeholders
- [x] Generate Query-Parameter cases as JSONL
- [x] Preserve unrelated and duplicate query parameters
- [x] HTTP request engine with concurrency, rate limit, timeout and bounded response capture
- [x] Disable automatic redirect following
- [x] Require `--authorized` before active requests
- [x] `-d DOMAIN` and `-l FILE` scan input modes
- [x] Derive exact request scope from the supplied domain/list and preflight all cases
- [x] Verification engine for HTTP `Location` and `Refresh` redirects
- [x] Distinguish confirmed, unconfirmed, same-host, reflected-only and client-side candidate results
- [ ] Browser-based confirmation for client-side/DOM redirects
- [ ] Benchmark suite against broader vulnerable and non-vulnerable lab profiles
- [x] Separate terminal UI layer with mock preview (`ui-demo`)
- [x] Quiet plain-text and streaming JSONL UI preview modes
- [ ] Connect terminal UI callbacks to the live scan workflow
- [ ] Final findings/reporting UX

## Requirements

- Go 1.23 or newer
- No third-party Go modules are required; the implementation uses the standard library.

## Installation

### Build from source (Linux / macOS)

```bash
git clone https://github.com/A-TURBO-99/opredir.git
cd opredir
go build -o opredir ./cmd/opredir
```

Run it from the current directory:

```bash
./opredir --help
./opredir version
```

Optional: install the command into your Go binary directory:

```bash
go install github.com/A-TURBO-99/opredir/cmd/opredir@latest
```

If `$(go env GOPATH)/bin` is already in your `PATH`, you can run `opredir` directly. Otherwise, on Linux/macOS, copy it into a system-wide binary directory:

```bash
sudo cp "$(go env GOPATH)/bin/opredir" /usr/local/bin/opredir
```

Windows PowerShell build:

```powershell
go build -o .\opredir.exe .\cmd\opredir
.\opredir.exe --help
```

### Development checks

Run from the project root:

```bash
go test ./...
go test -race ./...
go vet ./...
```

Prebuilt amd64 binaries are included in `dist/`:

- `dist/opredir-linux-amd64` — Linux x86-64 (CGO disabled).
- `dist/opredir-windows-amd64.exe` — Windows x86-64.

SHA-256 checksums are in `dist/SHA256SUMS.txt`.


## 1.1. Preview the terminal UI (mock data only)

The UI is implemented as a separate Go package at `internal/ui`. Preview its layout without sending network traffic:

```bash
go run ./cmd/opredir ui-demo
```

The preview intentionally uses mock data (240 targets, 1 parameter, 12 payloads, 2,880 simulated requests, 3 mock findings). It writes `opredir-demo-report.html`, clearly marked as demo data. It does **not** run the real scanner or create real vulnerability evidence.

Output modes:

```bash
go run ./cmd/opredir ui-demo --verbose             # also display clean results
go run ./cmd/opredir ui-demo --quiet                # one plain-text line per result
go run ./cmd/opredir ui-demo --json                 # newline-delimited JSON events
go run ./cmd/opredir ui-demo --width 48             # preview narrow-terminal layout
go run ./cmd/opredir ui-demo --report demo.html     # choose demo report path
```

`--quiet` and `--json` are mutually exclusive. Colors are enabled only for an interactive terminal when `NO_COLOR` is not set and `TERM` is not `dumb`. Progress uses in-place terminal updates only when stdout is an interactive terminal. The UI has not yet been connected to the real `scan` command; that is the next integration step after reviewing this mock preview.

## 1. Scan a domain or a target list (generate + request + verify)

The scan workflow accepts exactly one target source:

- `-d DOMAIN`: one domain or URL. A bare domain defaults to HTTPS. If you need HTTP or a custom port/path, include the scheme, for example `http://127.0.0.1:5000/redirect`.
- `-l FILE`: one subdomain or endpoint per line. Bare hostnames default to HTTPS; full endpoint URLs are kept as supplied. Blank lines and `#` comments are ignored. Duplicate entries are removed.
- `-dl DURATION`: minimum delay between consecutive request starts (default `500ms`; `0s` disables the delay).
- `-t N`: number of concurrent HTTP workers (default `4`; allowed range `1..100`).
- `-u DOMAIN` remains available as a legacy alias for `-d`; prefer `-d` in new commands.

`-d` does not enumerate subdomains. Use `-l` to provide the exact subdomains/endpoints you are authorized to test. Every host in `-l` becomes an exact scan-scope entry. The tool requires `--authorized` and will not follow redirects.

Local lab example:

```bash
./bin/opredir -d 'http://127.0.0.1:5000/redirect' \
  -dl 500ms \
  -t 4 \
  --authorized \
  --parameters data/demo_parameters.txt \
  --family http_https_scheme_or_absolute_url \
  --max-cases 20
```

List example (`targets.txt`):

```text
# authorized subdomains and endpoints
api.example.test
https://app.example.test/login?next=/home
http://127.0.0.1:5000/redirect
```

```bash
./bin/opredir -l targets.txt -dl 1s -t 2 --authorized --max-cases 100
```

The scan performs three steps: generate test cases, send bounded HTTP requests, then classify captured responses. By default it writes:

- `opredir-cases.jsonl`
- `opredir-responses.jsonl`
- `opredir-findings.jsonl`

Useful scan options:

```text
-d DOMAIN                 One domain or endpoint URL (mutually exclusive with -l)
-l FILE                   Subdomains/endpoints list (mutually exclusive with -d)
-dl DURATION              Minimum delay between request starts; default 500ms; 0 disables
-t N                      Concurrent HTTP workers; default 4; range 1..100
--authorized              Required acknowledgement for active testing
--parameters FILE         Default data/parameters.txt
--corpus FILE             Default data/payloads/url_value_candidates.json
--vars-json FILE          Runtime placeholder values
--attacker-host HOST      Default opredir-marker.invalid
--allowed-host HOST       Override ALLOWED_HOST; otherwise target host is used
--family NAME             Repeatable payload family filter
--mode MODE               auto|append|replace-all|replace-first
--max-cases N             Default 500; maximum 5000 active requests
--concurrency N           Alias for -t; default 4; maximum 100
--delay DURATION          Alias for -dl
--rate N                  Optional additional cap in requests/second; 0 disables
--timeout DURATION        Default 10s
--header 'Name: value'    Repeatable additional header
--cookie 'name=value'     Repeatable cookie value
--tls-insecure            Explicitly skip TLS verification (not recommended)
--cases-out FILE          Default opredir-cases.jsonl
--responses-out FILE      Default opredir-responses.jsonl
--out FILE                Findings output; default opredir-findings.jsonl
```

The default `opredir-marker.invalid` is a reserved non-resolving marker hostname suitable for checking reflected `Location` values. For tests that require DNS or browser navigation to reach a destination, use an attacker-controlled hostname and configure payload placeholders in `--vars-json`.

## 2. Verify previously captured responses

The scan command verifies automatically. When using the lower-level `request` command, run:

```bash
./bin/opredir verify --in responses.jsonl --out findings.jsonl
```

The Verification Engine applies conservative classifications:

- `confirmed_open_redirect`: a 3xx `Location` resolves to a different hostname and matches the external host supplied in the test value.
- `confirmed_refresh_redirect`: a `Refresh` response header directs to the matching external test host.
- `external_redirect_unconfirmed`: an external redirect exists but is not correlated with the supplied test destination; manual review is required.
- `same_origin_redirect` / `same_host_redirect`: same-origin or same-host navigation; not confirmed as Open Redirect.
- `reflected_input_only`: the test value appears in the body without proven navigation.
- `client_side_redirect_candidate`: a body navigation signal exists; browser verification is required.
- `no_redirect_observed`, `redirect_without_location`, `invalid_location`, `request_error`: no confirmed vulnerability.

The verifier deliberately does not follow redirects. It resolves relative `Location` values against the request URL. It uses Go's `net/url` parser; Browser/WHATWG parsing differences, complex IDN normalization, multi-hop redirect chains, and DOM data-flow are not fully verified yet.

## 3. Generate test cases only (no network traffic)

Use `--parameters data/demo_parameters.txt` to test only the `url` parameter in the local training lab:

```bash
./bin/opredir generate \
  --url 'http://127.0.0.1:5000/redirect' \
  --parameters data/demo_parameters.txt \
  --attacker-host 'redirect-marker.invalid' \
  --family http_https_scheme_or_absolute_url \
  --max-cases 10 \
  --out generated-cases.jsonl
```

The default corpus is the cleaned set of 724 Query-Parameter URL-value candidates. The full parameter file is editable; add one parameter name per line to `data/parameters.txt`. To filter payload families, repeat `--family`.

Useful options:

```text
--url URL                  Repeatable target endpoint
--urls-file FILE           One target URL per line
--parameters FILE          Parameter wordlist
--corpus FILE              URL-value JSON corpus
--vars-json FILE           Placeholder values as a JSON object
--attacker-host HOST       Set ATTACKER_HOST
--allowed-host HOST        Set ALLOWED_HOST
--family NAME              Repeatable exact family filter
--mode auto|append|replace-all|replace-first
--max-cases N              Default 10000; maximum 200000
--out FILE                 Default generated-cases.jsonl
```

The default mode replaces all existing exact-key occurrences; if none exists it appends the parameter. Unrelated query segments and their order are preserved. URL fragments are omitted because browsers do not send fragments in HTTP requests.

## 4. Send generated cases (active network traffic)

Only run against an authorized target. The command requires both `--authorized` and one or more `--scope-host` values. A scope rule is either an exact hostname (for example `127.0.0.1`) or a wildcard subdomain (for example `*.example.test`; it does not match the apex `example.test`).

Local training lab example:

```bash
./bin/opredir request \
  --cases generated-cases.jsonl \
  --authorized \
  --scope-host 127.0.0.1 \
  -t 2 \
  -dl 500ms \
  --timeout 10s \
  --max-requests 20 \
  --out responses.jsonl
```

Safe defaults and limits:

- 500 requests maximum by default (hard cap 5000 per invocation).
- 4 concurrent workers by default.
- 500ms minimum delay between consecutive request starts by default.
- 10-second per-request timeout.
- Response body preview capped at 4 KiB by default (maximum configurable cap 1 MiB).
- All requests are preflighted before network traffic begins.
- The generated request URL must retain the exact scheme, hostname and effective port of its target URL.
- HTTP redirects are returned as responses; the client does not follow `Location`.
- Only selected response headers are retained. Cookie values are not copied into the evidence output.

Options:

```text
--cases FILE               Generated JSONL input (required)
--authorized               Explicit authorization acknowledgement (required)
--scope-host HOST          Exact hostname or *.subdomain rule (repeatable, required)
-t N                       1..100; default 4 (concurrent workers)
-dl DURATION               Minimum delay between request starts; default 500ms
--concurrency N            Alias for -t
--delay DURATION           Alias for -dl
--rate N                   Optional additional cap in requests/second; 0 disables
--timeout DURATION         Default 10s
--max-requests N           1..5000; default 200
--max-body-bytes N         0..1048576; default 4096; 0 disables body preview
--header 'Name: value'     Repeatable; Host/Content-Length/Cookie are protected
--cookie 'name=value'      Repeatable; combined into one Cookie header
--user-agent VALUE         Default opredir/0.4.0
--tls-insecure             Explicitly skip TLS verification (not recommended)
--out FILE                 Default responses.jsonl
```

The response JSONL includes case ID, request URL, status, `Location`, selected headers, duration, remote address, bounded body preview, and any request error. Results can complete out of order under concurrency; correlate them using `case_id`.

Evidence files can contain response content from authenticated sessions. Store them securely and redact before sharing.

## Data layout

```text
opredir/
├── cmd/opredir/                 CLI entry point
├── internal/model/              JSON data structures
├── internal/generator/          parameter/payload combination logic
├── internal/requester/          scoped HTTP request engine
├── data/parameters.txt          editable parameter list
├── data/payloads/               cleaned payload corpus and research extensions
├── docs/                         research and cleanup notes
├── examples/                     sample input files
└── go.mod
```

## Scope and limitations

The `scan` workflow currently focuses on Query-Parameter candidates and first-response HTTP verification. The verifier parses `Location`, resolves relative destinations, compares the destination host with the tested value, recognizes `Refresh`, and distinguishes reflection from navigation candidates. Browser-only/DOM redirects still need a separate browser verification module. It does not enumerate subdomains: supply those explicitly with `-l`.
