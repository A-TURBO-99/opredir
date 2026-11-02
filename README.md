# opredir



**Open Redirect Scanner** · by **A-TURBO-99**  
Repository: https://github.com/A-TURBO-99/opredir

`opredir` is a Go-based Open Redirect testing tool. Version **0.5.1** runs the complete scan directly from the root command, includes three cumulative payload-coverage levels, live confirmed-finding output, automatic HTTP verification, and detailed JSON reporting.


## Installation

```bash
git clone https://github.com/A-TURBO-99/opredir.git
cd opredir
go build -o opredir ./cmd/opredir
```

Optional install into `$(go env GOPATH)/bin`:

```bash
go install github.com/A-TURBO-99/opredir/cmd/opredir@latest
sudo install -m 755 "$(go env GOPATH)/bin/opredir" /usr/local/bin/opredir
```

Supported runtime/distribution: Linux amd64. The project is packaged and tested for Linux only. Requirements for building from source: Go 1.23+. No third-party Go modules are required.

## Quick start

Scan one domain or endpoint:

```bash
./opredir -d https://example.com --level 1 -dl 500ms -t 4 -o report.json
```

Scan a list of subdomains/endpoints (`targets.txt`, one item per line):

```bash
./opredir -l targets.txt --level 2 -dl 1s -t 5 -o findings.json
```

Test only one query parameter:

```bash
./opredir -d https://example.com/redirect -param inject
```

Or test only the parameter names listed in a file:

```bash
./opredir -l targets.txt -param selected-parameters.txt
```

An existing regular file passed to `-param` is loaded as a wordlist; a non-path value such as `inject` is treated as one literal parameter name. When `-param` is omitted, the default `data/parameters.txt` wordlist is used (or the path supplied with `--parameters`).

### Payload coverage levels

`--level` controls how many payload records are selected from the ordered corpus. The levels are cumulative:

| Level | Payload records selected from the current 724-record corpus | Coverage |
|---|---:|---|
| `--level 1` | 242 | First third (default) |
| `--level 2` | 483 | First two thirds, including Level 1 |
| `--level 3` | 724 | Entire corpus |

The current default parameter list contains 169 names. Before placeholder-based records are skipped, that means up to 40,898, 81,627, or 122,356 generated requests per target, respectively. Records that require values not supplied through `--vars-json` are counted as `skipped_missing_placeholders` in the report's `generation_stats`; selecting Level 3 does not invent values for tester-controlled IP/IDN destinations.

The query placement strategy is automatic: if the target URL already contains the selected parameter, all matching occurrences are replaced; otherwise the parameter is appended. HTTP TLS certificate verification is always enabled.

A bare hostname defaults to HTTPS. Include a scheme when using HTTP or a non-default port, for example `http://127.0.0.1:5000/redirect`. Blank lines and `#` comments in target files are ignored; duplicate targets are removed. `-d` does not enumerate subdomains.

## Main options

| Option | Description | Default |
|---|---|---|
| `-d DOMAIN` | One domain or endpoint URL | — |
| `-l FILE` | File containing subdomains/endpoints | — |
| `--level N` | Payload coverage level (`1`, `2`, or `3`) | `1` |
| `-param NAME` | Test only the named parameter (for example, `-param inject`) | all parameters |
| `-param FILE` | Test only the parameter names listed in an existing file, one per line | — |
| `-dl DURATION` | Minimum delay between request starts; `0s` disables | `500ms` |
| `-t N` | Concurrent HTTP workers (`1..100`) | `4` |
| `-o FILE` | Detailed JSON report path | `opredir-report.json` |
| `-hide` | Hide confirmed findings on screen; keep them in the report | off |
| `--json` | Print confirmed findings and final summary as JSONL events | off |
| `--parameters FILE` | Default parameter names wordlist when `-param` is omitted | `data/parameters.txt` |
| `--corpus FILE` | URL-value payload corpus | `data/payloads/url_value_candidates.json` |
| `--vars-json FILE` | Runtime placeholder values | — |
| `--attacker-host HOST` | Value for `ATTACKER_HOST` | `opredir-marker.invalid` |
| `--allowed-host HOST` | Override `ALLOWED_HOST` placeholder | target hostname |
| `--timeout DURATION` | Per-request timeout | `10s` |
| `--rate N` | Additional maximum request rate (requests/second); `0` disables | `0` |
| `--max-body-bytes N` | Maximum response-body preview bytes; does not limit request count | `8192` |
| `--user-agent VALUE` | HTTP User-Agent | `opredir/0.5.1` |
| `--header 'Name: value'` | Additional request header; repeatable | — |
| `--cookie 'name=value'` | Cookie value; repeatable | — |

There is no scan-wide case-count cap: the root command generates and executes the complete matrix for the chosen payload level and parameter selection. The separate `request` subcommand retains `--max-requests` as a bounded control for replaying an existing JSONL case file.

The `--authorized` and `--scope-host` command-line options are not used. Scope is derived automatically from the targets supplied with `-d` or `-l`. The old `--verbose` option is removed. TLS certificate verification cannot be disabled from the CLI.

## Terminal output

On a normal run, the banner and Scan Plan appear first, followed by loading/progress updates. Confirmed findings are displayed as text by default and streamed immediately in this format:

```text
✖ VULNERABLE   https://example.com/redirect?next=...
                payload: https://opredir-marker.invalid/landing
                param:   next
                status:  302 → https://opredir-marker.invalid/landing
```

Clean responses, reflections, same-host redirects, and uncorrelated external redirects are not printed as findings. The final summary includes request count, confirmed findings, duration, and the report path.

Use `-hide` to suppress the finding details on screen; the full confirmed findings are still written to the JSON report selected by `-o`. The banner, scan progress, and final summary remain visible. `--json` emits JSONL finding events and a summary event instead of the formatted terminal interface. Colors are detected automatically and disabled when output is not an interactive terminal, `NO_COLOR` is set, or `TERM=dumb`.

## Detailed report (`-o`)

The report is JSON and contains scan metadata and **confirmed findings only**. Each finding includes:

- Target URL and exact request URL.
- Parameter name and resolved payload.
- Payload ID and payload families.
- HTTP status, raw `Location`, resolved destination, and expected destination.
- Verification classification, confidence, evidence type, and reason.
- Confirmation that the redirect was not followed.

Unconfirmed candidates and clean responses are deliberately omitted from the report so the file contains only verified results. The lower-level `request` command can still save raw response evidence separately when that is specifically needed.

## Verification model and limitations

The internal Verification Engine automatically checks each response and confirms a finding only when a 3xx `Location` or recognized `Refresh` destination points to an external hostname matching the destination supplied in the tested parameter. It resolves relative `Location` values against the request URL and does not follow redirects. Verification is part of the main run; there is no separate `verify` command.

The current scanner primarily generates Query-Parameter GET cases. When a parameter already exists in the target URL, all its matching occurrences are replaced; when absent, it is appended. Browser-only/DOM-based redirects need browser verification and are not reported as confirmed. It also does not enumerate subdomains; provide them explicitly in `-l`. Browser WHATWG parsing differences, complex IDN normalization, and multi-hop redirect chains are not fully covered.

## Additional utility command

Replay a previously generated JSONL test-case file and save raw response evidence:

```bash
./opredir request \
  --cases generated-cases.jsonl \
  -t 4 -dl 500ms \
  --out responses.jsonl
```

This is an optional replay feature. The normal workflow does not require pre-generated files: use `opredir -d ...` or `opredir -l ...` to generate, send, and verify test cases automatically.

Preview the terminal design using mock data only:

```bash
go run ./cmd/opredir ui-demo
```

`ui-demo` never sends network traffic and its findings are explicitly mock data.

## Development checks

```bash
gofmt -w ./cmd ./internal
go test ./...
go test -race ./...
go vet ./...
```

## Project layout

```text
opredir/
├── cmd/opredir/          CLI entry point
├── internal/model/       JSON data structures
├── internal/generator/   Parameter and payload generation
├── internal/requester/   Rate-controlled HTTP request engine
├── internal/verifier/    Redirect verification and classification
├── internal/ui/          Terminal banner, progress and finding output
├── data/                 Parameters and payload corpus
├── docs/                 Design and validation notes
└── go.mod
```
