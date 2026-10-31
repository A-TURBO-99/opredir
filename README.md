# opredir

**Open Redirect Scanner** · by **A-TURBO-99**  
Repository: https://github.com/A-TURBO-99/opredir

`opredir` is a Go-based Open Redirect testing tool. Version **0.4.3** includes the live terminal UI, a conservative HTTP Verification Engine, and detailed JSON reporting.

> Use only against systems you own or are explicitly authorized to test. The scanner derives its exact host scope from `-d` or the entries in `-l`; each generated request must preserve the target URL's scheme, hostname, and effective port. HTTP redirects are never followed.

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
./opredir -d https://example.com -dl 500ms -t 4 -o report.json
```

Scan a list of subdomains/endpoints (`targets.txt`, one item per line):

```bash
./opredir -l targets.txt -dl 1s -t 5 -o findings.json
```

A bare hostname defaults to HTTPS. Include a scheme when using HTTP or a non-default port, for example `http://127.0.0.1:5000/redirect`. Blank lines and `#` comments in target files are ignored; duplicate targets are removed. `-d` does not enumerate subdomains.

## Main options

| Option | Description | Default |
|---|---|---|
| `-d DOMAIN` | One domain or endpoint URL | — |
| `-l FILE` | File containing subdomains/endpoints | — |
| `-dl DURATION` | Minimum delay between request starts; `0s` disables | `500ms` |
| `-t N` | Concurrent HTTP workers (`1..100`) | `4` |
| `-o FILE` | Detailed JSON report path | `opredir-report.json` |
| `--quiet` | Plain-text confirmed findings only; suppress banner/progress/summary | off |
| `--json` | Confirmed findings and final summary as JSONL on stdout | off |
| `--max-cases N` | Maximum test requests (`1..5000`) | `500` |
| `--parameters FILE` | Parameter names wordlist | `data/parameters.txt` |
| `--corpus FILE` | URL-value payload corpus | `data/payloads/url_value_candidates.json` |
| `--family NAME` | Filter payload family; repeatable | all eligible |
| `--mode MODE` | `auto`, `append`, `replace-all`, `replace-first` | `auto` |
| `--vars-json FILE` | Runtime placeholder values | — |
| `--attacker-host HOST` | Value for `ATTACKER_HOST` | `opredir-marker.invalid` |
| `--allowed-host HOST` | Override `ALLOWED_HOST` placeholder | target hostname |
| `--timeout DURATION` | Per-request timeout | `10s` |
| `--header 'Name: value'` | Additional request header; repeatable | — |
| `--cookie 'name=value'` | Cookie value; repeatable | — |
| `--tls-insecure` | Skip TLS certificate verification (not recommended) | off |

The `--authorized` and `--scope-host` command-line options are not used. Scope is derived automatically from the targets supplied with `-d` or `-l`. The old `--verbose` mode is removed: the normal interface displays **confirmed findings only**.

## Terminal output

On a normal scan, the banner and Scan Plan appear first, followed by loading/progress updates. Each verified result is streamed immediately in this format:

```text
✖ VULNERABLE   https://example.com/redirect?next=...
                payload: https://opredir-marker.invalid/landing
                param:   next
                status:  302 → https://opredir-marker.invalid/landing
```

Clean responses, reflections, same-host redirects, and uncorrelated external redirects are not printed as findings. The final summary includes request count, confirmed findings, duration, and the report path.

`--quiet` emits one plain-text line per confirmed finding. `--json` emits JSONL finding events and a summary event. Those modes are mutually exclusive. Colors are detected automatically and disabled when output is not an interactive terminal, `NO_COLOR` is set, or `TERM=dumb`.

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

The Verification Engine confirms a finding only when a 3xx `Location` or recognized `Refresh` destination points to an external hostname matching the destination supplied in the tested parameter. It resolves relative `Location` values against the request URL and does not follow redirects.

The current scanner primarily generates Query-Parameter GET cases. Browser-only/DOM-based redirects need browser verification and are not reported as confirmed. It also does not enumerate subdomains; provide them explicitly in `-l`. Browser WHATWG parsing differences, complex IDN normalization, and multi-hop redirect chains are not fully covered.

## Advanced subcommands

Generate test cases without sending network traffic:

```bash
./opredir generate \
  --url 'https://example.com/redirect' \
  --parameters data/parameters.txt \
  --out generated-cases.jsonl
```

Send existing cases and save raw response evidence (host scope is derived from each case's `target_url`):

```bash
./opredir request \
  --cases generated-cases.jsonl \
  -t 4 -dl 500ms \
  --out responses.jsonl
```

Verify saved responses independently:

```bash
./opredir verify --in responses.jsonl --out findings.jsonl
```

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
├── internal/requester/   Bounded HTTP request engine
├── internal/verifier/    Redirect verification and classification
├── internal/ui/          Terminal banner, progress and finding output
├── data/                 Parameters and payload corpus
├── docs/                 Design and validation notes
└── go.mod
```
