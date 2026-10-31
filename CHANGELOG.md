# Changelog

## [0.5.0] - 2026-10-31

- Added cumulative `--level 1|2|3` payload coverage to `scan` and `generate` (first third, first two thirds, or the full corpus).
- Removed `--max-cases`; active scans and case generation now process the full selected parameter/payload matrix.
- Confirmed findings are displayed as text by default; added `-hide` to suppress finding details on screen while retaining them in the `-o` report.
- Removed the `--family` and `--mode` filters; payload selection is controlled by `--level` and query-parameter placement is automatic.
- Removed `--tls-insecure`; TLS certificate verification is always enabled.
- Updated the payload generator, request engine, CLI help, README, and regression tests for the revised behavior.

## [0.4.3] - 2026-10-31

- Standardized the release package for Linux amd64 only; removed the Windows executable and Windows cross-build references from current release validation.

- Removed the `--authorized` and `--scope-host` CLI options. Active-scan scope is still enforced internally from `-d` / `-l` targets, and each request URL must preserve the target authority.
- Removed `--verbose`; default terminal output now shows confirmed Open Redirect findings only.
- Connected the banner, Scan Plan, progress display, and streaming findings to the real scan workflow.
- Added `-o FILE` / `--output FILE` for a detailed JSON report containing confirmed findings and supporting evidence only.
- Added `-param NAME|FILE` to test one named parameter or load a selected parameter list in both `scan` and `generate` workflows.
- Added tests for literal parameter selection and file-based parameter selection.
- Added `requester.RunWithCallback` for immediate verification and live output as responses complete.
- Added tests for callback delivery, target-derived scope, and confirmed-only UI output.

## [0.4.2] - 2026-10-31

- Set the Go module path to `github.com/A-TURBO-99/opredir`.
- Updated internal imports for canonical GitHub module installation.
- Added Git clone/build instructions and optional `go install` instructions.


## 0.4.1 - Terminal UI preview

- Added a separate terminal UI/output package in `internal/ui`.
- Added `opredir ui-demo` with mock targets, payloads, streaming findings, progress display, summary and a clearly marked demo HTML report.
- Added `--quiet`, `--json`, `--verbose`, `--width`, and `--report` options to the UI preview command.
- Added terminal color detection (`NO_COLOR`, `TERM=dumb`) and disabled in-place progress updates for non-interactive output.
- Kept the real `scan` workflow unchanged; UI-to-scanner integration is the next stage.

## 0.4.0

- Standardized scan flags: `-d` selects one domain/endpoint, `-l` selects a target list, `-dl` sets the minimum delay between request starts, and `-t` sets concurrent HTTP workers.
- Renamed the short delay option from `-d` to `-dl` to avoid collision with the domain option.
- Kept `-u` as a legacy alias for `-d`; long aliases `--domain`, `--list`, `--delay`, `--threads` and `--concurrency` remain available.
- Updated help text, README examples, and version metadata.

## 0.2.0

- Added `opredir -d DOMAIN` and `opredir -l FILE` scan workflows.
- Added target normalization for bare domains, subdomains and full HTTP(S) endpoints.
- Added a Verification Engine for 3xx `Location` and `Refresh` response navigation.
- Added conservative finding classifications for confirmed redirects, unconfirmed external redirects, same-origin/same-host redirects, reflection-only responses and client-side candidates.
- Added `opredir verify --in responses.jsonl` for previously captured response files.
- Added `payload_resolved` and payload-family evidence to response records.
- Added tests for target-list loading and Verification Engine classification.
- Active requests still require `--authorized`; scan scope is derived from `-d` or exact hosts in `-l`; redirects are never followed.

## 0.1.0

- Initial Go CLI, payload generator and bounded HTTP request engine.
