# Open Redirect Payload Arsenal — Cleanup V3 Report

Generated: 2026-10-31

## Decision

The original v2 corpus is preserved byte-for-byte as reference. This cleanup creates a single-use classification for each of its 1003 records. Classification is not proof that a payload works.

## Partition of the 1,003 source records

| Record type | Count | Default handling |
|---|---:|---|
| URL-value candidates | 724 | Eligible for normal authorized Query-Parameter tests |
| Raw-control transport probes | 5 | Separate transport-specific tests; not in default wordlist |
| Request-context templates | 80 | Feed into request builder, never as a parameter value |
| Client-side navigation / special-scheme probes | 36 | Separate browser/client-side finding class |
| Header-injection probes | 4 | Separate vulnerability class |
| Internal-host negative controls | 3 | Use for negative/control checks, not external-marker positives |
| Corrupt Unicode quarantine | 151 | Preserve raw; do not use as valid IDN payloads |
| **Total** | **1003** | |

## What was corrected

1. Preserved all 946 legacy payload records exactly as they existed in v2.
2. Retained all 57 extension records and kept their `untested` state.
3. Standardized old records with `status=untested`, `confidence=candidate`, and an explicit `record_type`.
4. Excluded 151 strings containing U+FFFD from the active corpus. These strings cannot be safely reconstructed from the damaged character.
5. Moved request-context examples out of the URL-value list.
6. Moved `javascript:` / `data:`-style sink cases to a client-side navigation collection.
7. Moved CRLF / header-name injection cases to a separate collection.
8. Moved literal tabs/newlines into a special-transport collection.
9. Moved `localhost` cases into a negative-control collection.
10. Built `url_value_candidates.txt` from `templated_payload` values, so known sample attacker hosts are not used as live destinations. Resolve placeholders only to tester-controlled infrastructure.

## Important distinction

`url_value_candidates.json` contains **724 candidate values**, not 724 confirmed bypasses. Some values are deliberately malformed to exercise parser behavior. Some may be rejected by the HTTP client, normalized by a framework, or interpreted differently by a browser. Each remains `untested` until exercised against a named fixture and parser/browser version.

## Integrity checks performed

- JSON syntax validated for the master and extension data.
- 1,003 records, 1,003 unique IDs, and 1,003 unique exact source strings.
- Original 946 records compared object-for-object with the first 946 v2 records.
- All 1,003 records assigned to exactly one output category.
- Active corpus contains no U+FFFD, no literal control bytes, no request-context entries, and no client-side special-scheme family records.
- All runtime placeholders checked against the documented contract.
- HPP (10), transformation recipes (12), and verification fixture (10) counts checked.

## What was not done

No targets were scanned. No payload was marked as working. No browser/backend parser behavior was inferred from Python's URL parser. This stage is data cleanup and structural validation only.

## Recommended next stage

Build the Payload Generator and request serializer around the cleaned `url_value_candidates.json`, with support for one transformation at a time, ordered duplicate query parameters, safe scope checks, disabled redirect following on the first request, and a tester-controlled marker host.
