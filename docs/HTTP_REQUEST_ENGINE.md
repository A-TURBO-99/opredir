# HTTP Request Engine — V1

## Responsibilities

The request engine has one job: send pre-generated test cases to the exact endpoint authority supplied by the user and capture the first response as bounded evidence. It does **not** classify a response as an Open Redirect.

## Execution sequence

1. The root CLI generates the complete selected parameter/payload matrix and passes it to the request engine automatically. The optional `request` subcommand can replay an existing JSONL case file (bounded per invocation).
2. Derive an exact host allowlist from each case's `target_url`; no separate scope-host CLI option is needed.
3. Validate every case before sending any request:
   - `target_url` and `request_url` must be absolute HTTP(S) URLs.
   - URL credentials and request fragments are rejected.
   - Request scheme, hostname and effective port must match the original target URL.
   - The target hostname must match the exact host derived from that case's `target_url`; scope is not expanded to sibling subdomains.
4. Start a bounded worker pool.
5. Apply a global rate limiter before each request.
6. Send the request with a per-request timeout. TLS certificate verification remains enabled; there is no insecure TLS override.
7. Capture status, `Location`, selected response headers, duration, remote socket address and a bounded body preview.
8. Serialize one JSONL record per test case.

## Redirect behavior

`http.Client.CheckRedirect` always returns `http.ErrUseLastResponse`. A `301`, `302`, `303`, `307` or `308` is returned to the engine as the first response. The engine never follows the `Location` header; the integrated verification stage inspects the untrusted destination without making a second request to it.

## Evidence and privacy

The output intentionally does not store request Authorization headers, request cookies or response `Set-Cookie` values. Only a short allowlist of response headers is retained. The body preview defaults to 4 KiB and can be disabled with `--max-body-bytes 0`. Treat output files as sensitive when authenticated target sessions are used.

## Scope model

The scope is derived internally from the target URLs in the supplied cases. Each request URL must retain the exact scheme, hostname and effective port of its corresponding `target_url`. A user-supplied target file is therefore the explicit list of hosts to test; the request engine does not expand subdomains.

The derived scope check is a technical guardrail, not proof of authorization. The operator remains responsible for confirming written permission and program scope before running active tests.

## Known limitations

- The current generator produces Query-Parameter GET test cases.
- The request engine can send a method and request body if present in a JSONL test case, but there is not yet a general form/body parameter discovery module.
- Duplicate Query Parameter test templates are preserved as separate research data; a dedicated ordered HPP case generator is still pending.
- Redirect classification and relative `Location` resolution are handled by the Verification Engine. Multi-hop redirect-chain analysis is not implemented yet.
- JavaScript/DOM redirects require a future browser-based engine.
