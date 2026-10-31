# HTTP Request Engine — V1

## Responsibilities

The request engine has one job: send pre-generated test cases to the exact endpoint authority supplied by the user and capture the first response as bounded evidence. It does **not** classify a response as an Open Redirect.

## Execution sequence

1. Read JSONL test cases (maximum 5,000 per invocation).
2. Require an explicit authorization acknowledgement and at least one scope-host rule.
3. Validate every case before sending any request:
   - `target_url` and `request_url` must be absolute HTTP(S) URLs.
   - URL credentials and request fragments are rejected.
   - Request scheme, hostname and effective port must match the original target URL.
   - The target hostname must match an exact scope rule or a `*.example.com` subdomain rule.
4. Start a bounded worker pool.
5. Apply a global rate limiter before each request.
6. Send the request with a per-request timeout.
7. Capture status, `Location`, selected response headers, duration, remote socket address and a bounded body preview.
8. Serialize one JSONL record per test case.

## Redirect behavior

`http.Client.CheckRedirect` always returns `http.ErrUseLastResponse`. A `301`, `302`, `303`, `307` or `308` is returned to the engine as the first response. The engine never follows the `Location` header in this phase; that is essential so the verification phase can inspect the untrusted destination without making a second request to it.

## Evidence and privacy

The output intentionally does not store request Authorization headers, request cookies or response `Set-Cookie` values. Only a short allowlist of response headers is retained. The body preview defaults to 4 KiB and can be disabled with `--max-body-bytes 0`. Treat output files as sensitive when authenticated target sessions are used.

## Scope model

`--scope-host` accepts exact hostnames/IPs or wildcard subdomain rules. A wildcard such as `*.example.com` matches `a.example.com` but not the apex `example.com`. URL authority validation is separate: even an in-scope host is rejected if the generated request URL changes the target scheme, hostname or effective port from the original `target_url`.

The scope check is a guardrail, not proof of authorization. The operator remains responsible for confirming written permission and program scope before running active tests.

## Known limitations

- The current generator produces Query-Parameter GET test cases.
- The request engine can send a method and request body if present in a JSONL test case, but there is not yet a general form/body parameter discovery module.
- Duplicate Query Parameter test templates are preserved as separate research data; a dedicated ordered HPP case generator is still pending.
- Redirect classification, relative `Location` resolution, origin/allowlist comparison and redirect-chain analysis are not implemented yet.
- JavaScript/DOM redirects require a future browser-based engine.
