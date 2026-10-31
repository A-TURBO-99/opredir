# opredir Verification Engine (integrated)

## Inputs

The verifier consumes `ResponseRecord` JSONL produced by the HTTP request engine. Each record carries the original target/request URL, the parameter name, payload ID, resolved payload value, HTTP status, `Location`, selected response headers, and bounded body preview.

## Decision model

1. A transport error becomes `request_error`.
2. A 3xx response with a `Location` header is parsed and resolved against the request URL.
3. Same-origin and same-host redirects are not confirmed as Open Redirects.
4. A destination is `confirmed_open_redirect` only when its hostname differs from the target hostname and matches the external hostname represented by the test payload.
5. An unrelated external `Location` is `external_redirect_unconfirmed`; fixed login/SSO redirects can produce this result and require manual review.
6. A matching browser-recognized `Refresh` header is `confirmed_refresh_redirect`.
7. A body containing the test value without navigation evidence is `reflected_input_only`.
8. A body containing the test value and a navigation-looking sink is `client_side_redirect_candidate`; it is never confirmed without a browser.

## Important limits

- Redirects are not followed. Redirect chains are therefore not evaluated.
- URL parsing currently uses Go `net/url`, not a complete WHATWG browser implementation.
- Complex IDN/Unicode normalization and alternate numeric-IP canonicalization can produce inconclusive results.
- Client-side JavaScript data flow is heuristic only; a browser module is required for confirmation.
- A destination can be open in the technical sense but business-approved by the application. Review allowlists and intended behavior before reporting.

## JSONL output

Each finding includes classification, confirmed flag, confidence, evidence type, target/request URL, parameter, payload ID, resolved payload, raw and resolved destination, reason, and whether a redirect was followed (always false in this version).


The verifier runs automatically as part of the primary `opredir -d ...` / `opredir -l ...` workflow. It is an internal engine, not a standalone CLI subcommand.
