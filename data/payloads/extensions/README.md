# Open Redirect Pack v2 Extensions

This extension preserves the original 946-record corpus and adds curated, context-aware candidates.

## What was added

- `57` new URL-value test records in `payloads/master_all_v2.json` (original records remain first and unchanged).
- New families: domain allowlist/boundary checks, fake-relative URL semantics, Unicode/IDNA normalization, parser control characters, and runtime-generated IP representations.
- Query Parameter Pollution (HPP) request templates in `query_parameter_pollution_cases.json`. These are request-construction scenarios, not ordinary payload values.
- Transformation recipes in `transformation_recipes.json`; they define controlled transformations instead of exploding the corpus into every combination.
- Verification cases in `verification_cases.json`, including negative controls and client-side/separate-vulnerability classifications.
- A placeholder contract and a CSV coverage matrix.

## Important behavior

All new records have `status: untested`. They are candidates, not confirmed bypasses. The result depends on application decoding, framework validator, redirect implementation and browser URL parser.

The IP cases are symbolic templates. Generate all numeric notations from the same tester-controlled address. Never use fixed public IPs as callback targets.

Unicode invisibles, line separators, tabs and newlines are parser/validation probes. Some are invalid as URLs, and some HTTP clients reject raw controls. Use transport-level query serialization, retain the exact bytes/value seen by the application, and record the decoding stage.

HPP must use an ordered query representation that preserves duplicate keys. Do not turn the query into a dictionary.

## Sources informing the added categories

- PortSwigger URL Validation Bypass Cheat Sheet: https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet
- PortSwigger research introduction: https://portswigger.net/research/introducing-the-url-validation-bypass-cheat-sheet
- PortSwigger update on IP representations and parser discrepancies: https://portswigger.net/research/new-crazy-payloads-in-the-url-validation-bypass-cheat-sheet
- WHATWG URL Standard: https://url.spec.whatwg.org/
- OWASP Unvalidated Redirects and Forwards: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
- PayloadsAllTheThings Open Redirect: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect

## How to run the added cases

1. Load `payloads/master_all_v2.json` as the canonical extended corpus.
2. Resolve runtime placeholders from tester-controlled test infrastructure.
3. Apply one transformation recipe at a time. Record whether the application performs zero, one or multiple decoding passes.
4. Use HPP templates with an ordered query builder.
5. Send the first request with redirect following disabled.
6. Parse `Location` using WHATWG-compatible behavior and compare the final normalized origin to the explicit allowlist.
7. Keep browser-only redirects, `javascript:`/`data:`, and CRLF/header injection as separate finding types.
8. Run only on explicitly authorized targets with rate limits and scope controls.
