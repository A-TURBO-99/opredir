# Open Redirect AI Integration Pack

Generated: 2026-10-31

## What is included

- `payloads/master_all_raw.txt`: one de-duplicated exact-string corpus combining the previous 440-item merged list and the user's supplied 513-line list.
- `payloads/master_all_templated.txt`: the same corpus with common example domains replaced by runtime placeholders where safe to do so.
- `payloads/master_all.json`: structured corpus with IDs, multi-label families, source attribution, and templated variants.
- `payloads/by_family/`: overlapping family-specific wordlists. A payload may intentionally occur in several files.
- `payloads/user_supplied_513_exact.txt`: user's supplied list in original order, without normalization.
- `raw_sources/user_supplied_513_original.txt`: byte-preserving copy of the uploaded source file.
- `raw_sources/previous_440_wordlist_original.txt`: prior merged list preserved as supplied.
- `raw_sources/payloadbox_411_original.txt` and `raw_sources/LICENSE-PayloadBox.txt`: source subset and its license.
- `contexts/query_path_contexts_previous.txt`: full query/path examples; not intended for blind insertion as a parameter value.
- `parameters/redirect_parameter_candidates.txt`: possible parameter names; these are not payload values.
- `payloads/sink_specific_javascript_data.txt`: JavaScript/data URI test inputs; classify separately from ordinary HTTP(S) Open Redirect.
- `payloads/separate_crlf_header_injection.txt`: CRLF/header-injection probes; report separately.

## Counts

The previous merged list has 440 exact unique values. The supplied list has 513 non-empty lines and 513 exact unique strings. There are 7 exact-string overlaps. The combined exact-string corpus therefore contains 946 unique entries. These are test candidates, not 946 distinct or guaranteed bypasses.

The 411-entry PayloadBox base list is already contained in the previous merged 440-list; it is included separately only for provenance/license traceability, not counted again.

## Placeholder contract

The templated file uses:

- `{{ATTACKER_HOST}}`: a controlled external hostname used to verify whether the browser navigates off-site.
- `{{ALLOWED_HOST}}`: the hostname the application intends to allow.
- `{{ATTACKER_IPV4}}`: a controlled test IPv4 address.
- `{{ATTACKER_IPV4_DECIMAL}}` and `{{ATTACKER_IPV4_HEX}}`: alternate numeric forms of that same test IPv4 address.

Generate numeric IPv4 forms from the same configured address; do not hard-code a public third-party IP as the callback destination. Some entries from the user's source contain an intentionally obfuscated Unicode hostname that includes U+FFFD (replacement character). It is preserved verbatim in the raw files; do not silently repair or treat it as a valid IDN. Build deliberate Unicode/IDNA cases separately when needed.

## Integration rules for the scanner

1. Inspect the existing codebase, architecture, language, tests, and file conventions before editing. Do not overwrite unrelated files.
2. Keep raw corpus data separate from endpoint/parameter discovery and from query/path request templates.
3. Use URL-value payloads only at a URL-valued injection point. Use full query/path contexts only in a request-template layer that knows the endpoint and parameter name.
4. Replace placeholders at runtime using a hostname controlled by the tester and the target's actual allowed hostname. Correctly URL-encode the value for the specific request parameter exactly once; do not pre-encode blindly or double-decode without modelling the application's behavior.
5. Keep family tags and source IDs so findings can be traced to the payload and variant family.
6. Send the initial request with redirect following disabled. Record status code, raw `Location` header, parsed destination, response body, and redirect chain. Do not infer success from a 3xx response or reflected input alone.
7. Confirm the final navigation using a standards-compliant browser/URL parser or an isolated browser test. Compare the actual final origin (scheme, host, effective port) with the target origin and the configured allowed set.
8. Treat relative same-origin redirects as not open redirects. Treat `javascript:` and `data:` as separate client-side navigation/XSS sink tests, not ordinary HTTP(S) Open Redirect results. Treat CRLF/header injection as a separate finding class. Do not turn these into Open Redirect positives.
9. Duplicate query parameters (HPP) require a request builder that sends duplicate keys in the intended order. Do not flatten them into a single dictionary value.
10. Record negative results and parser/environment metadata (runtime/framework, browser, decode count, normalization) to make results reproducible.
11. Apply rate limits, timeouts, concurrency caps, and scope checks. Never send tests to domains or accounts outside explicit authorization.
12. Avoid claiming all entries are known-working bypasses. Many are parser-specific, malformed, legacy, or sink-specific probes.

## Attribution and license

The PayloadBox base corpus is distributed under the MIT License; see `raw_sources/LICENSE-PayloadBox.txt`. The 411 PayloadBox strings are included in the prior merged list. Other previous supplemental cases were authored for this pack. The user's supplied 513-line text is included verbatim as user-provided material. PortSwigger's URL Validation Bypass Cheat Sheet is listed as a research reference only, not copied into this pack.

## Research references

- PayloadBox Open Redirect Payload List: https://github.com/payload-box/open-redirect-payload-list
- PayloadsAllTheThings Open Redirect: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect
- PortSwigger URL Validation Bypass Cheat Sheet: https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet
- WHATWG URL Standard: https://url.spec.whatwg.org/
- OWASP Unvalidated Redirects and Forwards Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
- OWASP WSTG Client-side URL Redirect: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect


## Extended v2 corpus

See `payloads/master_all_v2.json` and `payloads/extensions/` for additional context-aware test candidates. The original `payloads/master_all.json` (946 records) is preserved unchanged. The extension adds parser/hostname/IDNA/IP cases, fake-relative URL probes, control-character cases, HPP request templates, transformation recipes, and verification/negative-control fixtures. See `payloads/extensions/README.md` for exact counts and operational caveats.
