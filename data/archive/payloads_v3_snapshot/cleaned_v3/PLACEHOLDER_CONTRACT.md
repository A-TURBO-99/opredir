# Extension Placeholder Contract

All destination markers must resolve to infrastructure controlled by the tester. Never substitute a third-party hostname or IP.

- `{{ATTACKER_HOST}}`: controlled external DNS hostname.
- `{{ALLOWED_HOST}}`: exact hostname the application intends to permit.
- `{{ATTACKER_IDN_UNICODE}}` / `{{ATTACKER_IDN_PUNYCODE}}`: Unicode and A-label form of the same tester-controlled IDN.
- `{{ATTACKER_IPV4}}`: controlled IPv4 in dotted-decimal form.
- `{{ATTACKER_IPV4_PARTIAL_A}}`, `{{ATTACKER_IPV4_PARTIAL_B}}`: generated partial-decimal forms of that same IPv4.
- `{{ATTACKER_IPV4_OCTAL}}`, `{{ATTACKER_IPV4_HEX}}`, `{{ATTACKER_IPV4_BINARY}}`: generated per-octet representations.
- `{{ATTACKER_IPV4_MIXED}}`: a documented mix of numeral systems for the same IPv4.
- `{{ATTACKER_IPV4_DWORD}}`, `{{ATTACKER_IPV4_DWORD_OVERFLOW}}`: generated 32-bit integer and overflow probes.
- `{{ATTACKER_IPV6_MAPPED}}`, `{{ATTACKER_IPV6_EXPANDED}}`: representations of the controlled IPv6 / IPv4-mapped address.
- `{{ATTACKER_URL}}`, `{{ALLOWED_URL}}`: complete URL values, serialized by the request builder.

Numeric-IP generation must be done by code from the configured controlled address. Validate that every generated form resolves to the same destination before testing.
