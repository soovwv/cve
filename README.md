# cve

Write-ups for vulnerabilities I reported, one file per identifier.

| Identifier | Product | Issue |
|---|---|---|
| [CVE-2026-119978](CVE-2026-119978.md) | Flowise `<= 3.1.4` | Custom Function dependency allowlist still reaches host code execution after the fix for CVE-2026-73483 |

Reports are local static analysis of public source, reproduced against containers I
started myself. No third-party deployment was contacted.

Working payloads and reproduction harnesses are not published here. Maintainers,
defenders and CNAs can have the full material on request.
