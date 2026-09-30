# Security Policy

## Reporting a vulnerability

fw-diff is a security tool; vulnerabilities in it are treated seriously.

- **Report privately:** open a GitHub [security advisory](https://github.com/Zlo/fw-diff/security/advisories/new)
  (preferred) or email the address on the repository profile (PGP available on request).
- **Do not** open a public issue for suspected vulnerabilities.
- Please include: affected version, reproduction (especially crafted inputs — we will treat
  them confidentially), and impact assessment.

## Scope

**In scope:** Ghidra-worker sandbox escapes, ingest/unpack path traversal or resource-cap
bypass, `facts.json`/policy tampering vectors, LLM guardrail bypass (injection affecting CI
decisions), secrets/telemetry leaks, dependency/build integrity issues.

**Out of scope:** crashes in *trusted in-process mode* with obviously malformed local files
(still welcome as bugs, just not security issues), spoofed reports not produced by fw-diff,
the analyzed firmware's own vulnerabilities (that's our users' job — our output is hypotheses).

## Handling

- Acknowledgment within 72h; triage within 7 days
- Coordinated disclosure, 90-day default embargo (shorter/longer by agreement)
- Credit unless you prefer anonymity; CVE requested for exploitable issues
- Fixes release per [docs/release-process.md](docs/release-process.md) hotfix flow

## Supported versions

| Version | Supported |
|---|---|
| latest 0.x minor | yes |
| older | security fixes best-effort until v1.0 policy (release-process §5) |

## Hardening notes for operators

Run `fw-diff ci` (container mode) on untrusted images — never in-process mode. See
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and the runbook hardening section.