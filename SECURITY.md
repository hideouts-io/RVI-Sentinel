# Security Policy

## Supported versions

RVI-Sentinel currently develops from the default branch rather than maintaining numbered release lines.

| Version | Supported |
|---|---|
| Latest `main` revision | Yes |
| Older commits, forks, and modified builds | No |

Before reporting a problem, reproduce it against the latest `main` revision when practical.

## Reporting a vulnerability

Do not disclose a suspected vulnerability in a public issue, discussion, pull request, capture, or log attachment.

Use GitHub's [private vulnerability reporting form](https://github.com/hideouts-io/RVI-Sentinel/security/advisories/new). Include:

- the affected revision, platform, and component;
- a concise description of the security impact;
- reproducible steps using synthetic or sanitized data;
- the conditions required to trigger the problem;
- sanitized logs or stack traces, if useful; and
- a suggested mitigation or fix, if known.

Do not submit private packet captures, real endpoint or hostname inventories, device identifiers, credentials, access tokens, private keys, or personal data. If reproducing the issue requires sensitive evidence, describe the evidence category first and wait for maintainers to agree on a safe transfer method.

Maintainers aim to acknowledge a complete report within seven days and provide a status update at least every fourteen days while the report remains active. Resolution timing depends on severity, reproducibility, affected platforms, and upstream dependencies.

## Appropriate security reports

Examples include:

- command or argument injection;
- unsafe file handling, path traversal, or unintended overwrite behavior;
- unintended disclosure of captures, reports, baselines, endpoint data, or credentials;
- unsafe privilege, device-trust, or process-boundary behavior;
- a dependency vulnerability with a demonstrated impact on RVI-Sentinel; or
- a bypass of a documented security or privacy boundary.

The following are not RVI-Sentinel vulnerabilities by themselves:

- a newly observed endpoint, hostname, port, or high-entropy DNS label;
- expected metadata visibility in an authorized packet capture;
- the inability to decrypt TLS, QUIC, VPN, Private Relay, encrypted DNS, ECH, or application-layer encryption;
- a vulnerability that exists only in an independently maintained upstream project without an RVI-Sentinel-specific impact; or
- findings from a network or device you are not authorized to inspect.

Report upstream-only vulnerabilities to the relevant upstream maintainer. If an upstream issue creates a concrete RVI-Sentinel risk, report that impact privately here as well.

## Coordinated disclosure

Please allow maintainers a reasonable opportunity to investigate, develop a fix, and coordinate with affected upstream projects before public disclosure. Maintainers will credit reporters when requested and when doing so does not expose private information.
