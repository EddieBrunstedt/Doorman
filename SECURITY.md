# Security policy

The full security model — threat model, implemented guarantees, defaults, and host hardening requirements — lives in [`docs/security.md`](docs/security.md). This file is the vulnerability-disclosure policy.

## Reporting a vulnerability

Please report security issues **privately** and give the maintainer a chance to ship a fix before any public disclosure.

- **Preferred:** open a private security advisory on the repository (<https://codeberg.org/EddieBrunstedt/Doorman>) if the platform exposes the advisory workflow.
- **Otherwise:** email `eddie.brunstedt@protonmail.com` with the details and a reproduction. Use a subject line that makes the security nature obvious.

Include the affected version, the impact, and steps to reproduce. You will get an acknowledgement; once a fix is available it will be released and the reporter credited unless they ask otherwise. Do not open a public issue or pull request for an unfixed vulnerability.

## Supported versions

doorman is pre-1.0. Only the latest published `0.x` release receives security fixes; there are no long-term-support branches before 1.0. Pin a version and upgrade forward to pick up fixes.

| Version      | Supported    |
| ------------ | ------------ |
| latest `0.x` | yes          |
| older `0.x`  | no — upgrade |
