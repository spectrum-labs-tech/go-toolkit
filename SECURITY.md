# Security Policy

## Supported versions

Only the latest release on the `main` branch receives security fixes.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report security issues by emailing **security@spectrumlabs.tech**. Include:

- A description of the vulnerability and its potential impact.
- Steps to reproduce or a minimal proof of concept.
- Any suggested fix, if you have one.

You can expect an initial response within 48 hours and a patch or mitigation
plan within 14 days for confirmed issues.

## Scope

This library provides JWT management and Gin middleware. Security issues in
scope include but are not limited to:

- Token forgery or bypass of signature verification.
- CSRF protection bypass.
- Incorrect enforcement of `iss`, `aud`, or `exp` claims.
- Auth cookie attributes that weaken security (missing `HttpOnly`, `Secure`, `SameSite`).

## Out of scope

- Vulnerabilities in dependencies (report those upstream).
- Theoretical weaknesses without a practical exploit path.
