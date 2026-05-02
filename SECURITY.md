# Security Policy

## Supported Versions

DIYDDNS is in early development. Only the latest tagged release receives
security fixes.

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Use GitHub's private vulnerability reporting:
<https://github.com/jacaudi/diyddns/security/advisories/new>

If GitHub Security Advisories is unavailable, contact
[@jacaudi](https://github.com/jacaudi) directly via GitHub.

You will receive an acknowledgement within 72 hours. We aim to issue a fix
or mitigation within 30 days for high-severity issues; lower-severity issues
are addressed on a best-effort basis.

## Scope

In scope:
- The `diyddns-server` and `diyddns-client` binaries.
- The web UI served by the server.
- Authentication, session, HMAC, and OIDC handling.
- The HTTP/JSON API and OpenAPI surface.

Out of scope:
- Third-party DNS providers, OIDC providers, and reverse proxies.
- Operator misconfiguration that doesn't reflect a defect in DIYDDNS itself.
- Bugs in the IP-discovery providers' upstream services.
