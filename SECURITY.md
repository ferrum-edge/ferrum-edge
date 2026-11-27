# Security Policy

## Supported Versions

Support windows, deprecation periods, and the backport policy are defined in
[docs/support_policy.md](docs/support_policy.md). They apply from Ferrum Edge
1.0.0 onward; releases before 1.0.0 (`0.x`) are build-out releases with no
backport commitment. A source tag alone does not prove that its release assets
or container images finished publishing. Check the
[Releases page](https://github.com/ferrum-edge/ferrum-edge/releases) and the
version's release workflow before choosing an artifact.

| Version | Status | Security updates |
| ------- | ------ | ---------------- |
| Current `1.Y` minor (from 1.0.0 onward) | supported | every fix ships as a new patch release of that minor |
| Previous `1.Y` minor | supported for 6 months after the next minor is published | Critical and High fixes are backported as patch releases; Medium at maintainer discretion; Low is not backported |
| Older `1.Y` minors | unsupported | upgrade to a supported minor |
| Published `v0.9.x` and earlier `0.x` artifacts | pre-1.0 build-out releases, where publication completed | until 1.0.0 is published, fixes ship in the next published `0.9.x` release (no backports); once 1.0.0 is published, unsupported — upgrade to 1.x |
| `main` | development branch | fixes land on `main` first; CI validates but does not publish production artifacts; the `latest` / `main-<sha>` development images follow it |
| `latest` / `main-<sha>` container tags | `latest` moves forward to the newest built `main` commit that passed CI and was signed, and may skip intermediate commits; `main-<sha>` exists only for built commits | development channel only; do not use as a security-update channel |
| Historical `latest` GitHub prerelease binaries | no longer refreshed | do not use |

Within a supported minor, only its newest patch release is supported. Production
artifacts are published by the version-tag release workflow after exact-commit
validation. Pin a published version or immutable image digest and verify that
its release contains the required fix; merging a fix to `main` does not update
an installed artifact.

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in Ferrum Edge, please report it responsibly.

### Private Disclosure Process

Please do not report security issues in public GitHub issues, discussions, or
pull requests. Email your report to **contact@ferrumedge.com** with a subject
starting with `[SECURITY]`. This address is always the private reporting
channel, so maintainers can coordinate a fix and disclosure privately.

If the repository's **Security** tab shows a **Report a vulnerability** button,
GitHub's private vulnerability reporting form is also available and works just
as well. If that button is missing, or the form does not open, use the email
address above; do not fall back to a public issue. Published advisories are
listed in the [GitHub Security Advisories](https://github.com/ferrum-edge/ferrum-edge/security/advisories).

Include the following information:
- Description of the vulnerability
- Steps to reproduce (if applicable)
- Potential impact
- Suggested fix (if you have one)
- Your contact information for follow-up

### Response Timeline

- **Acknowledgment**: Within 48 hours of receiving your report
- **Initial assessment**: Within 5 business days
- **Fix timeline**: Depends on severity and complexity
  - Critical: 7 days target
  - High: 30 days target
  - Medium: 90 days target
- **Disclosure**: Coordinated with reporter, typically after fix is released

### What to Expect

- We will confirm receipt of your vulnerability report
- We will assess the severity and impact
- We will work on a fix and may ask for additional information
- We will credit you in the security advisory (unless you prefer to remain anonymous)
- We will not take legal action against researchers who follow responsible disclosure

## Security Best Practices

### For Production Deployments

1. **Use TLS everywhere**: Frontend, backend, and database connections
2. **Enable mTLS**: For backend authentication and zero-trust architectures
3. **Set strong JWT secrets**: Use cryptographically secure random values
4. **Bound remote signing-key trust**: `jwks_auth` defaults
   `jwks_max_stale_seconds` to one hour and never permits an unlimited value.
   Set a shorter value when emergency issuer-key revocation must converge more
   quickly, while accounting for the availability impact of an IdP outage.
5. **Configure rate limiting**: Protect against abuse and DoS
6. **Use IP restrictions**: Limit admin API access to trusted sources
7. **Keep dependencies updated**: Monitor for security advisories
8. **Enable audit logging**: Track administrative changes
9. **Run with minimal privileges**: Don't run as root in containers
10. **Treat custom plugins as gateway code**: anything compiled from
    `custom_plugins/` runs in-process with full gateway privileges and
    self-declares its failure policy. Review it like a core change and
    restrict who can write to that directory in your build. See
    [Custom plugin trust boundary](CUSTOM_PLUGINS.md#trust-boundary).
11. **Protect the configuration database and its backups**: Consumer API keys
    (`keyauth`) and shared secrets (`jwt`, `hmac_auth`) are stored recoverable
    at rest so the gateway can verify them; only Basic passwords are hashed.
    A database, replica, or backup read recovers them. See
    [Credential storage at rest](docs/plugins.md#credential-storage-at-rest).

### Security Features

- **mTLS support**: Frontend and backend mutual TLS authentication
- **JWT-based authentication**: Secure admin API with configurable secrets
- **Rate limiting**: Local token-bucket / sliding-window limits and Redis-backed centralized limits
- **IP restrictions**: Allow and deny lists for client IP addresses
- **Request size limiting**: Prevent large payload attacks
- **Bot detection**: Identify and block automated threats
- **CORS handling**: Configure cross-origin request policies
- **Audit logging**: Track all administrative changes

### Security Hardening

See the following documentation for detailed security configuration:
- [Production hardening checklist](docs/hardening.md) — start here
- [Threat model](docs/threat_model.md) — trust boundaries, controls, and documented residuals
- [Frontend TLS/mTLS](docs/frontend_tls.md)
- [Backend mTLS](docs/backend_mtls.md)
- [Database TLS](docs/database_tls.md)
- [Client IP Resolution](docs/client_ip_resolution.md)

## Security Advisories

When security vulnerabilities are fixed, we will:
1. Release a patched version
2. Publish a security advisory on GitHub
3. Update this document with details (after coordinated disclosure)

## Dependency & Supply-Chain Security

Ferrum Edge gates its dependency tree and the vendored, patched upstream crates
it carries in `vendor/**`. The authoritative, complete
[vendored-patch inventory](docs/dependency-policy.md#vendored-crate-inventory)
— with owners, retirement triggers, the blocking advisory gate, time-boxed
exception expiry, the vendor drift guard, and the **emergency security-update
process for vendored crates** — is documented in
[docs/dependency-policy.md](docs/dependency-policy.md).

Key controls:

- **Blocking advisory gate.** `cargo deny check advisories bans sources licenses`
  runs when CI selects the full dependency-audit lane (`ci-plan` full mode plus
  `run_dependency_audit`) for an eligible pull request, merge group, push to
  `main`, or manual dispatch (`.github/workflows/ci.yml`), once over the root workspace and
  once over the separate `ebpf/Cargo.toml` workspace with the same `deny.toml`. A
  RUSTSEC advisory not explicitly time-boxed in `deny.toml` fails the build.
- **Weekly re-check.** `.github/workflows/dependency-audit.yml` re-runs the gate
  against the latest advisory database, fails on expired exceptions, and reports
  when a vendored patch has merged upstream so it can be retired. This is why a
  fix in the reqwest/h3 lineage cannot be missed silently.
- **Vendor integrity.** `tests/integration/vendor_integrity_tests.rs` pins every
  vendored file to `vendor/VENDOR_INTEGRITY.sha256`; drift beyond the documented
  patches fails CI.

## Acknowledgments

Researchers who choose to be credited are acknowledged in the
[published GitHub Security Advisories](https://github.com/ferrum-edge/ferrum-edge/security/advisories).

---

For questions about security practices or to report security concerns, contact: contact@ferrumedge.com
