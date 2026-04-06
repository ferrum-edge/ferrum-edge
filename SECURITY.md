# Security Policy

## Supported Versions

The following versions of Ferrum Edge are currently receiving security updates:

| Version | Supported          |
| ------- | ------------------ |
| Latest release | :white_check_mark: |
| Previous minor | :white_check_mark: |
| Older versions | :x:                |

We recommend always running the latest release to ensure you have the most recent security patches.

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in Ferrum Edge, please report it responsibly.

### Private Disclosure Process

**Please do not open public GitHub issues for security vulnerabilities.**

Instead, send an email to: **security@ferrum-edge.io**

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
4. **Configure rate limiting**: Protect against abuse and DoS
5. **Use IP restrictions**: Limit admin API access to trusted sources
6. **Keep dependencies updated**: Monitor for security advisories
7. **Enable audit logging**: Track administrative changes
8. **Run with minimal privileges**: Don't run as root in containers

### Security Features

Ferrum Edge includes several security-focused features:

- **mTLS support**: Frontend and backend mutual TLS authentication
- **JWT-based authentication**: Secure admin API with configurable secrets
- **Rate limiting**: Token-bucket and Redis-backed distributed rate limiting
- **IP restrictions**: Whitelist/blacklist client IP addresses
- **Request size limiting**: Prevent large payload attacks
- **Bot detection**: Identify and block automated threats
- **CORS handling**: Configure cross-origin request policies
- **Audit logging**: Track all administrative changes

### Security Hardening

See the following documentation for detailed security configuration:
- [Frontend TLS/mTLS](docs/frontend_tls.md)
- [Backend mTLS](docs/backend_mtls.md)
- [Database TLS](docs/database_tls.md)
- [Client IP Resolution](docs/client_ip_resolution.md)

## Security Advisories

When security vulnerabilities are fixed, we will:
1. Release a patched version
2. Publish a security advisory on GitHub
3. Update this document with details (after coordinated disclosure)

## Acknowledgments

We thank the following security researchers who have responsibly disclosed vulnerabilities:

*No vulnerabilities have been publicly disclosed at this time.*

---

For questions about security practices or to report security concerns, contact: security@ferrum-edge.io
