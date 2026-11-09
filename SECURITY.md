# Security Policy

ssshhh-env stores secrets, so we take vulnerabilities seriously.

## Reporting a vulnerability

**Please do not open a public issue.** Report privately through GitHub's
**"Report a vulnerability"** button (Security tab → Advisories) on this repository.

Include:
- the affected version or commit
- steps to reproduce, or a proof of concept
- the impact you believe it has

We aim to acknowledge reports within 72 hours and to agree on a disclosure timeline with you.
Reporters are credited in the advisory unless they prefer otherwise.

## Supported versions

Before v1.0, only the latest release receives security fixes.

## Trust model (summary)

- Secrets are encrypted at rest. A stolen database or backup is useless without the master key.
- The server decrypts secrets in order to serve them over SSH. **Anyone with root on the server, or
  with the master key, can read the secrets.** Run it on infrastructure you trust.
- Once a secret is pulled to a laptop, it is outside our control. After revoking someone, rotate
  the secrets they had access to.

More detail is in the [README](README.md#trust-model).
