# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, email: sambou@gmail.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

You will receive a response within 48 hours acknowledging the report.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Security Measures

This project implements:
- OPA policy evaluation for all dependency decisions
- SHA-256 evidence seal chain for audit integrity
- Path traversal guards on all file operations
- SecretStr for credential fields (never logged)
- Parameterized queries only (no SQL concatenation)
- Fail-open design (security failures degrade gracefully, never silently pass)
- Subprocess calls use list-form arguments (never `shell=True`)
- Semgrep code pattern scanning on PR diffs
