# Security Policy

## Responsible Disclosure & Scope

StateWeaver is a defensive security research tool designed to analyze authorization boundaries and business logic consistency in authorized test environments.

If you believe you have found a security vulnerability in StateWeaver itself (including its CLI, HTTP executor, parser, or SQLite persistence engine), please report it responsibly.

### Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please send an encrypted or direct email to `security@stateweaver.local` or open a private GitHub Security Advisory with:
- A descriptive title and vulnerability category.
- Detailed steps to reproduce.
- Proof of Concept (PoC) traffic or configuration.
- Potential impact and affected versions.

We will acknowledge receipt of your vulnerability report within 48 hours and work with you to validate and remediate the issue promptly.

## Safe Usage Guidelines

- StateWeaver is intended exclusively for authorized security research, pre-production auditing, and developer QA testing.
- Never run StateWeaver against production systems or targets where you do not possess explicit, documented authorization.
- StateWeaver enforces a localhost-only execution policy by default to prevent accidental scanning of public endpoints.
- All sensitive tokens, authorization headers, and credentials are automatically scrubbed from generated reports.

