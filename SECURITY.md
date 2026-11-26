# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| 0.1.x   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in SOC-GPT, please report it responsibly.

**Do not open a public GitHub issue.** Instead, email the details to:

**omarrevolve@gmail.com**

Include:
- A description of the vulnerability and its impact
- Steps to reproduce (minimal proof-of-concept preferred)
- Any suggested mitigations

### What to expect

- Acknowledgment within 72 hours
- An initial assessment within 7 days
- Coordinated disclosure timeline agreed with the reporter
- Public credit in the release notes (unless you request anonymity)

## Known Trade-offs

SOC-GPT is a defensive triage tool designed for development and learning environments. Before deploying to production, you should:

- Replace simulated auto-response actions with real integrations (UFW, Wazuh Active Response)
- Add authentication to the webhook endpoint (HMAC signature verification, API keys)
- Deploy behind a reverse proxy with TLS
- Review and extend the critical keyword guard in `src/core/response.py` for your threat model
- Rotate the `GROQ_API_KEY` regularly