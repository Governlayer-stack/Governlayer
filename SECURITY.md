# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 3.x     | Yes       |
| < 3.0   | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in GovernLayer, please report it responsibly.

**Email:** security@governlayer.ai

**Do NOT** open a public GitHub issue for security vulnerabilities.

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response timeline

- **Acknowledgment:** Within 48 hours
- **Initial assessment:** Within 5 business days
- **Fix timeline:** Critical vulnerabilities patched within 14 days
- **Disclosure:** Coordinated disclosure after fix is deployed

### Scope

The following are in scope:

- GovernLayer API (`src/`)
- Authentication and authorization (`src/security/`)
- Audit ledger integrity (`src/models/database.py`)
- MCP server (`src/mcp/`)
- LangChain integration (`integrations/langchain/`)

### Out of scope

- Third-party dependencies (report upstream)
- Social engineering
- Denial of service attacks
