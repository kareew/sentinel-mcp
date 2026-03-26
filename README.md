# sentinel-mcp

Security Operations MCP Server — turns AI agents into security analysts.

## What it does

Gives Claude (or any MCP-compatible AI agent) 6 security tools:

| Tool | Description |
|---|---|
| `http_security_scan` | Grades 10+ HTTP security headers (HSTS, CSP, X-Frame-Options...) with A+ to F scoring |
| `ssl_certificate_check` | Validates SSL/TLS — cert expiry, trust chain, protocol version, cipher strength |
| `dns_recon` | Enumerates DNS records + checks SPF, DMARC, DKIM for email spoofing risk |
| `port_scan` | Scans 30 high-risk ports, flags exposed databases/RDP/Telnet |
| `tech_fingerprint` | Identifies web servers, frameworks, CMS, CDN/WAF from headers + HTML |
| `security_report` | Runs ALL scans concurrently → executive summary + MITRE ATT&CK mapping |

## Install

```bash
npm install
npm run build
```

## Usage with Claude Code

Add to your Claude Code MCP config:

```json
{
  "mcpServers": {
    "sentinel": {
      "command": "node",
      "args": ["/path/to/sentinel-mcp/dist/index.js"]
    }
  }
}
```

Then ask Claude: "Run a full security audit on example.com"

## Tools deep dive

### `security_report` (the main one)
Runs all 5 individual scans concurrently and produces:
- Overall security grade (A+ to F)
- Risk level (critical/high/medium/low)
- Executive summary
- Critical findings list
- MITRE ATT&CK technique mapping
- Prioritized remediation recommendations

### Individual tools
Each tool can be called independently for targeted analysis. All return structured JSON with findings, severity ratings, and actionable recommendations.

## Tech stack

- TypeScript + Node.js
- MCP SDK (`@modelcontextprotocol/sdk`)
- Zero external scanning dependencies — uses Node built-in `tls`, `dns`, `net`, `https` modules

## Authorization

Only scan targets you are authorized to test. This tool is intended for defensive security assessments, penetration testing engagements, and educational use.

## License

MIT
