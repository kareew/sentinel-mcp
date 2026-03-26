#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { scanHttpSecurity } from "./tools/http-security.js";
import { checkSsl } from "./tools/ssl-check.js";
import { dnsRecon } from "./tools/dns-recon.js";
import { portScan } from "./tools/port-scan.js";
import { fingerprintTech } from "./tools/tech-fingerprint.js";
import { generateSecurityReport } from "./tools/security-report.js";

const server = new McpServer({
  name: "sentinel-mcp",
  version: "1.0.0",
});

// ─── Tool 1: HTTP Security Header Scanner ───────────────────────────────────

server.tool(
  "http_security_scan",
  "Analyze HTTP security headers of a target URL. Checks for HSTS, CSP, X-Frame-Options, and 10+ security headers. Returns a security grade (A+ to F), detailed findings, and remediation recommendations.",
  {
    url: z.string().describe("Target URL or domain to scan (e.g., 'example.com' or 'https://example.com')"),
  },
  async ({ url }) => {
    try {
      const result = await scanHttpSecurity(url);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text" as const,
            text: `Error scanning ${url}: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// ─── Tool 2: SSL/TLS Certificate Analyzer ───────────────────────────────────

server.tool(
  "ssl_certificate_check",
  "Analyze SSL/TLS configuration of a target. Checks certificate validity, expiration, trust chain, protocol version (TLS 1.2/1.3), and cipher strength. Returns security grade and detailed findings.",
  {
    target: z
      .string()
      .describe("Target hostname or URL to check (e.g., 'example.com' or 'https://example.com:443')"),
  },
  async ({ target }) => {
    try {
      const result = await checkSsl(target);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text" as const,
            text: `Error checking SSL for ${target}: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// ─── Tool 3: DNS Reconnaissance ─────────────────────────────────────────────

server.tool(
  "dns_recon",
  "Perform DNS reconnaissance on a domain. Enumerates A, AAAA, MX, TXT, NS, CNAME, and SOA records. Checks email security (SPF, DMARC, DKIM), nameserver redundancy, and CAA records. Identifies email spoofing vulnerabilities.",
  {
    domain: z.string().describe("Target domain to enumerate (e.g., 'example.com')"),
  },
  async ({ domain }) => {
    try {
      const result = await dnsRecon(domain);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text" as const,
            text: `Error performing DNS recon on ${domain}: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// ─── Tool 4: Port Scanner ───────────────────────────────────────────────────

server.tool(
  "port_scan",
  "Scan common ports on a target host to identify open services and assess attack surface. Checks 30 well-known ports including databases (MySQL, PostgreSQL, MongoDB, Redis), remote access (SSH, RDP, Telnet), web servers, and more. Maps findings to risk levels and provides security recommendations. Only use for authorized targets.",
  {
    target: z.string().describe("Target hostname or IP address to scan (e.g., 'example.com' or '192.168.1.1')"),
    ports: z
      .array(z.number())
      .optional()
      .describe("Optional: specific ports to scan. If omitted, scans 30 common high-risk ports."),
    timeout: z
      .number()
      .optional()
      .describe("Optional: connection timeout in milliseconds per port (default: 3000)"),
  },
  async ({ target, ports, timeout }) => {
    try {
      const result = await portScan(target, { ports, timeout });
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text" as const,
            text: `Error scanning ports on ${target}: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// ─── Tool 5: Technology Fingerprinting ──────────────────────────────────────

server.tool(
  "tech_fingerprint",
  "Fingerprint the technology stack of a website. Detects web servers, frameworks, CMS platforms, JavaScript libraries, CDNs, WAFs, analytics tools, and more from HTTP headers and HTML content. Identifies security implications of detected technologies.",
  {
    url: z.string().describe("Target URL or domain to fingerprint (e.g., 'example.com')"),
  },
  async ({ url }) => {
    try {
      const result = await fingerprintTech(url);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text" as const,
            text: `Error fingerprinting ${url}: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// ─── Tool 6: Full Security Report ───────────────────────────────────────────

server.tool(
  "security_report",
  "Generate a comprehensive security assessment report for a target. Runs ALL scans (HTTP headers, SSL/TLS, DNS, ports, technology) concurrently and produces an executive summary with overall grade, critical findings, MITRE ATT&CK technique mapping, and prioritized remediation recommendations. This is the primary tool for a complete security audit.",
  {
    target: z
      .string()
      .describe("Target domain or URL to audit (e.g., 'example.com'). Must be a domain you are authorized to scan."),
  },
  async ({ target }) => {
    try {
      const result = await generateSecurityReport(target);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text" as const,
            text: `Error generating security report for ${target}: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// ─── Start Server ───────────────────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Sentinel MCP Security Server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
