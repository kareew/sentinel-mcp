import https from "node:https";
import http from "node:http";
import { URL } from "node:url";

interface HeaderCheck {
  header: string;
  present: boolean;
  value: string | null;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  recommendation: string;
}

interface HttpSecurityResult {
  url: string;
  statusCode: number | null;
  headers: Record<string, string>;
  checks: HeaderCheck[];
  score: number;
  grade: string;
  summary: string;
}

const SECURITY_HEADERS: Array<{
  header: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  recommendation: string;
}> = [
  {
    header: "strict-transport-security",
    severity: "critical",
    description: "HTTP Strict Transport Security (HSTS) forces browsers to use HTTPS, preventing protocol downgrade attacks and cookie hijacking.",
    recommendation: "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
  },
  {
    header: "content-security-policy",
    severity: "critical",
    description: "Content Security Policy (CSP) prevents XSS, clickjacking, and code injection attacks by specifying trusted content sources.",
    recommendation: "Implement a restrictive CSP. Start with: Content-Security-Policy: default-src 'self'; script-src 'self'",
  },
  {
    header: "x-content-type-options",
    severity: "high",
    description: "Prevents browsers from MIME-sniffing responses, reducing drive-by download attacks.",
    recommendation: "Add header: X-Content-Type-Options: nosniff",
  },
  {
    header: "x-frame-options",
    severity: "high",
    description: "Protects against clickjacking by controlling whether the page can be rendered in frames.",
    recommendation: "Add header: X-Frame-Options: DENY (or SAMEORIGIN if framing is needed)",
  },
  {
    header: "x-xss-protection",
    severity: "medium",
    description: "Enables browser-level XSS filtering. Largely superseded by CSP but still provides defense-in-depth.",
    recommendation: "Add header: X-Xss-Protection: 1; mode=block",
  },
  {
    header: "referrer-policy",
    severity: "medium",
    description: "Controls how much referrer information is sent with requests, protecting user privacy.",
    recommendation: "Add header: Referrer-Policy: strict-origin-when-cross-origin",
  },
  {
    header: "permissions-policy",
    severity: "medium",
    description: "Controls which browser features (camera, mic, geolocation) the page can use.",
    recommendation: "Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()",
  },
  {
    header: "cross-origin-opener-policy",
    severity: "medium",
    description: "Prevents other pages from gaining arbitrary window references, protecting against Spectre-like attacks.",
    recommendation: "Add header: Cross-Origin-Opener-Policy: same-origin",
  },
  {
    header: "cross-origin-resource-policy",
    severity: "low",
    description: "Controls which origins can load this resource, preventing cross-origin data leaks.",
    recommendation: "Add header: Cross-Origin-Resource-Policy: same-origin",
  },
  {
    header: "cross-origin-embedder-policy",
    severity: "low",
    description: "Prevents loading cross-origin resources that don't explicitly grant permission.",
    recommendation: "Add header: Cross-Origin-Embedder-Policy: require-corp",
  },
];

const DANGEROUS_HEADERS = [
  { header: "server", description: "Reveals server software and version — aids attacker reconnaissance." },
  { header: "x-powered-by", description: "Reveals backend technology — aids attacker reconnaissance." },
  { header: "x-aspnet-version", description: "Reveals ASP.NET version — known CVEs may apply." },
  { header: "x-aspnetmvc-version", description: "Reveals ASP.NET MVC version — known CVEs may apply." },
];

function fetchHeaders(targetUrl: string): Promise<{ statusCode: number; headers: Record<string, string> }> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(targetUrl);
    const client = parsed.protocol === "https:" ? https : http;

    const req = client.request(
      targetUrl,
      { method: "HEAD", timeout: 10000, headers: { "User-Agent": "Sentinel-MCP-SecurityScanner/1.0" } },
      (res) => {
        const headers: Record<string, string> = {};
        for (const [key, value] of Object.entries(res.headers)) {
          if (value) headers[key] = Array.isArray(value) ? value.join(", ") : value;
        }
        resolve({ statusCode: res.statusCode ?? 0, headers });
      }
    );

    req.on("error", reject);
    req.on("timeout", () => {
      req.destroy();
      reject(new Error("Request timed out after 10 seconds"));
    });
    req.end();
  });
}

function calculateGrade(score: number): string {
  if (score >= 90) return "A+";
  if (score >= 80) return "A";
  if (score >= 70) return "B";
  if (score >= 60) return "C";
  if (score >= 50) return "D";
  return "F";
}

export async function scanHttpSecurity(url: string): Promise<HttpSecurityResult> {
  let targetUrl = url;
  if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
    targetUrl = `https://${targetUrl}`;
  }

  const { statusCode, headers } = await fetchHeaders(targetUrl);
  const lowerHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    lowerHeaders[k.toLowerCase()] = v;
  }

  const checks: HeaderCheck[] = [];
  let totalWeight = 0;
  let earnedWeight = 0;

  const severityWeight = { critical: 30, high: 20, medium: 10, low: 5, info: 0 };

  for (const def of SECURITY_HEADERS) {
    const value = lowerHeaders[def.header] ?? null;
    const present = value !== null;
    const weight = severityWeight[def.severity];
    totalWeight += weight;
    if (present) earnedWeight += weight;

    checks.push({
      header: def.header,
      present,
      value,
      severity: def.severity,
      description: def.description,
      recommendation: present ? "Header is properly configured." : def.recommendation,
    });
  }

  for (const danger of DANGEROUS_HEADERS) {
    const value = lowerHeaders[danger.header] ?? null;
    if (value) {
      checks.push({
        header: danger.header,
        present: true,
        value,
        severity: "info",
        description: danger.description,
        recommendation: `Remove or suppress the '${danger.header}' header to reduce information leakage.`,
      });
    }
  }

  const score = totalWeight > 0 ? Math.round((earnedWeight / totalWeight) * 100) : 0;
  const grade = calculateGrade(score);
  const missing = checks.filter((c) => !c.present && c.severity !== "info");
  const criticalMissing = missing.filter((c) => c.severity === "critical");

  let summary = `Security header score: ${score}/100 (Grade: ${grade}). `;
  summary += `${checks.filter((c) => c.present && c.severity !== "info").length}/${SECURITY_HEADERS.length} security headers present. `;
  if (criticalMissing.length > 0) {
    summary += `CRITICAL: Missing ${criticalMissing.map((c) => c.header).join(", ")}. `;
  }

  return { url: targetUrl, statusCode, headers, checks, score, grade, summary };
}
