import { scanHttpSecurity } from "./http-security.js";
import { checkSsl } from "./ssl-check.js";
import { dnsRecon } from "./dns-recon.js";
import { portScan } from "./port-scan.js";
import { fingerprintTech } from "./tech-fingerprint.js";

interface FullReportResult {
  target: string;
  timestamp: string;
  overallGrade: string;
  overallScore: number;
  riskLevel: "critical" | "high" | "medium" | "low";
  executiveSummary: string;
  sections: {
    httpSecurity: { grade: string; score: number; summary: string; findings: number };
    sslTls: { grade: string; score: number; summary: string; findings: number };
    dns: { summary: string; findings: number };
    ports: { summary: string; openCount: number; criticalCount: number };
    technology: { summary: string; techCount: number };
  };
  criticalFindings: string[];
  recommendations: string[];
  mitreMapping: Array<{ technique: string; id: string; relevance: string }>;
}

export async function generateSecurityReport(target: string): Promise<FullReportResult> {
  const timestamp = new Date().toISOString();

  // Run all scans concurrently
  const [httpResult, sslResult, dnsResult, portResult, techResult] = await Promise.allSettled([
    scanHttpSecurity(target),
    checkSsl(target),
    dnsRecon(target),
    portScan(target, { timeout: 3000 }),
    fingerprintTech(target),
  ]);

  const http = httpResult.status === "fulfilled" ? httpResult.value : null;
  const ssl = sslResult.status === "fulfilled" ? sslResult.value : null;
  const dns = dnsResult.status === "fulfilled" ? dnsResult.value : null;
  const ports = portResult.status === "fulfilled" ? portResult.value : null;
  const tech = techResult.status === "fulfilled" ? techResult.value : null;

  // Calculate overall score
  const scores: number[] = [];
  if (http) scores.push(http.score);
  if (ssl) scores.push(ssl.score);

  // DNS score based on passed checks
  if (dns) {
    const dnsPass = dns.securityChecks.filter((c) => c.passed).length;
    const dnsTotal = dns.securityChecks.length;
    scores.push(dnsTotal > 0 ? Math.round((dnsPass / dnsTotal) * 100) : 50);
  }

  // Port score — fewer critical open ports = better
  if (ports) {
    const critPorts = ports.openPorts.filter((p) => p.risk === "critical").length;
    const highPorts = ports.openPorts.filter((p) => p.risk === "high").length;
    const portScore = Math.max(0, 100 - critPorts * 25 - highPorts * 10);
    scores.push(portScore);
  }

  const overallScore = scores.length > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;
  const overallGrade =
    overallScore >= 90 ? "A+" : overallScore >= 80 ? "A" : overallScore >= 70 ? "B" : overallScore >= 60 ? "C" : overallScore >= 50 ? "D" : "F";

  // Determine risk level
  const riskLevel: FullReportResult["riskLevel"] =
    overallScore < 40 ? "critical" : overallScore < 60 ? "high" : overallScore < 80 ? "medium" : "low";

  // Collect critical findings
  const criticalFindings: string[] = [];

  if (http) {
    const critHeaders = http.checks.filter((c) => !c.present && c.severity === "critical");
    critHeaders.forEach((c) => criticalFindings.push(`Missing critical HTTP header: ${c.header}`));
  }

  if (ssl) {
    ssl.checks
      .filter((c) => !c.passed && c.severity === "critical")
      .forEach((c) => criticalFindings.push(`SSL/TLS: ${c.detail}`));
  }

  if (dns) {
    if (!dns.mailSecurity.hasSPF) criticalFindings.push("Email spoofing risk: No SPF record configured");
    if (!dns.mailSecurity.hasDMARC) criticalFindings.push("Email spoofing risk: No DMARC record configured");
  }

  if (ports) {
    ports.openPorts
      .filter((p) => p.risk === "critical")
      .forEach((p) => criticalFindings.push(`Critical port exposed: ${p.port}/${p.service}`));
  }

  if (tech) {
    tech.securityImplications.forEach((s) => {
      if (s.includes("reveals") || s.includes("No WAF")) criticalFindings.push(s);
    });
  }

  // Generate recommendations
  const recommendations: string[] = [];
  if (http && http.score < 80) recommendations.push("Implement missing security headers — start with HSTS and CSP");
  if (ssl && ssl.score < 80) recommendations.push("Upgrade TLS configuration — ensure TLS 1.2+ and strong ciphers");
  if (ssl?.certificate?.isExpiringSoon) recommendations.push("Renew SSL certificate immediately — expires soon");
  if (dns && !dns.mailSecurity.hasSPF) recommendations.push("Add SPF record to prevent email spoofing");
  if (dns && !dns.mailSecurity.hasDMARC) recommendations.push("Add DMARC record with reject policy");
  if (ports && ports.openPorts.filter((p) => p.risk === "critical").length > 0) {
    recommendations.push("Close or restrict access to critical-risk ports (databases, RDP, etc.)");
  }
  if (tech && !tech.technologies.some((t) => t.category === "CDN/WAF")) {
    recommendations.push("Deploy a WAF/CDN (e.g., Cloudflare) for DDoS protection and bot mitigation");
  }
  recommendations.push("Suppress server version headers to reduce information leakage");
  recommendations.push("Schedule regular security assessments — at minimum quarterly");

  // MITRE ATT&CK mapping
  const mitreMapping: FullReportResult["mitreMapping"] = [];

  if (http && http.checks.some((c) => c.header === "content-security-policy" && !c.present)) {
    mitreMapping.push({
      technique: "Drive-by Compromise",
      id: "T1189",
      relevance: "Missing CSP allows injection of malicious scripts",
    });
  }

  if (ports?.openPorts.some((p) => [22, 3389, 23].includes(p.port))) {
    mitreMapping.push({
      technique: "External Remote Services",
      id: "T1133",
      relevance: "Exposed remote access services (SSH/RDP/Telnet)",
    });
  }

  if (ports?.openPorts.some((p) => [3306, 5432, 1433, 27017, 6379].includes(p.port))) {
    mitreMapping.push({
      technique: "Exploitation of Remote Services",
      id: "T1210",
      relevance: "Exposed database ports allow direct data access",
    });
  }

  if (dns && (!dns.mailSecurity.hasSPF || !dns.mailSecurity.hasDMARC)) {
    mitreMapping.push({
      technique: "Phishing",
      id: "T1566",
      relevance: "Missing email authentication (SPF/DMARC) enables spoofing",
    });
  }

  if (tech?.serverInfo.server || tech?.serverInfo.poweredBy) {
    mitreMapping.push({
      technique: "Gather Victim Host Information",
      id: "T1592",
      relevance: "Server/technology headers expose version info for targeted exploits",
    });
  }

  if (ssl && ssl.checks.some((c) => c.check === "Modern TLS Protocol" && !c.passed)) {
    mitreMapping.push({
      technique: "Adversary-in-the-Middle",
      id: "T1557",
      relevance: "Weak TLS protocol enables traffic interception",
    });
  }

  // Executive summary
  let executiveSummary = `Security assessment of ${target} completed on ${new Date().toLocaleDateString()}. `;
  executiveSummary += `Overall security grade: ${overallGrade} (${overallScore}/100). Risk level: ${riskLevel.toUpperCase()}. `;
  executiveSummary += `${criticalFindings.length} critical finding(s) identified. `;
  if (criticalFindings.length > 0) {
    executiveSummary += `Immediate action required on: ${criticalFindings.slice(0, 3).join("; ")}. `;
  }
  executiveSummary += `${mitreMapping.length} MITRE ATT&CK technique(s) mapped. ${recommendations.length} recommendations provided.`;

  return {
    target,
    timestamp,
    overallGrade,
    overallScore,
    riskLevel,
    executiveSummary,
    sections: {
      httpSecurity: {
        grade: http?.grade ?? "N/A",
        score: http?.score ?? 0,
        summary: http?.summary ?? "Scan failed",
        findings: http?.checks.length ?? 0,
      },
      sslTls: {
        grade: ssl?.grade ?? "N/A",
        score: ssl?.score ?? 0,
        summary: ssl?.summary ?? "Scan failed",
        findings: ssl?.checks.length ?? 0,
      },
      dns: {
        summary: dns?.summary ?? "Scan failed",
        findings: dns?.securityChecks.length ?? 0,
      },
      ports: {
        summary: ports?.summary ?? "Scan failed",
        openCount: ports?.openPorts.length ?? 0,
        criticalCount: ports?.openPorts.filter((p) => p.risk === "critical").length ?? 0,
      },
      technology: {
        summary: tech?.summary ?? "Scan failed",
        techCount: tech?.technologies.length ?? 0,
      },
    },
    criticalFindings,
    recommendations,
    mitreMapping,
  };
}
