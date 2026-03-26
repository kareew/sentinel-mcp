import tls from "node:tls";
import { URL } from "node:url";

interface CertificateInfo {
  subject: Record<string, string>;
  issuer: Record<string, string>;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  serialNumber: string;
  fingerprint: string;
  fingerprint256: string;
  isExpired: boolean;
  isExpiringSoon: boolean;
}

interface SslCheckResult {
  host: string;
  port: number;
  connected: boolean;
  protocol: string | null;
  cipher: { name: string; version: string; bits: number } | null;
  certificate: CertificateInfo | null;
  checks: Array<{
    check: string;
    passed: boolean;
    severity: "critical" | "high" | "medium" | "low" | "info";
    detail: string;
  }>;
  score: number;
  grade: string;
  summary: string;
}

function parseCertField(field: any): Record<string, string> {
  if (!field) return {};
  const result: Record<string, string> = {};
  if (typeof field === "object") {
    for (const [k, v] of Object.entries(field)) {
      result[k] = String(v);
    }
  }
  return result;
}

export async function checkSsl(target: string): Promise<SslCheckResult> {
  let host: string;
  let port: number;

  try {
    const url = new URL(target.includes("://") ? target : `https://${target}`);
    host = url.hostname;
    port = url.port ? parseInt(url.port) : 443;
  } catch {
    host = target.split(":")[0];
    port = parseInt(target.split(":")[1]) || 443;
  }

  return new Promise((resolve) => {
    const checks: SslCheckResult["checks"] = [];

    const socket = tls.connect(
      {
        host,
        port,
        timeout: 10000,
        rejectUnauthorized: false,
        servername: host,
      },
      () => {
        const protocol = socket.getProtocol();
        const cipher = socket.getCipher();
        const cert = socket.getPeerCertificate();
        const authorized = socket.authorized;

        let certificate: CertificateInfo | null = null;

        if (cert && cert.valid_from) {
          const validFrom = new Date(cert.valid_from);
          const validTo = new Date(cert.valid_to);
          const now = new Date();
          const daysRemaining = Math.ceil((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

          certificate = {
            subject: parseCertField(cert.subject),
            issuer: parseCertField(cert.issuer),
            validFrom: cert.valid_from,
            validTo: cert.valid_to,
            daysRemaining,
            serialNumber: cert.serialNumber || "N/A",
            fingerprint: cert.fingerprint || "N/A",
            fingerprint256: cert.fingerprint256 || "N/A",
            isExpired: daysRemaining < 0,
            isExpiringSoon: daysRemaining >= 0 && daysRemaining < 30,
          };

          // Certificate validity check
          checks.push({
            check: "Certificate Valid",
            passed: !certificate.isExpired,
            severity: "critical",
            detail: certificate.isExpired
              ? `Certificate expired ${Math.abs(daysRemaining)} days ago`
              : `Certificate valid for ${daysRemaining} more days`,
          });

          // Expiring soon check
          if (!certificate.isExpired) {
            checks.push({
              check: "Certificate Not Expiring Soon",
              passed: !certificate.isExpiringSoon,
              severity: "high",
              detail: certificate.isExpiringSoon
                ? `Certificate expires in ${daysRemaining} days — renew immediately`
                : `Certificate expires in ${daysRemaining} days`,
            });
          }

          // Self-signed check
          const isSelfSigned =
            cert.subject &&
            cert.issuer &&
            JSON.stringify(cert.subject) === JSON.stringify(cert.issuer);
          checks.push({
            check: "Not Self-Signed",
            passed: !isSelfSigned,
            severity: "high",
            detail: isSelfSigned
              ? "Certificate is self-signed — not trusted by browsers"
              : `Issued by: ${certificate.issuer.O || certificate.issuer.CN || "Unknown CA"}`,
          });
        }

        // Certificate trust check
        checks.push({
          check: "Certificate Trusted",
          passed: authorized,
          severity: "critical",
          detail: authorized
            ? "Certificate chain is trusted"
            : `Certificate not trusted: ${socket.authorizationError || "unknown error"}`,
        });

        // Protocol version check
        const goodProtocols = ["TLSv1.2", "TLSv1.3"];
        checks.push({
          check: "Modern TLS Protocol",
          passed: protocol ? goodProtocols.includes(protocol) : false,
          severity: "critical",
          detail: protocol
            ? goodProtocols.includes(protocol)
              ? `Using ${protocol}`
              : `Using deprecated ${protocol} — upgrade to TLS 1.2+`
            : "Could not determine protocol",
        });

        // TLS 1.3 check
        checks.push({
          check: "TLS 1.3 Support",
          passed: protocol === "TLSv1.3",
          severity: "low",
          detail: protocol === "TLSv1.3" ? "TLS 1.3 is active" : `Using ${protocol} — TLS 1.3 preferred`,
        });

        // Cipher strength
        const bits = (cipher as any)?.bits || 0;
        checks.push({
          check: "Strong Cipher",
          passed: bits >= 128,
          severity: "high",
          detail: `Cipher: ${cipher?.name || "unknown"} (${bits}-bit)`,
        });

        const passedCount = checks.filter((c) => c.passed).length;
        const score = checks.length > 0 ? Math.round((passedCount / checks.length) * 100) : 0;
        const grade = score >= 90 ? "A+" : score >= 80 ? "A" : score >= 70 ? "B" : score >= 60 ? "C" : score >= 50 ? "D" : "F";

        const criticalFails = checks.filter((c) => !c.passed && c.severity === "critical");
        let summary = `SSL/TLS score: ${score}/100 (Grade: ${grade}). Protocol: ${protocol || "unknown"}. `;
        if (certificate) {
          summary += `Certificate: ${certificate.isExpired ? "EXPIRED" : `valid for ${certificate.daysRemaining} days`}. `;
        }
        if (criticalFails.length > 0) {
          summary += `CRITICAL ISSUES: ${criticalFails.map((c) => c.detail).join("; ")}`;
        }

        socket.end();
        resolve({
          host,
          port,
          connected: true,
          protocol,
          cipher: cipher ? { name: cipher.name, version: cipher.version, bits: (cipher as any).bits || 0 } : null,
          certificate,
          checks,
          score,
          grade,
          summary,
        });
      }
    );

    socket.on("error", (err) => {
      resolve({
        host,
        port,
        connected: false,
        protocol: null,
        cipher: null,
        certificate: null,
        checks: [{ check: "Connection", passed: false, severity: "critical", detail: `Failed to connect: ${err.message}` }],
        score: 0,
        grade: "F",
        summary: `Could not establish SSL/TLS connection to ${host}:${port}: ${err.message}`,
      });
    });

    socket.on("timeout", () => {
      socket.destroy();
      resolve({
        host,
        port,
        connected: false,
        protocol: null,
        cipher: null,
        certificate: null,
        checks: [{ check: "Connection", passed: false, severity: "critical", detail: "Connection timed out" }],
        score: 0,
        grade: "F",
        summary: `SSL/TLS connection to ${host}:${port} timed out`,
      });
    });
  });
}
