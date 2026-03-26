import dns from "node:dns";
import { URL } from "node:url";

interface DnsRecord {
  type: string;
  values: string[];
}

interface DnsSecurityCheck {
  check: string;
  passed: boolean;
  severity: "critical" | "high" | "medium" | "low" | "info";
  detail: string;
}

interface DnsReconResult {
  domain: string;
  records: DnsRecord[];
  securityChecks: DnsSecurityCheck[];
  mailSecurity: {
    hasSPF: boolean;
    hasDMARC: boolean;
    hasDKIM: boolean;
    spfRecord: string | null;
    dmarcRecord: string | null;
  };
  nameservers: string[];
  summary: string;
}

function resolveRecords(domain: string, type: string): Promise<string[]> {
  return new Promise((resolve) => {
    const resolver = dns.promises.resolve;
    switch (type) {
      case "A":
        dns.resolve4(domain, (err, addresses) => resolve(err ? [] : addresses));
        break;
      case "AAAA":
        dns.resolve6(domain, (err, addresses) => resolve(err ? [] : addresses));
        break;
      case "MX":
        dns.resolveMx(domain, (err, addresses) =>
          resolve(err ? [] : addresses.map((r) => `${r.priority} ${r.exchange}`))
        );
        break;
      case "TXT":
        dns.resolveTxt(domain, (err, records) =>
          resolve(err ? [] : records.map((r) => r.join("")))
        );
        break;
      case "NS":
        dns.resolveNs(domain, (err, addresses) => resolve(err ? [] : addresses));
        break;
      case "CNAME":
        dns.resolveCname(domain, (err, addresses) => resolve(err ? [] : addresses));
        break;
      case "SOA":
        dns.resolveSoa(domain, (err, soa) =>
          resolve(err || !soa ? [] : [`${soa.nsname} ${soa.hostmaster} (serial: ${soa.serial})`])
        );
        break;
      default:
        resolve([]);
    }
  });
}

export async function dnsRecon(target: string): Promise<DnsReconResult> {
  let domain: string;
  try {
    const url = new URL(target.includes("://") ? target : `https://${target}`);
    domain = url.hostname;
  } catch {
    domain = target.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
  }

  const recordTypes = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"];
  const recordResults = await Promise.all(
    recordTypes.map(async (type) => ({
      type,
      values: await resolveRecords(domain, type),
    }))
  );

  const records = recordResults.filter((r) => r.values.length > 0);
  const txtRecords = records.find((r) => r.type === "TXT")?.values || [];
  const nsRecords = records.find((r) => r.type === "NS")?.values || [];
  const mxRecords = records.find((r) => r.type === "MX")?.values || [];

  // Mail security analysis
  const spfRecord = txtRecords.find((r) => r.toLowerCase().startsWith("v=spf1")) || null;
  const hasSPF = spfRecord !== null;

  // Check DMARC
  let dmarcRecord: string | null = null;
  try {
    const dmarcRecords = await resolveRecords(`_dmarc.${domain}`, "TXT");
    dmarcRecord = dmarcRecords.find((r) => r.toLowerCase().startsWith("v=dmarc1")) || null;
  } catch {
    // DMARC record not found
  }
  const hasDMARC = dmarcRecord !== null;

  // Check DKIM (common selectors)
  let hasDKIM = false;
  const dkimSelectors = ["default", "google", "selector1", "selector2", "k1"];
  for (const selector of dkimSelectors) {
    try {
      const dkimRecords = await resolveRecords(`${selector}._domainkey.${domain}`, "TXT");
      if (dkimRecords.length > 0) {
        hasDKIM = true;
        break;
      }
    } catch {
      continue;
    }
  }

  const securityChecks: DnsSecurityCheck[] = [];

  // SPF check
  securityChecks.push({
    check: "SPF Record",
    passed: hasSPF,
    severity: "high",
    detail: hasSPF
      ? `SPF configured: ${spfRecord}`
      : "No SPF record found — domain is vulnerable to email spoofing",
  });

  // DMARC check
  securityChecks.push({
    check: "DMARC Record",
    passed: hasDMARC,
    severity: "high",
    detail: hasDMARC
      ? `DMARC configured: ${dmarcRecord}`
      : "No DMARC record found — no policy for handling spoofed emails",
  });

  // DKIM check
  securityChecks.push({
    check: "DKIM Record",
    passed: hasDKIM,
    severity: "medium",
    detail: hasDKIM
      ? "DKIM signing detected on common selectors"
      : "No DKIM records found on common selectors (may use custom selector)",
  });

  // Multiple nameservers
  securityChecks.push({
    check: "Multiple Nameservers",
    passed: nsRecords.length >= 2,
    severity: "medium",
    detail:
      nsRecords.length >= 2
        ? `${nsRecords.length} nameservers configured — good redundancy`
        : `Only ${nsRecords.length} nameserver(s) — single point of failure risk`,
  });

  // IPv6 support
  const hasIPv6 = records.some((r) => r.type === "AAAA" && r.values.length > 0);
  securityChecks.push({
    check: "IPv6 Support",
    passed: hasIPv6,
    severity: "info",
    detail: hasIPv6 ? "AAAA records present — IPv6 enabled" : "No AAAA records — IPv6 not configured",
  });

  // CAA records check
  let hasCaa = false;
  try {
    const caaRecords = await resolveRecords(domain, "CAA");
    hasCaa = caaRecords.length > 0;
  } catch {
    // not supported by all resolvers
  }
  securityChecks.push({
    check: "CAA Records",
    passed: hasCaa,
    severity: "low",
    detail: hasCaa
      ? "CAA records present — restricts certificate issuance"
      : "No CAA records — any CA can issue certificates for this domain",
  });

  // Dangling CNAME check
  const cnameRecords = records.find((r) => r.type === "CNAME")?.values || [];
  const hasMXAndCNAME = mxRecords.length > 0 && cnameRecords.length > 0;
  if (hasMXAndCNAME) {
    securityChecks.push({
      check: "No CNAME+MX Conflict",
      passed: false,
      severity: "medium",
      detail: "Domain has both CNAME and MX records — this violates RFC 1034 and may cause mail delivery issues",
    });
  }

  const passedChecks = securityChecks.filter((c) => c.passed).length;
  let summary = `DNS reconnaissance for ${domain}: ${records.length} record types found, `;
  summary += `${passedChecks}/${securityChecks.length} security checks passed. `;
  if (!hasSPF || !hasDMARC) {
    summary += `WARNING: Email security gaps — ${!hasSPF ? "missing SPF" : ""}${!hasSPF && !hasDMARC ? " and " : ""}${!hasDMARC ? "missing DMARC" : ""}. `;
  }

  return {
    domain,
    records,
    securityChecks,
    mailSecurity: { hasSPF, hasDMARC, hasDKIM, spfRecord, dmarcRecord },
    nameservers: nsRecords,
    summary,
  };
}
