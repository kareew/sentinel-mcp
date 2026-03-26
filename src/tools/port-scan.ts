import net from "node:net";
import { URL } from "node:url";

interface PortResult {
  port: number;
  state: "open" | "closed" | "filtered";
  service: string;
  risk: "critical" | "high" | "medium" | "low" | "info";
}

interface PortScanResult {
  host: string;
  openPorts: PortResult[];
  closedPorts: number;
  filteredPorts: number;
  totalScanned: number;
  riskAssessment: string[];
  summary: string;
}

const COMMON_PORTS: Record<number, { service: string; risk: "critical" | "high" | "medium" | "low" | "info" }> = {
  21: { service: "FTP", risk: "high" },
  22: { service: "SSH", risk: "medium" },
  23: { service: "Telnet", risk: "critical" },
  25: { service: "SMTP", risk: "medium" },
  53: { service: "DNS", risk: "medium" },
  80: { service: "HTTP", risk: "low" },
  110: { service: "POP3", risk: "high" },
  111: { service: "RPCbind", risk: "high" },
  135: { service: "MS-RPC", risk: "high" },
  139: { service: "NetBIOS", risk: "high" },
  143: { service: "IMAP", risk: "medium" },
  443: { service: "HTTPS", risk: "info" },
  445: { service: "SMB", risk: "critical" },
  587: { service: "SMTP (submission)", risk: "low" },
  993: { service: "IMAPS", risk: "info" },
  995: { service: "POP3S", risk: "info" },
  1433: { service: "MSSQL", risk: "critical" },
  1521: { service: "Oracle DB", risk: "critical" },
  3306: { service: "MySQL", risk: "critical" },
  3389: { service: "RDP", risk: "critical" },
  5432: { service: "PostgreSQL", risk: "critical" },
  5900: { service: "VNC", risk: "critical" },
  6379: { service: "Redis", risk: "critical" },
  8080: { service: "HTTP Alt", risk: "medium" },
  8443: { service: "HTTPS Alt", risk: "low" },
  8888: { service: "HTTP Alt", risk: "medium" },
  9200: { service: "Elasticsearch", risk: "critical" },
  11211: { service: "Memcached", risk: "critical" },
  27017: { service: "MongoDB", risk: "critical" },
};

function scanPort(host: string, port: number, timeout: number): Promise<"open" | "closed" | "filtered"> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(timeout);

    socket.on("connect", () => {
      socket.destroy();
      resolve("open");
    });

    socket.on("timeout", () => {
      socket.destroy();
      resolve("filtered");
    });

    socket.on("error", (err: NodeJS.ErrnoException) => {
      socket.destroy();
      if (err.code === "ECONNREFUSED") {
        resolve("closed");
      } else {
        resolve("filtered");
      }
    });

    socket.connect(port, host);
  });
}

export async function portScan(
  target: string,
  options?: { ports?: number[]; timeout?: number; concurrency?: number }
): Promise<PortScanResult> {
  let host: string;
  try {
    const url = new URL(target.includes("://") ? target : `https://${target}`);
    host = url.hostname;
  } catch {
    host = target.split(":")[0];
  }

  const ports = options?.ports || Object.keys(COMMON_PORTS).map(Number);
  const timeout = options?.timeout || 3000;
  const concurrency = options?.concurrency || 20;

  const openPorts: PortResult[] = [];
  let closedCount = 0;
  let filteredCount = 0;

  // Scan in batches for concurrency control
  for (let i = 0; i < ports.length; i += concurrency) {
    const batch = ports.slice(i, i + concurrency);
    const results = await Promise.all(
      batch.map(async (port) => {
        const state = await scanPort(host, port, timeout);
        return { port, state };
      })
    );

    for (const { port, state } of results) {
      if (state === "open") {
        const info = COMMON_PORTS[port] || { service: "Unknown", risk: "info" as const };
        openPorts.push({ port, state, service: info.service, risk: info.risk });
      } else if (state === "closed") {
        closedCount++;
      } else {
        filteredCount++;
      }
    }
  }

  openPorts.sort((a, b) => a.port - b.port);

  // Risk assessment
  const riskAssessment: string[] = [];
  const criticalPorts = openPorts.filter((p) => p.risk === "critical");
  const highPorts = openPorts.filter((p) => p.risk === "high");

  if (criticalPorts.length > 0) {
    riskAssessment.push(
      `CRITICAL: ${criticalPorts.length} critical-risk port(s) open: ${criticalPorts.map((p) => `${p.port}/${p.service}`).join(", ")}. These services should not be exposed to the internet.`
    );
  }

  if (highPorts.length > 0) {
    riskAssessment.push(
      `HIGH: ${highPorts.length} high-risk port(s) open: ${highPorts.map((p) => `${p.port}/${p.service}`).join(", ")}. Consider restricting access.`
    );
  }

  // Specific service warnings
  if (openPorts.some((p) => p.port === 23)) {
    riskAssessment.push("CRITICAL: Telnet (23) is open — transmits credentials in plaintext. Replace with SSH immediately.");
  }
  if (openPorts.some((p) => p.port === 3389)) {
    riskAssessment.push("CRITICAL: RDP (3389) is exposed — major ransomware attack vector. Use VPN or restrict to trusted IPs.");
  }
  if (openPorts.some((p) => [3306, 5432, 1433, 1521, 27017].includes(p.port))) {
    riskAssessment.push("CRITICAL: Database port(s) exposed to the internet — immediate data breach risk.");
  }
  if (openPorts.some((p) => p.port === 6379)) {
    riskAssessment.push("CRITICAL: Redis (6379) exposed — often unprotected, allows remote code execution.");
  }

  if (riskAssessment.length === 0) {
    riskAssessment.push("No critical or high-risk ports detected. Attack surface appears minimal.");
  }

  let summary = `Port scan of ${host}: ${openPorts.length} open, ${closedCount} closed, ${filteredCount} filtered (${ports.length} scanned). `;
  if (criticalPorts.length > 0) {
    summary += `${criticalPorts.length} CRITICAL-risk ports exposed. `;
  }
  summary += `Open services: ${openPorts.map((p) => `${p.port}/${p.service}`).join(", ") || "none"}`;

  return {
    host,
    openPorts,
    closedPorts: closedCount,
    filteredPorts: filteredCount,
    totalScanned: ports.length,
    riskAssessment,
    summary,
  };
}
