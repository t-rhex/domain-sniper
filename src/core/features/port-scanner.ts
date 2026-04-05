import { assertValidDomain } from "../validate.js";
import { connect } from "net";

export interface PortResult {
  port: number;
  service: string;
  open: boolean;
  banner: string | null;
}

export interface PortScanResult {
  domain: string;
  ip: string | null;
  openPorts: PortResult[];
  closedCount: number;
  scanTime: number;
  error: string | null;
}

const COMMON_PORTS: { port: number; service: string }[] = [
  { port: 21, service: "FTP" },
  { port: 22, service: "SSH" },
  { port: 25, service: "SMTP" },
  { port: 53, service: "DNS" },
  { port: 80, service: "HTTP" },
  { port: 110, service: "POP3" },
  { port: 143, service: "IMAP" },
  { port: 443, service: "HTTPS" },
  { port: 465, service: "SMTPS" },
  { port: 587, service: "Submission" },
  { port: 993, service: "IMAPS" },
  { port: 995, service: "POP3S" },
  { port: 3000, service: "Dev Server" },
  { port: 3306, service: "MySQL" },
  { port: 5432, service: "PostgreSQL" },
  { port: 6379, service: "Redis" },
  { port: 8080, service: "HTTP Alt" },
  { port: 8443, service: "HTTPS Alt" },
  { port: 27017, service: "MongoDB" },
  { port: 9200, service: "Elasticsearch" },
];

function checkPort(host: string, port: number, timeoutMs: number = 3000): Promise<{ open: boolean; banner: string | null }> {
  return new Promise((resolve) => {
    const socket = connect({ host, port });
    let banner: string | null = null;

    const timer = setTimeout(() => {
      socket.destroy();
      resolve({ open: false, banner: null });
    }, timeoutMs);

    socket.on("connect", () => {
      clearTimeout(timer);
      // Try to grab a banner (wait briefly for data)
      const bannerTimer = setTimeout(() => {
        socket.destroy();
        resolve({ open: true, banner });
      }, 1500);

      socket.once("data", (data) => {
        clearTimeout(bannerTimer);
        banner = data.toString("utf-8").trim().slice(0, 200);
        socket.destroy();
        resolve({ open: true, banner });
      });
    });

    socket.on("error", () => {
      clearTimeout(timer);
      socket.destroy();
      resolve({ open: false, banner: null });
    });
  });
}

export async function scanPorts(
  domain: string,
  ports: { port: number; service: string }[] = COMMON_PORTS,
  concurrency: number = 10
): Promise<PortScanResult> {
  assertValidDomain(domain);
  const startTime = Date.now();

  const result: PortScanResult = {
    domain,
    ip: null,
    openPorts: [],
    closedCount: 0,
    scanTime: 0,
    error: null,
  };

  try {
    // Resolve domain to IP first
    const { execFile } = await import("child_process");
    const { promisify } = await import("util");
    const execFileAsync = promisify(execFile);
    try {
      const { stdout } = await execFileAsync("dig", ["+short", domain, "A"], { timeout: 5000 });
      result.ip = stdout.trim().split("\n")[0] || null;
    } catch {}

    const host = result.ip || domain;

    // Scan in batches
    for (let i = 0; i < ports.length; i += concurrency) {
      const batch = ports.slice(i, i + concurrency);
      const batchResults = await Promise.all(
        batch.map(async (p) => {
          const { open, banner } = await checkPort(host, p.port);
          return { port: p.port, service: p.service, open, banner };
        })
      );

      for (const r of batchResults) {
        if (r.open) {
          result.openPorts.push(r);
        } else {
          result.closedCount++;
        }
      }
    }
  } catch (err: unknown) {
    result.error = err instanceof Error ? err.message : "Port scan failed";
  }

  result.scanTime = Date.now() - startTime;
  return result;
}

export { COMMON_PORTS };
