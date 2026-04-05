import { execFile } from "child_process";
import { promisify } from "util";
import { assertValidDomain } from "../validate.js";

const execFileAsync = promisify(execFile);

const COMMON_SUBDOMAINS = [
  "www", "mail", "ftp", "smtp", "pop", "imap",
  "api", "app", "cdn", "dev", "staging", "beta",
  "admin", "portal", "blog", "shop", "store",
  "ns1", "ns2", "mx", "vpn", "remote",
  "docs", "wiki", "git", "ci", "status",
];

export interface SubdomainResult {
  subdomain: string;
  full: string;
  resolved: boolean;
  ip: string | null;
}

export async function discoverSubdomains(
  domain: string,
  subdomains: string[] = COMMON_SUBDOMAINS
): Promise<SubdomainResult[]> {
  assertValidDomain(domain);

  const results: SubdomainResult[] = [];
  const BATCH = 10;

  for (let i = 0; i < subdomains.length; i += BATCH) {
    const batch = subdomains.slice(i, i + BATCH);
    const batchResults = await Promise.all(
      batch.map(async (sub) => {
        const full = `${sub}.${domain}`;
        try {
          const { stdout } = await execFileAsync("dig", ["+short", full, "A"], { timeout: 5000 });
          const ip = stdout.trim().split("\n")[0] || null;
          return { subdomain: sub, full, resolved: !!ip, ip };
        } catch {
          return { subdomain: sub, full, resolved: false, ip: null };
        }
      })
    );
    results.push(...batchResults);
  }

  return results;
}

export function getActiveSubdomains(results: SubdomainResult[]): SubdomainResult[] {
  return results.filter((r) => r.resolved);
}
