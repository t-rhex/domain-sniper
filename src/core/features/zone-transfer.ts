import { execFile } from "child_process";
import { promisify } from "util";
import { assertValidDomain } from "../validate.js";

const execFileAsync = promisify(execFile);

export interface ZoneTransferResult {
  domain: string;
  vulnerable: boolean;
  nameServers: string[];
  vulnerableNs: string[];
  records: string[];
  error: string | null;
}

async function getNameServers(domain: string): Promise<string[]> {
  try {
    const { stdout } = await execFileAsync("dig", ["+short", domain, "NS"], { timeout: 5000 });
    return stdout.trim().split("\n").filter(Boolean).map((ns) => ns.replace(/\.$/, ""));
  } catch {
    return [];
  }
}

async function attemptAxfr(domain: string, nameserver: string): Promise<{ success: boolean; records: string[] }> {
  try {
    const { stdout } = await execFileAsync(
      "dig", ["@" + nameserver, domain, "AXFR", "+noall", "+answer", "+time=5"],
      { timeout: 10000 }
    );
    const lines = stdout.trim().split("\n").filter((l) => l && !l.startsWith(";"));
    // If we got records, the zone transfer succeeded (vulnerable!)
    if (lines.length > 0) {
      return { success: true, records: lines.slice(0, 100) };
    }
    return { success: false, records: [] };
  } catch {
    return { success: false, records: [] };
  }
}

export async function checkZoneTransfer(domain: string): Promise<ZoneTransferResult> {
  assertValidDomain(domain);

  const result: ZoneTransferResult = {
    domain,
    vulnerable: false,
    nameServers: [],
    vulnerableNs: [],
    records: [],
    error: null,
  };

  try {
    result.nameServers = await getNameServers(domain);
    if (result.nameServers.length === 0) {
      result.error = "No nameservers found";
      return result;
    }

    for (const ns of result.nameServers) {
      const { success, records } = await attemptAxfr(domain, ns);
      if (success) {
        result.vulnerable = true;
        result.vulnerableNs.push(ns);
        result.records.push(...records);
      }
    }

    return result;
  } catch (err: unknown) {
    result.error = err instanceof Error ? err.message : "Zone transfer check failed";
    return result;
  }
}
