import { execFile } from "child_process";
import { promisify } from "util";
import { assertValidDomain } from "../validate.js";

const execFileAsync = promisify(execFile);

export interface ReverseIpResult {
  domain: string;
  ip: string | null;
  sharedDomains: string[];
  source: string;
  error: string | null;
}

async function resolveIp(domain: string): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync("dig", ["+short", domain, "A"], { timeout: 5000 });
    return stdout.trim().split("\n")[0] || null;
  } catch {
    return null;
  }
}

export async function reverseIpLookup(domain: string): Promise<ReverseIpResult> {
  assertValidDomain(domain);

  const result: ReverseIpResult = {
    domain,
    ip: null,
    sharedDomains: [],
    source: "",
    error: null,
  };

  try {
    result.ip = await resolveIp(domain);
    if (!result.ip) {
      result.error = "Could not resolve IP";
      return result;
    }

    // Try HackerTarget free API (50 queries/day without API key)
    try {
      const resp = await fetch(
        `https://api.hackertarget.com/reverseiplookup/?q=${encodeURIComponent(result.ip)}`,
        { signal: AbortSignal.timeout(10000) }
      );
      const text = await resp.text();
      if (!text.includes("error") && !text.includes("API count exceeded")) {
        const domains = text.trim().split("\n").filter((d) => d && d !== domain && d.includes("."));
        result.sharedDomains = domains.slice(0, 50);
        result.source = "HackerTarget";
        return result;
      }
    } catch {}

    // Fallback: PTR record lookup
    try {
      const reversed = result.ip.split(".").reverse().join(".");
      const { stdout } = await execFileAsync("dig", ["+short", `${reversed}.in-addr.arpa`, "PTR"], { timeout: 5000 });
      const ptrs = stdout.trim().split("\n").filter(Boolean);
      if (ptrs.length > 0) {
        result.sharedDomains = ptrs.map((p) => p.replace(/\.$/, ""));
        result.source = "PTR";
      }
    } catch {}

    return result;
  } catch (err: unknown) {
    result.error = err instanceof Error ? err.message : "Reverse IP lookup failed";
    return result;
  }
}
