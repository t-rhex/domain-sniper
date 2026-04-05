import { execFile } from "child_process";
import { promisify } from "util";
import { assertValidDomain } from "../validate.js";
import type { DnsDetails } from "../types.js";

const execFileAsync = promisify(execFile);

async function digQuery(domain: string, type: string): Promise<string[]> {
  try {
    const { stdout } = await execFileAsync("dig", ["+short", domain, type], { timeout: 10000 });
    return stdout.trim().split("\n").filter(Boolean);
  } catch {
    return [];
  }
}

export async function lookupDns(domain: string): Promise<DnsDetails> {
  assertValidDomain(domain);
  const [a, aaaa, mx, txt, cname] = await Promise.all([
    digQuery(domain, "A"),
    digQuery(domain, "AAAA"),
    digQuery(domain, "MX"),
    digQuery(domain, "TXT"),
    digQuery(domain, "CNAME"),
  ]);
  return { a, aaaa, mx, txt, cname };
}
