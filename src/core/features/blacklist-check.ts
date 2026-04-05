import { execFile } from "child_process";
import { promisify } from "util";
import { assertValidDomain } from "../validate.js";

const execFileAsync = promisify(execFile);

export interface BlacklistResult {
  domain: string;
  listed: boolean;
  lists: BlacklistEntry[];
  cleanCount: number;
  listedCount: number;
}

export interface BlacklistEntry {
  name: string;
  listed: boolean;
  detail: string | null;
}

// DNS-based blacklists for domain reputation
const DOMAIN_BLACKLISTS = [
  { name: "Spamhaus DBL", suffix: "dbl.spamhaus.org" },
  { name: "SURBL", suffix: "multi.surbl.org" },
  { name: "URIBL", suffix: "multi.uribl.com" },
  { name: "Spamhaus ZEN", suffix: "zen.spamhaus.org" },
  { name: "Barracuda", suffix: "b.barracudacentral.org" },
  { name: "SpamCop", suffix: "bl.spamcop.net" },
  { name: "PhishTank", suffix: "phishtank.org" },
  { name: "SORBS", suffix: "dnsbl.sorbs.net" },
];

async function checkBlacklist(
  domain: string,
  bl: { name: string; suffix: string }
): Promise<BlacklistEntry> {
  try {
    const query = `${domain}.${bl.suffix}`;
    const { stdout } = await execFileAsync("dig", ["+short", query, "A"], { timeout: 5000 });
    const result = stdout.trim();
    // A response (typically 127.0.0.x) means listed
    if (result && result.startsWith("127.")) {
      return { name: bl.name, listed: true, detail: result };
    }
    return { name: bl.name, listed: false, detail: null };
  } catch {
    // NXDOMAIN or timeout = not listed (which is good)
    return { name: bl.name, listed: false, detail: null };
  }
}

export async function checkBlacklists(domain: string): Promise<BlacklistResult> {
  assertValidDomain(domain);

  const results = await Promise.all(
    DOMAIN_BLACKLISTS.map((bl) => checkBlacklist(domain, bl))
  );

  const listedCount = results.filter((r) => r.listed).length;
  return {
    domain,
    listed: listedCount > 0,
    lists: results,
    cleanCount: results.length - listedCount,
    listedCount,
  };
}
