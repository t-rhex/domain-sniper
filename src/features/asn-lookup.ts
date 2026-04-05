import { execFile } from "child_process";
import { promisify } from "util";
import { assertValidDomain } from "../validate.js";

const execFileAsync = promisify(execFile);

export interface AsnResult {
  domain: string;
  ip: string | null;
  asn: string | null;
  asnName: string | null;
  org: string | null;
  country: string | null;
  city: string | null;
  region: string | null;
  isp: string | null;
  error: string | null;
}

export async function lookupAsn(domain: string): Promise<AsnResult> {
  assertValidDomain(domain);

  const result: AsnResult = {
    domain, ip: null, asn: null, asnName: null,
    org: null, country: null, city: null, region: null, isp: null, error: null,
  };

  try {
    // Resolve IP
    try {
      const { stdout } = await execFileAsync("dig", ["+short", domain, "A"], { timeout: 5000 });
      result.ip = stdout.trim().split("\n")[0] || null;
    } catch {}

    if (!result.ip) {
      result.error = "Could not resolve IP";
      return result;
    }

    // Use ip-api.com (free, 45 req/min, no key needed)
    try {
      const resp = await fetch(
        `http://ip-api.com/json/${encodeURIComponent(result.ip)}?fields=status,country,regionName,city,isp,org,as,asname`,
        { signal: AbortSignal.timeout(8000) }
      );
      const data = await resp.json() as {
        status?: string;
        country?: string;
        regionName?: string;
        city?: string;
        isp?: string;
        org?: string;
        as?: string;
        asname?: string;
      };

      if (data.status === "success") {
        result.country = data.country || null;
        result.region = data.regionName || null;
        result.city = data.city || null;
        result.isp = data.isp || null;
        result.org = data.org || null;
        result.asn = data.as || null;
        result.asnName = data.asname || null;
      }
    } catch {}

    // Fallback: DNS-based ASN lookup via Team Cymru
    if (!result.asn && result.ip) {
      try {
        const reversed = result.ip.split(".").reverse().join(".");
        const { stdout } = await execFileAsync(
          "dig", ["+short", `${reversed}.origin.asn.cymru.com`, "TXT"],
          { timeout: 5000 }
        );
        const txt = stdout.trim().replace(/"/g, "");
        // Format: "ASN | IP/Prefix | CC | Registry | Date"
        const parts = txt.split("|").map((p) => p.trim());
        if (parts.length >= 3) {
          result.asn = parts[0] ? `AS${parts[0]}` : null;
          result.country = parts[2] || null;
        }
      } catch {}
    }

    return result;
  } catch (err: unknown) {
    result.error = err instanceof Error ? err.message : "ASN lookup failed";
    return result;
  }
}
