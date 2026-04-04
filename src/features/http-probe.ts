import { assertValidDomain } from "../validate.js";
import type { HttpProbeResult } from "../types.js";

const PARKED_INDICATORS = [
  "parked", "for sale", "buy this domain", "domain parking",
  "godaddy", "sedo", "afternic", "hugedomains", "dan.com",
  "this domain is for sale", "under construction",
];

export async function httpProbe(domain: string): Promise<HttpProbeResult> {
  assertValidDomain(domain);

  for (const scheme of ["https", "http"] as const) {
    try {
      const resp = await fetch(`${scheme}://${domain}`, {
        redirect: "manual",
        signal: AbortSignal.timeout(8000),
        headers: { "User-Agent": "DomainSniper/2.0" },
      });

      const redirectUrl = resp.status >= 300 && resp.status < 400
        ? resp.headers.get("location")
        : null;

      let parked = false;
      try {
        const body = await resp.text();
        const lower = body.toLowerCase();
        parked = PARKED_INDICATORS.some((ind) => lower.includes(ind));
      } catch {}

      return {
        status: resp.status,
        redirectUrl,
        server: resp.headers.get("server"),
        parked,
        reachable: true,
        error: null,
      };
    } catch {
      continue;
    }
  }

  return { status: null, redirectUrl: null, server: null, parked: false, reachable: false, error: "Unreachable" };
}
