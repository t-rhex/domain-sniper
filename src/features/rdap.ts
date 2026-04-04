import { assertValidDomain } from "../validate.js";

export interface RdapResult {
  domain: string;
  status: string[];
  registrar: string | null;
  registrarUrl: string | null;
  createdDate: string | null;
  updatedDate: string | null;
  expiryDate: string | null;
  nameServers: string[];
  available: boolean;
  error: string | null;
}

interface RdapResponse {
  handle?: string;
  ldhName?: string;
  status?: string[];
  entities?: Array<{
    roles?: string[];
    vcardArray?: [string, ...Array<[string, Record<string, unknown>, string, string]>];
    publicIds?: Array<{ type: string; identifier: string }>;
  }>;
  events?: Array<{ eventAction: string; eventDate: string }>;
  nameservers?: Array<{ ldhName?: string }>;
  links?: Array<{ rel?: string; href?: string }>;
  errorCode?: number;
}

// RDAP bootstrap: resolve TLD to the correct RDAP server
async function getRdapUrl(domain: string): Promise<string | null> {
  try {
    const resp = await fetch("https://data.iana.org/rdap/dns.json", {
      signal: AbortSignal.timeout(5000),
    });
    const data = await resp.json() as { services: [string[], string[]][] };
    const tld = domain.split(".").pop()?.toLowerCase() || "";
    for (const [tlds, urls] of data.services) {
      if (tlds.some((t) => t.toLowerCase() === tld)) {
        return urls[0] || null;
      }
    }
    return null;
  } catch {
    return null;
  }
}

export async function rdapLookup(domain: string): Promise<RdapResult> {
  assertValidDomain(domain);

  const result: RdapResult = {
    domain, status: [], registrar: null, registrarUrl: null,
    createdDate: null, updatedDate: null, expiryDate: null,
    nameServers: [], available: false, error: null,
  };

  try {
    const baseUrl = await getRdapUrl(domain);
    if (!baseUrl) {
      result.error = "No RDAP server for this TLD";
      return result;
    }

    const url = `${baseUrl.replace(/\/$/, "")}/domain/${encodeURIComponent(domain)}`;
    const resp = await fetch(url, {
      signal: AbortSignal.timeout(10000),
      headers: { Accept: "application/rdap+json" },
    });

    if (resp.status === 404) {
      result.available = true;
      return result;
    }

    if (!resp.ok) {
      result.error = `RDAP HTTP ${resp.status}`;
      return result;
    }

    const data = await resp.json() as RdapResponse;

    // Status
    result.status = data.status || [];

    // Registrar
    if (data.entities) {
      for (const entity of data.entities) {
        if (entity.roles?.includes("registrar")) {
          if (entity.vcardArray && entity.vcardArray.length > 1) {
            const vcard = entity.vcardArray[1];
            if (Array.isArray(vcard)) {
              for (const field of vcard) {
                if (Array.isArray(field) && field[0] === "fn") {
                  result.registrar = String(field[3] || "");
                }
              }
            }
          }
        }
      }
    }

    // Events (dates)
    if (data.events) {
      for (const event of data.events) {
        switch (event.eventAction) {
          case "registration": result.createdDate = event.eventDate; break;
          case "last changed": result.updatedDate = event.eventDate; break;
          case "expiration": result.expiryDate = event.eventDate; break;
        }
      }
    }

    // Nameservers
    if (data.nameservers) {
      result.nameServers = data.nameservers
        .map((ns) => ns.ldhName || "")
        .filter(Boolean);
    }

    return result;
  } catch (err: unknown) {
    result.error = err instanceof Error ? err.message : "RDAP lookup failed";
    return result;
  }
}
