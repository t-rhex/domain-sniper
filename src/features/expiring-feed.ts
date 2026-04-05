import { assertValidDomain } from "../validate.js";

export interface ExpiringDomain {
  domain: string;
  expiryDate: string;
  deleteDate: string | null;
  registrar: string | null;
  age: string | null;
  source: string;
}

export interface ExpiringFeedConfig {
  apiKey?: string;      // WhoisFreaks API key (optional)
  tld?: string;         // Filter by TLD
  minAge?: number;      // Minimum domain age in years
  limit?: number;       // Max results
}

/**
 * Fetch expiring/dropped domains from WhoisFreaks API
 * Free tier: 100 requests/month
 * Get a key at: https://whoisfreaks.com/
 */
async function fetchFromWhoisFreaks(
  config: ExpiringFeedConfig
): Promise<ExpiringDomain[]> {
  if (!config.apiKey) return [];

  try {
    const params = new URLSearchParams({
      apiKey: config.apiKey,
      whoisType: "expiring",
    });
    if (config.tld) params.set("tld", config.tld);
    if (config.limit) params.set("page_size", String(Math.min(config.limit, 100)));

    const resp = await fetch(
      `https://api.whoisfreaks.com/v1.0/whois?${params.toString()}`,
      { signal: AbortSignal.timeout(15000) }
    );

    if (!resp.ok) return [];

    const data = await resp.json() as {
      whois_domains_list?: Array<{
        domain_name?: string;
        expiry_date?: string;
        create_date?: string;
        registrar_name?: string;
      }>;
    };

    if (!data.whois_domains_list) return [];

    return data.whois_domains_list.map((d) => ({
      domain: d.domain_name || "",
      expiryDate: d.expiry_date || "",
      deleteDate: null,
      registrar: d.registrar_name || null,
      age: d.create_date ? calculateAge(d.create_date) : null,
      source: "WhoisFreaks",
    })).filter((d) => d.domain);
  } catch {
    return [];
  }
}

/**
 * Check a specific list of domains for pending-delete status via RDAP
 */
export async function checkPendingDelete(domains: string[]): Promise<ExpiringDomain[]> {
  const results: ExpiringDomain[] = [];

  for (const domain of domains) {
    try {
      assertValidDomain(domain);
      const resp = await fetch(
        `https://rdap.org/domain/${encodeURIComponent(domain)}`,
        { signal: AbortSignal.timeout(8000) }
      );

      if (!resp.ok) continue;

      const data = await resp.json() as {
        status?: string[];
        events?: Array<{ eventAction: string; eventDate: string }>;
        entities?: Array<{ roles?: string[]; vcardArray?: unknown[] }>;
      };

      const status = data.status || [];
      const isPendingDelete = status.some((s) =>
        s.toLowerCase().includes("pending delete") ||
        s.toLowerCase().includes("redemption period") ||
        s.toLowerCase().includes("pendingdelete")
      );

      if (isPendingDelete) {
        let expiryDate = "";
        const registrar: string | null = null;
        let createdDate: string | null = null;

        if (data.events) {
          for (const event of data.events) {
            if (event.eventAction === "expiration") expiryDate = event.eventDate;
            if (event.eventAction === "registration") createdDate = event.eventDate;
          }
        }

        results.push({
          domain,
          expiryDate,
          deleteDate: null, // Not always available from RDAP
          registrar,
          age: createdDate ? calculateAge(createdDate) : null,
          source: "RDAP",
        });
      }

      // Rate limit
      await new Promise((r) => setTimeout(r, 500));
    } catch {
      continue;
    }
  }

  return results;
}

/**
 * Get a feed of expiring domains
 */
export async function getExpiringFeed(config: ExpiringFeedConfig = {}): Promise<ExpiringDomain[]> {
  const results: ExpiringDomain[] = [];

  // Try WhoisFreaks if API key provided
  const wfResults = await fetchFromWhoisFreaks(config);
  results.push(...wfResults);

  // Apply age filter
  if (config.minAge && config.minAge > 0) {
    return results.filter((d) => {
      if (!d.age) return false;
      const years = parseInt(d.age, 10);
      return !isNaN(years) && years >= config.minAge!;
    });
  }

  return results.slice(0, config.limit || 50);
}

function calculateAge(createDate: string): string | null {
  try {
    const created = new Date(createDate);
    if (isNaN(created.getTime())) return null;
    const years = Math.floor((Date.now() - created.getTime()) / (365.25 * 86400000));
    return `${years}y`;
  } catch {
    return null;
  }
}
