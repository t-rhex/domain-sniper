import { assertValidDomain } from "../validate.js";

export interface MarketplaceListing {
  source: string;
  listed: boolean;
  price: number | null;
  currency: string;
  url: string | null;
  error: string | null;
}

async function checkEstibot(domain: string): Promise<MarketplaceListing> {
  try {
    const resp = await fetch(
      `https://www.estibot.com/api/v1/appraisal?domain=${encodeURIComponent(domain)}`,
      { signal: AbortSignal.timeout(8000) }
    );
    if (!resp.ok) {
      return { source: "estibot", listed: false, price: null, currency: "USD", url: null, error: `HTTP ${resp.status}` };
    }
    const text = await resp.text();
    // Estibot returns estimated value, not a listing
    const match = text.match(/"appraised_value"\s*:\s*(\d+)/);
    const value = match?.[1] ? parseInt(match[1], 10) : null;
    return {
      source: "estibot",
      listed: false,
      price: value,
      currency: "USD",
      url: `https://www.estibot.com/appraisal/${encodeURIComponent(domain)}`,
      error: null,
    };
  } catch (err: unknown) {
    return { source: "estibot", listed: false, price: null, currency: "USD", url: null, error: err instanceof Error ? err.message : "Failed" };
  }
}

async function checkSedo(domain: string): Promise<MarketplaceListing> {
  try {
    const resp = await fetch(
      `https://sedo.com/search/searchresult.php?keyword=${encodeURIComponent(domain)}&trackingid=domain-sniper`,
      { signal: AbortSignal.timeout(8000), headers: { "User-Agent": "DomainSniper/2.0" } }
    );
    const listed = resp.ok;
    return {
      source: "sedo",
      listed,
      price: null,
      currency: "USD",
      url: `https://sedo.com/search/details/?domain=${encodeURIComponent(domain)}`,
      error: null,
    };
  } catch (err: unknown) {
    return { source: "sedo", listed: false, price: null, currency: "USD", url: null, error: err instanceof Error ? err.message : "Failed" };
  }
}

export async function checkMarketplaces(domain: string): Promise<MarketplaceListing[]> {
  assertValidDomain(domain);
  const results = await Promise.allSettled([
    checkEstibot(domain),
    checkSedo(domain),
  ]);
  return results.map((r) =>
    r.status === "fulfilled"
      ? r.value
      : { source: "unknown", listed: false, price: null, currency: "USD", url: null, error: r.reason?.message || "Failed" }
  );
}
