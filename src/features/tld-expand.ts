/**
 * TLD Expansion — enter "coolstartup" and check across all popular TLDs
 */

export const POPULAR_TLDS = [
  "com", "io", "dev", "ai", "app", "co", "net", "org",
  "xyz", "me", "tech", "so", "sh", "gg", "cc", "to",
  "cloud", "run", "live", "site", "online", "store",
] as const;

export const PREMIUM_TLDS = [
  "com", "io", "dev", "ai", "app", "co",
] as const;

export const STARTUP_TLDS = [
  "com", "io", "dev", "ai", "app", "co", "so", "sh", "gg", "run",
] as const;

export type TldPreset = "popular" | "premium" | "startup" | "all";

export function expandTlds(
  baseName: string,
  preset: TldPreset = "popular",
  customTlds?: string[]
): string[] {
  // Strip any existing TLD
  const name = baseName.replace(/\.[a-z]+$/i, "").trim().toLowerCase();
  if (!name) return [];

  if (customTlds && customTlds.length > 0) {
    return customTlds.map((tld) => `${name}.${tld.replace(/^\./, "")}`);
  }

  let tlds: readonly string[];
  switch (preset) {
    case "premium": tlds = PREMIUM_TLDS; break;
    case "startup": tlds = STARTUP_TLDS; break;
    case "all": tlds = POPULAR_TLDS; break;
    default: tlds = POPULAR_TLDS;
  }

  return tlds.map((tld) => `${name}.${tld}`);
}
