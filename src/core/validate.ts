/**
 * Input validation utilities for domain names, session IDs, and file paths
 */

import { resolve, normalize } from "path";

export const DOMAIN_RE =
  /^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$/;

/**
 * Check if a string is a valid domain name (case-insensitive)
 */
export function isValidDomain(domain: string): boolean {
  if (domain.length > 253) return false;
  return DOMAIN_RE.test(domain.toLowerCase());
}

/**
 * Assert that a string is a valid domain name, throwing if not
 */
export function assertValidDomain(domain: string): void {
  if (!isValidDomain(domain)) {
    throw new Error(`Invalid domain: ${domain}`);
  }
}

/**
 * Filter and normalize a list of domains to only valid ones (lowercased)
 */
export function sanitizeDomainList(domains: string[]): string[] {
  return domains
    .map((d) => d.toLowerCase())
    .filter(isValidDomain);
}

// ── TLD typo detection ──────────────────────────────────────

const COMMON_TLDS = new Set([
  "com", "net", "org", "io", "dev", "app", "co", "me", "info", "biz",
  "xyz", "tech", "ai", "sh", "gg", "cc", "to", "so", "run", "live",
  "site", "online", "store", "cloud", "pro", "in", "us", "uk", "de",
  "fr", "jp", "cn", "au", "ca", "nl", "eu", "ru", "br", "it", "es",
  "se", "no", "fi", "dk", "pl", "cz", "at", "ch", "be", "ie", "nz",
  "mx", "ar", "cl", "za", "sg", "hk", "tw", "kr", "id", "th", "ph",
  "edu", "gov", "mil", "int",
]);

const TLD_CORRECTIONS: Record<string, string> = {
  "commm": "com", "comm": "com", "con": "com", "vom": "com", "cim": "com", "cm": "com",
  "conn": "com", "coom": "com", "xom": "com",
  "nett": "net", "ner": "net", "met": "net",
  "orgg": "org", "rog": "org",
  "ioo": "io", "oi": "io",
  "deev": "dev", "dve": "dev",
  "appp": "app", "ap": "app",
};

/**
 * Detect likely TLD typos and return a corrected domain, or null if no typo detected.
 */
export function detectTldTypo(domain: string): string | null {
  const parts = domain.toLowerCase().split(".");
  if (parts.length < 2) return null;
  const tld = parts[parts.length - 1]!;

  // Check known corrections
  const correction = TLD_CORRECTIONS[tld];
  if (correction) {
    return parts.slice(0, -1).join(".") + "." + correction;
  }

  // Check if TLD exists in common list — no suggestion needed
  if (!COMMON_TLDS.has(tld)) {
    // Try to find closest match (simple 1-char edit distance)
    for (const known of COMMON_TLDS) {
      if (Math.abs(tld.length - known.length) <= 1 && levenshtein1(tld, known)) {
        return parts.slice(0, -1).join(".") + "." + known;
      }
    }
  }

  return null;
}

/**
 * Check if two strings differ by at most 1 edit (insert, delete, or substitute)
 */
function levenshtein1(a: string, b: string): boolean {
  if (a === b) return true;
  if (Math.abs(a.length - b.length) > 1) return false;

  if (a.length === b.length) {
    // Check for single substitution
    let diffs = 0;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) diffs++;
      if (diffs > 1) return false;
    }
    return diffs === 1;
  }

  // Check for single insert/delete
  const longer = a.length > b.length ? a : b;
  const shorter = a.length > b.length ? b : a;
  let i = 0, j = 0, diffs = 0;
  while (i < longer.length && j < shorter.length) {
    if (longer[i] !== shorter[j]) {
      diffs++;
      if (diffs > 1) return false;
      i++;
    } else {
      i++;
      j++;
    }
  }
  return true;
}

/**
 * Check if a string is a valid session ID (alphanumeric + hyphens, max 100 chars)
 */
export function isValidSessionId(id: string): boolean {
  if (id.length === 0 || id.length > 100) return false;
  return /^[a-z0-9\-]+$/.test(id);
}

/**
 * Resolve and normalize a file path, ensuring it falls within one of the allowed root directories.
 * Throws if the resolved path is outside all allowed roots.
 */
export function safePath(input: string, allowedRoots: string[]): string {
  const resolved = normalize(resolve(input));
  const isAllowed = allowedRoots.some((root) => {
    const normalizedRoot = normalize(resolve(root));
    return resolved.startsWith(normalizedRoot + "/") || resolved === normalizedRoot;
  });
  if (!isAllowed) {
    throw new Error(`Path "${input}" is outside allowed roots`);
  }
  return resolved;
}
