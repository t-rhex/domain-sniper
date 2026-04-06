/**
 * Smart domain grouping — automatically categorize similar domains
 */

const STRIP_PREFIXES = ["get", "try", "use", "go", "my", "the", "hey", "super", "hyper", "ultra", "mega", "meta", "neo"];
const STRIP_SUFFIXES = ["app", "hq", "hub", "lab", "labs", "ify", "ize", "box", "kit", "now", "run"];

export interface DomainGroup {
  baseName: string;
  domains: string[];
  available: number;
  taken: number;
  expired: number;
  total: number;
}

/**
 * Extract the base/root name from a domain.
 * "getcoolstartup.com" → "coolstartup"
 * "coolstartupapp.dev" → "coolstartup"
 * "my-coolstartup.io" → "coolstartup"
 */
export function extractBaseName(domain: string): string {
  // Get the SLD (second-level domain) — everything before the TLD
  const parts = domain.toLowerCase().split(".");
  let name = parts[0] || domain;

  // Remove hyphens for comparison
  name = name.replace(/-/g, "");

  // Strip known prefixes
  for (const prefix of STRIP_PREFIXES) {
    if (name.startsWith(prefix) && name.length > prefix.length + 3) {
      name = name.slice(prefix.length);
      break; // Only strip one prefix
    }
  }

  // Strip known suffixes
  for (const suffix of STRIP_SUFFIXES) {
    if (name.endsWith(suffix) && name.length > suffix.length + 3) {
      name = name.slice(0, -suffix.length);
      break; // Only strip one suffix
    }
  }

  return name;
}

/**
 * Group a list of domain entries by their base name.
 * Returns groups sorted by size (largest first), with singles at the end.
 */
export function groupDomains(
  domains: Array<{ domain: string; status: string }>
): DomainGroup[] {
  const groupMap = new Map<string, DomainGroup>();

  for (const d of domains) {
    const base = extractBaseName(d.domain);

    let group = groupMap.get(base);
    if (!group) {
      group = { baseName: base, domains: [], available: 0, taken: 0, expired: 0, total: 0 };
      groupMap.set(base, group);
    }

    group.domains.push(d.domain);
    group.total++;

    if (d.status === "available") group.available++;
    else if (d.status === "expired") group.expired++;
    else if (d.status === "taken") group.taken++;
  }

  // Sort: multi-domain groups first (by size desc), then singles
  const groups = Array.from(groupMap.values());
  groups.sort((a, b) => {
    if (a.total > 1 && b.total <= 1) return -1;
    if (a.total <= 1 && b.total > 1) return 1;
    return b.total - a.total;
  });

  return groups;
}

/**
 * Check if grouping would be useful (more than 1 group with 2+ domains)
 */
export function shouldShowGroups(domains: Array<{ domain: string; status: string }>): boolean {
  if (domains.length < 4) return false;
  const groups = groupDomains(domains);
  return groups.filter((g) => g.total >= 2).length >= 1;
}
