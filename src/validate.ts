/**
 * Input validation utilities for domain names, session IDs, and file paths
 */

import { resolve, normalize } from "path";

export const DOMAIN_RE =
  /^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$/;

/**
 * Check if a string is a valid domain name
 */
export function isValidDomain(domain: string): boolean {
  if (domain.length > 253) return false;
  return DOMAIN_RE.test(domain);
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
 * Filter a list of domains to only valid ones
 */
export function sanitizeDomainList(domains: string[]): string[] {
  return domains.filter(isValidDomain);
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
