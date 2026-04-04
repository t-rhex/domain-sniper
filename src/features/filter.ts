/**
 * Filter & sort domain results
 */

import type { DomainScore } from "./scoring.js";
import { scoreDomain } from "./scoring.js";
import type { DomainEntry } from "../types.js";

export type SortField = "domain" | "status" | "score" | "expiry" | "price";
export type SortOrder = "asc" | "desc";
export type FilterStatus = "all" | "available" | "expired" | "taken" | "registered" | "actionable";

export interface FilterConfig {
  status: FilterStatus;
  search: string;
  sort: SortField;
  order: SortOrder;
  minScore: number;
}

export const DEFAULT_FILTER: FilterConfig = {
  status: "all",
  search: "",
  sort: "domain",
  order: "asc",
  minScore: 0,
};

export function filterDomains(domains: DomainEntry[], config: FilterConfig): DomainEntry[] {
  let filtered = [...domains];

  // Status filter
  if (config.status !== "all") {
    if (config.status === "actionable") {
      filtered = filtered.filter((d) => d.status === "available" || d.status === "expired");
    } else {
      filtered = filtered.filter((d) => d.status === config.status);
    }
  }

  // Search filter
  if (config.search) {
    const q = config.search.toLowerCase();
    filtered = filtered.filter((d) => d.domain.toLowerCase().includes(q));
  }

  // Score filter
  if (config.minScore > 0) {
    filtered = filtered.filter((d) => scoreDomain(d.domain).total >= config.minScore);
  }

  // Sort
  filtered.sort((a, b) => {
    let cmp = 0;
    switch (config.sort) {
      case "domain":
        cmp = a.domain.localeCompare(b.domain);
        break;
      case "status": {
        const order: Record<string, number> = { available: 0, expired: 1, registering: 2, registered: 3, taken: 4, error: 5, pending: 6, checking: 7 };
        cmp = (order[a.status] ?? 9) - (order[b.status] ?? 9);
        break;
      }
      case "score":
        cmp = scoreDomain(b.domain).total - scoreDomain(a.domain).total;
        break;
      case "expiry": {
        const aExp = a.whois?.expiryDate ? new Date(a.whois.expiryDate).getTime() : Infinity;
        const bExp = b.whois?.expiryDate ? new Date(b.whois.expiryDate).getTime() : Infinity;
        cmp = aExp - bExp;
        break;
      }
      case "price": {
        const aP = a.registrarCheck?.price ?? Infinity;
        const bP = b.registrarCheck?.price ?? Infinity;
        cmp = aP - bP;
        break;
      }
    }
    return config.order === "desc" ? -cmp : cmp;
  });

  return filtered;
}

export function nextStatus(current: FilterStatus): FilterStatus {
  const order: FilterStatus[] = ["all", "available", "expired", "taken", "registered", "actionable"];
  const idx = order.indexOf(current);
  return order[(idx + 1) % order.length]!;
}

export function nextSort(current: SortField): SortField {
  const order: SortField[] = ["domain", "status", "score", "expiry", "price"];
  const idx = order.indexOf(current);
  return order[(idx + 1) % order.length]!;
}
