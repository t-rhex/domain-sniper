/**
 * Portfolio management — SQLite-backed domain portfolio tracking
 */

import {
  addPortfolioDomain as dbAddPortfolio,
  removePortfolioDomain as dbRemovePortfolio,
  getPortfolioDomains,
  getPortfolioExpiring,
  getPortfolioStatsDb,
} from "../db.js";
import { isValidDomain } from "../validate.js";

export interface PortfolioDomain {
  domain: string;
  registrar: string;
  purchaseDate: string;
  expiryDate: string;
  purchasePrice: number;
  renewalPrice: number;
  currency: string;
  autoRenew: boolean;
  tags: string[];
  notes: string;
  addedAt: string;
}

export interface Portfolio {
  domains: PortfolioDomain[];
  totalSpent: number;
  currency: string;
}

function dbRowToPortfolioDomain(row: any): PortfolioDomain {
  return {
    domain: row.domain,
    registrar: row.registrar || "unknown",
    purchaseDate: row.purchase_date || "",
    expiryDate: row.expiry_date || "",
    purchasePrice: row.purchase_price || 0,
    renewalPrice: row.renewal_price || 0,
    currency: row.currency || "USD",
    autoRenew: !!row.auto_renew,
    tags: (() => { try { return JSON.parse(row.tags || "[]"); } catch { return []; } })(),
    notes: row.notes || "",
    addedAt: row.added_at || "",
  };
}

export function loadPortfolio(): Portfolio {
  const rows = getPortfolioDomains();
  const domains = rows.map(dbRowToPortfolioDomain);
  const totalSpent = domains.reduce((sum, d) => sum + d.purchasePrice, 0);
  return { domains, totalSpent, currency: "USD" };
}

export function savePortfolio(_portfolio: Portfolio): void {
  // No-op: SQLite handles persistence automatically
  // Kept for backward compatibility
}

export function addToPortfolio(
  domain: string,
  details: Partial<PortfolioDomain> = {}
): Portfolio {
  if (!isValidDomain(domain)) throw new Error(`Invalid domain: ${domain}`);
  dbAddPortfolio(domain, {
    registrar: details.registrar,
    purchaseDate: details.purchaseDate,
    expiryDate: details.expiryDate,
    purchasePrice: details.purchasePrice,
    renewalPrice: details.renewalPrice,
    currency: details.currency,
    autoRenew: details.autoRenew,
    tags: details.tags,
    notes: details.notes,
  });
  return loadPortfolio();
}

export function removeFromPortfolio(domain: string): Portfolio {
  dbRemovePortfolio(domain);
  return loadPortfolio();
}

export function getExpiringDomains(withinDays: number = 30): PortfolioDomain[] {
  return getPortfolioExpiring(withinDays).map(dbRowToPortfolioDomain);
}

export function getPortfolioStats(): {
  total: number;
  totalSpent: number;
  expiringIn30: number;
  expiringIn90: number;
  byRegistrar: Record<string, number>;
} {
  return getPortfolioStatsDb();
}
