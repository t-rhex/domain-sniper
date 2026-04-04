import { readFileSync, writeFileSync, existsSync, mkdirSync } from "fs";
import { join } from "path";
import { homedir } from "os";
import { isValidDomain } from "../validate.js";

const PORTFOLIO_DIR = join(homedir(), ".domain-sniper");
const PORTFOLIO_FILE = join(PORTFOLIO_DIR, "portfolio.json");

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

function ensureDir(): void {
  if (!existsSync(PORTFOLIO_DIR)) {
    mkdirSync(PORTFOLIO_DIR, { recursive: true });
  }
}

export function loadPortfolio(): Portfolio {
  ensureDir();
  if (!existsSync(PORTFOLIO_FILE)) {
    return { domains: [], totalSpent: 0, currency: "USD" };
  }
  try {
    const content = readFileSync(PORTFOLIO_FILE, "utf-8");
    const parsed = JSON.parse(content);
    if (!parsed || !Array.isArray(parsed.domains)) {
      return { domains: [], totalSpent: 0, currency: "USD" };
    }
    return parsed as Portfolio;
  } catch {
    return { domains: [], totalSpent: 0, currency: "USD" };
  }
}

export function savePortfolio(portfolio: Portfolio): void {
  ensureDir();
  const updated = {
    ...portfolio,
    totalSpent: portfolio.domains.reduce((sum, d) => sum + d.purchasePrice, 0),
  };
  writeFileSync(PORTFOLIO_FILE, JSON.stringify(updated, null, 2), "utf-8");
}

export function addToPortfolio(
  domain: string,
  details: Partial<PortfolioDomain> = {}
): Portfolio {
  if (!isValidDomain(domain)) throw new Error(`Invalid domain: ${domain}`);
  const portfolio = loadPortfolio();

  const existing = portfolio.domains.findIndex((d) => d.domain === domain);
  const entry: PortfolioDomain = {
    domain,
    registrar: details.registrar || "unknown",
    purchaseDate: details.purchaseDate || new Date().toISOString().split("T")[0]!,
    expiryDate: details.expiryDate || "",
    purchasePrice: details.purchasePrice || 0,
    renewalPrice: details.renewalPrice || 0,
    currency: details.currency || "USD",
    autoRenew: details.autoRenew ?? false,
    tags: details.tags || [],
    notes: details.notes || "",
    addedAt: new Date().toISOString(),
  };

  if (existing >= 0) {
    const updatedDomains = [...portfolio.domains];
    updatedDomains[existing] = entry;
    const updatedPortfolio = { ...portfolio, domains: updatedDomains };
    savePortfolio(updatedPortfolio);
    return updatedPortfolio;
  } else {
    const updatedPortfolio = { ...portfolio, domains: [...portfolio.domains, entry] };
    savePortfolio(updatedPortfolio);
    return updatedPortfolio;
  }
}

export function removeFromPortfolio(domain: string): Portfolio {
  const portfolio = loadPortfolio();
  const updatedPortfolio = {
    ...portfolio,
    domains: portfolio.domains.filter((d) => d.domain !== domain),
  };
  savePortfolio(updatedPortfolio);
  return updatedPortfolio;
}

export function getExpiringDomains(withinDays: number = 30): PortfolioDomain[] {
  const portfolio = loadPortfolio();
  const now = Date.now();
  return portfolio.domains.filter((d) => {
    if (!d.expiryDate) return false;
    const expiry = new Date(d.expiryDate).getTime();
    const daysLeft = (expiry - now) / 86400000;
    return daysLeft >= 0 && daysLeft <= withinDays;
  });
}

export function getPortfolioStats(): {
  total: number;
  totalSpent: number;
  expiringIn30: number;
  expiringIn90: number;
  byRegistrar: Record<string, number>;
} {
  const portfolio = loadPortfolio();
  const byRegistrar: Record<string, number> = {};
  for (const d of portfolio.domains) {
    byRegistrar[d.registrar] = (byRegistrar[d.registrar] || 0) + 1;
  }
  return {
    total: portfolio.domains.length,
    totalSpent: portfolio.totalSpent,
    expiringIn30: getExpiringDomains(30).length,
    expiringIn90: getExpiringDomains(90).length,
    byRegistrar,
  };
}
