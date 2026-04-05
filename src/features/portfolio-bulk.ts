import {
  getPortfolioDomains,
  updatePortfolioStatus,
  updatePortfolioCategory,
  addTransaction,
  removePortfolioDomain,
  type PortfolioStatus,
  type TransactionType,
  type DbPortfolioDomain,
} from "../db.js";
import { writeFileSync } from "fs";
import { getTaxExportData, getPortfolioPnL, getDomainPnL, getTransactions } from "../db.js";

export interface BulkResult {
  total: number;
  success: number;
  failed: number;
  errors: string[];
}

export function bulkUpdateStatus(domains: string[], status: PortfolioStatus): BulkResult {
  const result: BulkResult = { total: domains.length, success: 0, failed: 0, errors: [] };
  for (const domain of domains) {
    try {
      updatePortfolioStatus(domain, status);
      result.success++;
    } catch (err: unknown) {
      result.failed++;
      result.errors.push(`${domain}: ${err instanceof Error ? err.message : "failed"}`);
    }
  }
  return result;
}

export function bulkUpdateCategory(domains: string[], category: string): BulkResult {
  const result: BulkResult = { total: domains.length, success: 0, failed: 0, errors: [] };
  for (const domain of domains) {
    try {
      updatePortfolioCategory(domain, category);
      result.success++;
    } catch (err: unknown) {
      result.failed++;
      result.errors.push(`${domain}: ${err instanceof Error ? err.message : "failed"}`);
    }
  }
  return result;
}

export function bulkAddTransaction(
  domains: string[],
  type: TransactionType,
  amount: number,
  description: string = "",
  date?: string
): BulkResult {
  const result: BulkResult = { total: domains.length, success: 0, failed: 0, errors: [] };
  for (const domain of domains) {
    try {
      addTransaction(domain, type, amount, description, date);
      result.success++;
    } catch (err: unknown) {
      result.failed++;
      result.errors.push(`${domain}: ${err instanceof Error ? err.message : "failed"}`);
    }
  }
  return result;
}

export function bulkRemove(domains: string[]): BulkResult {
  const result: BulkResult = { total: domains.length, success: 0, failed: 0, errors: [] };
  for (const domain of domains) {
    try {
      removePortfolioDomain(domain);
      result.success++;
    } catch (err: unknown) {
      result.failed++;
      result.errors.push(`${domain}: ${err instanceof Error ? err.message : "failed"}`);
    }
  }
  return result;
}

// ─── Export ──────────────────────────────────────────────

export function exportPortfolioCSV(filePath: string): string {
  const domains = getPortfolioDomains();
  const headers = ["domain", "registrar", "status", "category", "purchase_date", "expiry_date", "purchase_price", "renewal_price", "estimated_value", "currency", "auto_renew", "tags", "notes"];
  const rows = domains.map((d) =>
    headers.map((h) => {
      const val = String((d as any)[h] ?? "");
      return val.includes(",") || val.includes('"') ? `"${val.replace(/"/g, '""')}"` : val;
    }).join(",")
  );
  const csv = [headers.join(","), ...rows].join("\n");
  writeFileSync(filePath, csv, "utf-8");
  return filePath;
}

export function exportTaxCSV(filePath: string, year: number): string {
  const data = getTaxExportData(year);
  const headers = ["domain", "purchase_date", "purchase_price", "sale_date", "sale_price", "holding_days", "profit", "currency"];
  const rows = data.map((d) => [
    d.domain, d.purchaseDate, d.purchasePrice, d.saleDate || "", d.salePrice ?? "", d.holdingDays ?? "", d.profit, d.currency,
  ].map((v) => {
    const s = String(v);
    return s.includes(",") ? `"${s}"` : s;
  }).join(","));
  const csv = [headers.join(","), ...rows].join("\n");
  writeFileSync(filePath, csv, "utf-8");
  return filePath;
}

export function exportTransactionsCSV(filePath: string, domain?: string): string {
  const txns = getTransactions(domain, 1000);
  const headers = ["id", "domain", "type", "amount", "currency", "description", "date"];
  const rows = txns.map((t) =>
    headers.map((h) => {
      const val = String((t as any)[h] ?? "");
      return val.includes(",") || val.includes('"') ? `"${val.replace(/"/g, '""')}"` : val;
    }).join(",")
  );
  const csv = [headers.join(","), ...rows].join("\n");
  writeFileSync(filePath, csv, "utf-8");
  return filePath;
}
