/**
 * Export results to CSV / JSON
 */

import { writeFileSync } from "fs";
import { scoreDomain } from "./scoring.js";
import { safePath } from "../validate.js";
import type { DomainEntry } from "../types.js";

interface ExportEntry {
  domain: string;
  status: string;
  available: boolean;
  expired: boolean;
  confidence: string;
  registrar: string;
  expiryDate: string;
  createdDate: string;
  nameServers: string;
  score: number;
  grade: string;
  price: string;
  registered: boolean;
}

function toExportEntry(d: DomainEntry): ExportEntry {
  const score = scoreDomain(d.domain);
  return {
    domain: d.domain,
    status: d.status,
    available: d.status === "available",
    expired: d.status === "expired",
    confidence: d.verification?.confidence || "",
    registrar: d.whois?.registrar || "",
    expiryDate: d.whois?.expiryDate || "",
    createdDate: d.whois?.createdDate || "",
    nameServers: (d.whois?.nameServers || []).join("; "),
    score: score.total,
    grade: score.total >= 85 ? "A+" : score.total >= 75 ? "A" : score.total >= 65 ? "B+" : score.total >= 55 ? "B" : score.total >= 45 ? "C+" : score.total >= 35 ? "C" : "D",
    price: d.registrarCheck?.price ? `${d.registrarCheck.price}` : "",
    registered: d.status === "registered",
  };
}

export function exportToCSV(domains: DomainEntry[], filePath: string): string {
  if (domains.length === 0) throw new Error("No domains to export");
  const safe = safePath(filePath, [process.cwd()]);
  const entries = domains.map(toExportEntry);
  const headers = Object.keys(entries[0] || {});
  const rows = entries.map((e) =>
    headers.map((h) => {
      const val = String((e as any)[h] ?? "");
      return val.includes(",") || val.includes('"') ? `"${val.replace(/"/g, '""')}"` : val;
    }).join(",")
  );
  const csv = [headers.join(","), ...rows].join("\n");
  writeFileSync(safe, csv, "utf-8");
  return safe;
}

export function exportToJSON(domains: DomainEntry[], filePath: string): string {
  if (domains.length === 0) throw new Error("No domains to export");
  const safe = safePath(filePath, [process.cwd()]);
  const entries = domains.map(toExportEntry);
  const json = JSON.stringify({
    exported: new Date().toISOString(),
    total: entries.length,
    available: entries.filter((e) => e.available).length,
    expired: entries.filter((e) => e.expired).length,
    domains: entries,
  }, null, 2);
  writeFileSync(safe, json, "utf-8");
  return safe;
}
