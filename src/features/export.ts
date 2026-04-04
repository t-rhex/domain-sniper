/**
 * Export results to CSV / JSON
 */

import { writeFileSync } from "fs";
import { scoreDomain } from "./scoring.js";

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

function toExportEntry(d: any): ExportEntry {
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

export function exportToCSV(domains: any[], filePath: string): string {
  const entries = domains.map(toExportEntry);
  const headers = Object.keys(entries[0] || {});
  const rows = entries.map((e) =>
    headers.map((h) => {
      const val = String((e as any)[h] ?? "");
      return val.includes(",") || val.includes('"') ? `"${val.replace(/"/g, '""')}"` : val;
    }).join(",")
  );
  const csv = [headers.join(","), ...rows].join("\n");
  writeFileSync(filePath, csv, "utf-8");
  return filePath;
}

export function exportToJSON(domains: any[], filePath: string): string {
  const entries = domains.map(toExportEntry);
  const json = JSON.stringify({
    exported: new Date().toISOString(),
    total: entries.length,
    available: entries.filter((e) => e.available).length,
    expired: entries.filter((e) => e.expired).length,
    domains: entries,
  }, null, 2);
  writeFileSync(filePath, json, "utf-8");
  return filePath;
}
