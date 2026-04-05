/**
 * WHOIS history tracking — SQLite-backed snapshot storage
 */

import {
  saveWhoisSnapshotDb,
  getWhoisHistoryDb,
  getWhoisHistoryCountDb,
} from "../db.js";
import { isValidDomain } from "../validate.js";
import type { WhoisResult } from "../whois.js";

export interface WhoisSnapshot {
  timestamp: string;
  domain: string;
  registrar: string | null;
  expiryDate: string | null;
  createdDate: string | null;
  updatedDate: string | null;
  status: string[];
  nameServers: string[];
  available: boolean;
  expired: boolean;
}

export interface WhoisDiff {
  field: string;
  old: string;
  new: string;
}

export function saveWhoisSnapshot(whois: WhoisResult): string {
  if (!isValidDomain(whois.domain)) throw new Error(`Invalid domain: ${whois.domain}`);
  const id = saveWhoisSnapshotDb(whois.domain, {
    registrar: whois.registrar,
    expiryDate: whois.expiryDate,
    createdDate: whois.createdDate,
    updatedDate: whois.updatedDate,
    status: whois.status,
    nameServers: whois.nameServers,
    available: whois.available,
    expired: whois.expired,
    rawText: whois.rawText,
  });
  return `db:whois-${id}`;
}

function dbRowToSnapshot(row: any): WhoisSnapshot {
  return {
    timestamp: row.snapshot_at,
    domain: row.domain,
    registrar: row.registrar,
    expiryDate: row.expiry_date,
    createdDate: row.created_date,
    updatedDate: row.updated_date,
    status: (() => { try { return JSON.parse(row.status || "[]"); } catch { return []; } })(),
    nameServers: (() => { try { return JSON.parse(row.name_servers || "[]"); } catch { return []; } })(),
    available: !!row.available,
    expired: !!row.expired,
  };
}

export function getWhoisHistory(domain: string): WhoisSnapshot[] {
  if (!isValidDomain(domain)) return [];
  const rows = getWhoisHistoryDb(domain);
  return rows.map(dbRowToSnapshot).reverse(); // oldest first
}

export function diffWhoisSnapshots(
  older: WhoisSnapshot,
  newer: WhoisSnapshot
): WhoisDiff[] {
  const diffs: WhoisDiff[] = [];
  const fields: (keyof WhoisSnapshot)[] = [
    "registrar", "expiryDate", "createdDate", "updatedDate", "available", "expired",
  ];
  for (const field of fields) {
    const oldVal = String(older[field] ?? "");
    const newVal = String(newer[field] ?? "");
    if (oldVal !== newVal) diffs.push({ field, old: oldVal, new: newVal });
  }
  const oldStatus = [...older.status].sort().join(", ");
  const newStatus = [...newer.status].sort().join(", ");
  if (oldStatus !== newStatus) diffs.push({ field: "status", old: oldStatus, new: newStatus });
  const oldNs = [...older.nameServers].sort().join(", ");
  const newNs = [...newer.nameServers].sort().join(", ");
  if (oldNs !== newNs) diffs.push({ field: "nameServers", old: oldNs, new: newNs });
  return diffs;
}

export function getLatestDiff(domain: string): WhoisDiff[] | null {
  const history = getWhoisHistory(domain);
  if (history.length < 2) return null;
  return diffWhoisSnapshots(history[history.length - 2]!, history[history.length - 1]!);
}

export function getHistoryCount(domain: string): number {
  return getWhoisHistoryCountDb(domain);
}
