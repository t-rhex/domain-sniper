import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync } from "fs";
import { join } from "path";
import { isValidDomain } from "../validate.js";
import type { WhoisResult } from "../whois.js";
import { WHOIS_HISTORY_DIR } from "../paths.js";

const HISTORY_DIR = WHOIS_HISTORY_DIR;

function ensureDir(domain: string): string {
  const dir = join(HISTORY_DIR, domain.replace(/[^a-z0-9.-]/gi, "_"));
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  return dir;
}

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

function toSnapshot(whois: WhoisResult): WhoisSnapshot {
  return {
    timestamp: new Date().toISOString(),
    domain: whois.domain,
    registrar: whois.registrar,
    expiryDate: whois.expiryDate,
    createdDate: whois.createdDate,
    updatedDate: whois.updatedDate,
    status: whois.status,
    nameServers: whois.nameServers,
    available: whois.available,
    expired: whois.expired,
  };
}

export function saveWhoisSnapshot(whois: WhoisResult): string {
  if (!isValidDomain(whois.domain)) throw new Error(`Invalid domain: ${whois.domain}`);
  const dir = ensureDir(whois.domain);
  const snapshot = toSnapshot(whois);
  const filename = `${Date.now()}.json`;
  const path = join(dir, filename);
  writeFileSync(path, JSON.stringify(snapshot, null, 2), "utf-8");
  return path;
}

export function getWhoisHistory(domain: string): WhoisSnapshot[] {
  if (!isValidDomain(domain)) return [];
  const dir = join(HISTORY_DIR, domain.replace(/[^a-z0-9.-]/gi, "_"));
  if (!existsSync(dir)) return [];

  try {
    const files = readdirSync(dir)
      .filter((f) => f.endsWith(".json"))
      .sort(); // chronological by timestamp filename

    return files.map((f) => {
      const content = readFileSync(join(dir, f), "utf-8");
      return JSON.parse(content) as WhoisSnapshot;
    });
  } catch {
    return [];
  }
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
    if (oldVal !== newVal) {
      diffs.push({ field, old: oldVal, new: newVal });
    }
  }

  // Compare status arrays
  const oldStatus = older.status.sort().join(", ");
  const newStatus = newer.status.sort().join(", ");
  if (oldStatus !== newStatus) {
    diffs.push({ field: "status", old: oldStatus, new: newStatus });
  }

  // Compare nameservers
  const oldNs = older.nameServers.sort().join(", ");
  const newNs = newer.nameServers.sort().join(", ");
  if (oldNs !== newNs) {
    diffs.push({ field: "nameServers", old: oldNs, new: newNs });
  }

  return diffs;
}

export function getLatestDiff(domain: string): WhoisDiff[] | null {
  const history = getWhoisHistory(domain);
  if (history.length < 2) return null;
  return diffWhoisSnapshots(history[history.length - 2]!, history[history.length - 1]!);
}

export function getHistoryCount(domain: string): number {
  return getWhoisHistory(domain).length;
}
