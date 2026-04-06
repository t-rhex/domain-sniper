/**
 * Scan history analysis — timeline, diffs, deltas between scans
 */

import { getScanHistory, getScanById } from "../db.js";
import type { DomainEntry } from "../types.js";

export interface HistoryEntry {
  id: number;
  scannedAt: string;
  status: string;
  score: number | null;
  data: DomainEntry | null;
}

export interface HistoryDelta {
  field: string;
  from: string;
  to: string;
  severity: "info" | "warning" | "critical";
}

export interface HistoryTimeline {
  domain: string;
  entries: HistoryEntry[];
  deltas: HistoryDelta[][]; // deltas[i] = changes between entries[i] and entries[i+1]
  totalScans: number;
  firstSeen: string | null;
  lastSeen: string | null;
  statusChanges: Array<{ from: string; to: string; at: string }>;
}

export function getTimeline(domain: string, limit: number = 20): HistoryTimeline {
  const rawHistory = getScanHistory(domain, limit);

  const entries: HistoryEntry[] = rawHistory.map((h) => ({
    id: h.id,
    scannedAt: h.scanned_at,
    status: h.status,
    score: h.score,
    data: null, // loaded on demand
  }));

  const timeline: HistoryTimeline = {
    domain,
    entries,
    deltas: [],
    totalScans: entries.length,
    firstSeen: entries.length > 0 ? entries[entries.length - 1]!.scannedAt : null,
    lastSeen: entries.length > 0 ? entries[0]!.scannedAt : null,
    statusChanges: [],
  };

  // Compute deltas between consecutive scans
  for (let i = 0; i < entries.length - 1; i++) {
    const newer = entries[i]!;
    const older = entries[i + 1]!;
    const deltas = computeDelta(older, newer, domain);
    timeline.deltas.push(deltas);
  }

  // Extract status changes
  for (let i = entries.length - 1; i > 0; i--) {
    const older = entries[i]!;
    const newer = entries[i - 1]!;
    if (older.status !== newer.status) {
      timeline.statusChanges.push({
        from: older.status,
        to: newer.status,
        at: newer.scannedAt,
      });
    }
  }

  return timeline;
}

function computeDelta(_older: HistoryEntry, _newer: HistoryEntry, _domain: string): HistoryDelta[] {
  const deltas: HistoryDelta[] = [];

  // Status change
  if (_older.status !== _newer.status) {
    const severity = (_newer.status === "available" || _newer.status === "expired") ? "critical" : "info";
    deltas.push({ field: "status", from: _older.status, to: _newer.status, severity });
  }

  // Score change
  if (_older.score !== null && _newer.score !== null && _older.score !== _newer.score) {
    const diff = _newer.score - _older.score;
    deltas.push({ field: "score", from: `${_older.score}`, to: `${_newer.score} (${diff > 0 ? "+" : ""}${diff})`, severity: "info" });
  }

  // Load full data for detailed comparison
  const olderData = getScanById(_older.id);
  const newerData = getScanById(_newer.id);

  if (olderData && newerData) {
    // Registrar change
    const oldReg = olderData.whois?.registrar || olderData.rdap?.registrar || null;
    const newReg = newerData.whois?.registrar || newerData.rdap?.registrar || null;
    if (oldReg !== newReg && (oldReg || newReg)) {
      deltas.push({ field: "registrar", from: oldReg || "none", to: newReg || "none", severity: "warning" });
    }

    // Expiry date change
    const oldExp = olderData.whois?.expiryDate || null;
    const newExp = newerData.whois?.expiryDate || null;
    if (oldExp !== newExp && (oldExp || newExp)) {
      deltas.push({ field: "expiry", from: oldExp || "none", to: newExp || "none", severity: "warning" });
    }

    // Nameserver change
    const oldNs = (olderData.whois?.nameServers || []).sort().join(", ");
    const newNs = (newerData.whois?.nameServers || []).sort().join(", ");
    if (oldNs !== newNs && (oldNs || newNs)) {
      deltas.push({ field: "nameservers", from: oldNs || "none", to: newNs || "none", severity: "warning" });
    }

    // IP address change
    const oldIp = (olderData.dns?.a || []).sort().join(", ");
    const newIp = (newerData.dns?.a || []).sort().join(", ");
    if (oldIp !== newIp && (oldIp || newIp)) {
      deltas.push({ field: "IP (A)", from: oldIp || "none", to: newIp || "none", severity: "info" });
    }

    // SSL change
    const oldSsl = olderData.ssl?.issuer || null;
    const newSsl = newerData.ssl?.issuer || null;
    if (oldSsl !== newSsl && (oldSsl || newSsl)) {
      deltas.push({ field: "SSL issuer", from: oldSsl || "none", to: newSsl || "none", severity: "warning" });
    }

    // HTTP status change
    const oldHttp = olderData.httpProbe?.status || null;
    const newHttp = newerData.httpProbe?.status || null;
    if (oldHttp !== newHttp && (oldHttp || newHttp)) {
      deltas.push({ field: "HTTP status", from: `${oldHttp || "none"}`, to: `${newHttp || "none"}`, severity: oldHttp === 200 && newHttp !== 200 ? "warning" : "info" });
    }

    // Tech stack change
    const oldTech = olderData.techStack?.technologies?.map((t) => t.name).sort().join(", ") || "";
    const newTech = newerData.techStack?.technologies?.map((t) => t.name).sort().join(", ") || "";
    if (oldTech !== newTech && (oldTech || newTech)) {
      deltas.push({ field: "tech stack", from: oldTech || "none", to: newTech || "none", severity: "info" });
    }

    // Blacklist change
    const oldBl = olderData.blacklist?.listed || false;
    const newBl = newerData.blacklist?.listed || false;
    if (oldBl !== newBl) {
      deltas.push({ field: "blacklist", from: oldBl ? "listed" : "clean", to: newBl ? "LISTED" : "clean", severity: newBl ? "critical" : "info" });
    }
  }

  return deltas;
}

/**
 * Load a specific past scan result by ID
 */
export function loadHistoryScan(scanId: number): DomainEntry | null {
  return getScanById(scanId);
}
