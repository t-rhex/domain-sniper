/**
 * Session persistence — SQLite-backed save/load scan results
 */

import {
  createSession as dbCreateSession,
  updateSessionCount,
  listAllSessions,
  getSession,
  getSessionScans,
  deleteSessionById,
  upsertDomain,
  saveScan,
} from "../db.js";
import type { DomainEntry } from "../types.js";
import { scoreDomain } from "./scoring.js";

export interface SavedSession {
  id: string;
  timestamp: string;
  domains: DomainEntry[];
  watchlist: string[];
  tags: Record<string, string[]>;
  notes: Record<string, string>;
}

export function saveSession(
  domains: DomainEntry[],
  watchlist: string[] = [],
  tags: Record<string, string[]> = {},
  notes: Record<string, string> = {}
): string {
  const sessionId = dbCreateSession();
  for (const d of domains) {
    const domainId = upsertDomain(d.domain);
    const score = scoreDomain(d.domain);
    saveScan(domainId, d.status, d, sessionId, score.total);
  }
  updateSessionCount(sessionId, domains.length);
  return `session-${sessionId}`;
}

export function loadSession(id: string): SavedSession | null {
  // Accept both "session-123" format and raw number
  const numId = parseInt(id.replace("session-", "").replace("scan-", ""), 10);
  if (isNaN(numId)) return null;
  const session = getSession(numId);
  if (!session) return null;
  const domains = getSessionScans(numId);
  return {
    id: `session-${session.id}`,
    timestamp: session.created_at,
    domains,
    watchlist: [],
    tags: {},
    notes: {},
  };
}

export function listSessions(): { id: string; timestamp: string; count: number; path: string }[] {
  return listAllSessions().map((s) => ({
    id: `session-${s.id}`,
    timestamp: s.created_at,
    count: s.domain_count,
    path: `db:session-${s.id}`,
  }));
}

export function deleteSession(id: string): boolean {
  const numId = parseInt(id.replace("session-", "").replace("scan-", ""), 10);
  if (isNaN(numId)) return false;
  deleteSessionById(numId);
  return true;
}
