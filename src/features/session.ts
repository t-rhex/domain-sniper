/**
 * Session persistence — save/load scan results to disk
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync, unlinkSync } from "fs";
import { join } from "path";
import { isValidSessionId } from "../validate.js";
import type { DomainEntry } from "../types.js";
import { SESSION_DIR } from "../paths.js";

export interface SavedSession {
  id: string;
  timestamp: string;
  domains: DomainEntry[];
  watchlist: string[];
  tags: Record<string, string[]>;  // domain -> tags
  notes: Record<string, string>;   // domain -> note
}

function ensureDir() {
  if (!existsSync(SESSION_DIR)) {
    mkdirSync(SESSION_DIR, { recursive: true });
  }
}

export function saveSession(domains: DomainEntry[], watchlist: string[] = [], tags: Record<string, string[]> = {}, notes: Record<string, string> = {}): string {
  ensureDir();
  const id = `scan-${Date.now()}`;
  const session: SavedSession = {
    id,
    timestamp: new Date().toISOString(),
    domains,
    watchlist,
    tags,
    notes,
  };
  const path = join(SESSION_DIR, `${id}.json`);
  writeFileSync(path, JSON.stringify(session, null, 2), "utf-8");
  return path;
}

export function loadSession(id: string): SavedSession | null {
  if (!isValidSessionId(id)) return null;
  try {
    const path = join(SESSION_DIR, `${id}.json`);
    if (!existsSync(path)) return null;
    const content = readFileSync(path, "utf-8");
    const parsed = JSON.parse(content) as SavedSession | null;
    if (!parsed || !Array.isArray(parsed.domains)) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function listSessions(): { id: string; timestamp: string; count: number; path: string }[] {
  ensureDir();
  try {
    const files = readdirSync(SESSION_DIR) as string[];
    return files
      .filter((f: string) => f.endsWith(".json"))
      .map((f: string) => {
        try {
          const content = readFileSync(join(SESSION_DIR, f), "utf-8");
          const session = JSON.parse(content) as SavedSession;
          return {
            id: session.id,
            timestamp: session.timestamp,
            count: session.domains.length,
            path: join(SESSION_DIR, f),
          };
        } catch {
          return null;
        }
      })
      .filter((s): s is NonNullable<typeof s> => s !== null)
      .sort((a, b) => b.timestamp.localeCompare(a.timestamp));
  } catch {
    return [];
  }
}

export function deleteSession(id: string): boolean {
  if (!isValidSessionId(id)) return false;
  const path = join(SESSION_DIR, `${id}.json`);
  try {
    if (existsSync(path)) {
      unlinkSync(path);
      return true;
    }
  } catch {}
  return false;
}
