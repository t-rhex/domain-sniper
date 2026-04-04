/**
 * Session persistence — save/load scan results to disk
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from "fs";
import { join } from "path";
import { homedir } from "os";

const SESSION_DIR = join(homedir(), ".domain-sniper", "sessions");

export interface SavedSession {
  id: string;
  timestamp: string;
  domains: any[];
  watchlist: string[];
  tags: Record<string, string[]>;  // domain -> tags
  notes: Record<string, string>;   // domain -> note
}

function ensureDir() {
  if (!existsSync(SESSION_DIR)) {
    mkdirSync(SESSION_DIR, { recursive: true });
  }
}

export function saveSession(domains: any[], watchlist: string[] = [], tags: Record<string, string[]> = {}, notes: Record<string, string> = {}): string {
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

export function loadSession(idOrPath: string): SavedSession | null {
  try {
    let path = idOrPath;
    if (!existsSync(path)) {
      path = join(SESSION_DIR, `${idOrPath}.json`);
    }
    if (!existsSync(path)) return null;
    const content = readFileSync(path, "utf-8");
    return JSON.parse(content) as SavedSession;
  } catch {
    return null;
  }
}

export function listSessions(): { id: string; timestamp: string; count: number; path: string }[] {
  ensureDir();
  try {
    const { readdirSync } = require("fs");
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
      .filter(Boolean)
      .sort((a: any, b: any) => b.timestamp.localeCompare(a.timestamp)) as any[];
  } catch {
    return [];
  }
}

export function deleteSession(id: string): boolean {
  const path = join(SESSION_DIR, `${id}.json`);
  try {
    if (existsSync(path)) {
      const { unlinkSync } = require("fs");
      unlinkSync(path);
      return true;
    }
  } catch {}
  return false;
}
