import { Database } from "bun:sqlite";
import { mkdirSync, existsSync } from "fs";
import { join } from "path";
import { homedir } from "os";

const APP_DIR = join(homedir(), ".domain-sniper");
const PROXY_DB_FILE = join(APP_DIR, "proxy.db");

let _db: Database | null = null;
let _dbPath: string | null = null;

/**
 * Override the database path. Call BEFORE getProxyDb().
 * Use ":memory:" for tests to avoid polluting the real database.
 */
export function setProxyDbPath(path: string): void {
  if (_db) { _db.close(); _db = null; }
  _dbPath = path;
}

export function getProxyDb(): Database {
  if (_db) return _db;
  const dbPath = _dbPath || PROXY_DB_FILE;
  if (dbPath !== ":memory:") {
    if (!existsSync(APP_DIR)) mkdirSync(APP_DIR, { recursive: true });
  }
  _db = new Database(dbPath);
  _db.run("PRAGMA journal_mode = WAL");
  _db.run("PRAGMA foreign_keys = ON");
  initSchema(_db);
  return _db;
}

export function closeProxyDb(): void {
  if (_db) { _db.close(); _db = null; }
}

function initSchema(db: Database): void {
  db.run(`
    CREATE TABLE IF NOT EXISTS requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      method TEXT NOT NULL,
      url TEXT NOT NULL,
      host TEXT NOT NULL,
      path TEXT NOT NULL,
      scheme TEXT DEFAULT 'http',
      request_headers TEXT DEFAULT '{}',
      request_body TEXT DEFAULT '',
      request_size INTEGER DEFAULT 0,
      status_code INTEGER,
      response_headers TEXT DEFAULT '{}',
      response_body TEXT DEFAULT '',
      response_size INTEGER DEFAULT 0,
      duration_ms INTEGER DEFAULT 0,
      intercepted_at TEXT DEFAULT (datetime('now')),
      tags TEXT DEFAULT '[]',
      notes TEXT DEFAULT '',
      flagged INTEGER DEFAULT 0
    )
  `);

  db.run("CREATE INDEX IF NOT EXISTS idx_req_host ON requests(host)");
  db.run("CREATE INDEX IF NOT EXISTS idx_req_method ON requests(method)");
  db.run("CREATE INDEX IF NOT EXISTS idx_req_status ON requests(status_code)");
  db.run("CREATE INDEX IF NOT EXISTS idx_req_time ON requests(intercepted_at)");
  db.run("CREATE INDEX IF NOT EXISTS idx_req_flagged ON requests(flagged)");
}

// ─── CRUD ────────────────────────────────────────────────

export interface InterceptedRequest {
  id: number;
  method: string;
  url: string;
  host: string;
  path: string;
  scheme: string;
  request_headers: string;
  request_body: string;
  request_size: number;
  status_code: number | null;
  response_headers: string;
  response_body: string;
  response_size: number;
  duration_ms: number;
  intercepted_at: string;
  tags: string;
  notes: string;
  flagged: number;
}

export function saveRequest(data: {
  method: string;
  url: string;
  host: string;
  path: string;
  scheme: string;
  requestHeaders: Record<string, string>;
  requestBody: string;
  statusCode: number | null;
  responseHeaders: Record<string, string>;
  responseBody: string;
  durationMs: number;
}): number {
  const db = getProxyDb();
  const result = db.run(`
    INSERT INTO requests (method, url, host, path, scheme, request_headers, request_body, request_size, status_code, response_headers, response_body, response_size, duration_ms)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `, [
    data.method, data.url, data.host, data.path, data.scheme,
    JSON.stringify(data.requestHeaders), data.requestBody, data.requestBody.length,
    data.statusCode,
    JSON.stringify(data.responseHeaders), data.responseBody, data.responseBody.length,
    data.durationMs,
  ]);
  return Number(result.lastInsertRowid);
}

export function getRequests(options: {
  host?: string; method?: string; statusCode?: number;
  search?: string; flagged?: boolean;
  limit?: number; offset?: number;
} = {}): { requests: InterceptedRequest[]; total: number } {
  const db = getProxyDb();
  const conditions: string[] = [];
  const params: (string | number)[] = [];

  if (options.host) { conditions.push("host LIKE ?"); params.push(`%${options.host}%`); }
  if (options.method) { conditions.push("method = ?"); params.push(options.method); }
  if (options.statusCode) { conditions.push("status_code = ?"); params.push(options.statusCode); }
  if (options.search) { conditions.push("(url LIKE ? OR request_body LIKE ? OR response_body LIKE ?)"); params.push(`%${options.search}%`, `%${options.search}%`, `%${options.search}%`); }
  if (options.flagged) { conditions.push("flagged = 1"); }

  const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
  const limit = Math.min(options.limit || 50, 500);
  const offset = options.offset || 0;

  const total = (db.query(`SELECT COUNT(*) as c FROM requests ${where}`).get(...params) as { c: number }).c;
  const requests = db.query(`SELECT * FROM requests ${where} ORDER BY intercepted_at DESC LIMIT ? OFFSET ?`).all(...params, limit, offset) as InterceptedRequest[];

  return { requests, total };
}

export function getRequest(id: number): InterceptedRequest | null {
  return getProxyDb().query("SELECT * FROM requests WHERE id = ?").get(id) as InterceptedRequest | null;
}

export function flagRequest(id: number, flagged: boolean = true): void {
  getProxyDb().run("UPDATE requests SET flagged = ? WHERE id = ?", [flagged ? 1 : 0, id]);
}

export function addNote(id: number, note: string): void {
  getProxyDb().run("UPDATE requests SET notes = ? WHERE id = ?", [note, id]);
}

export function clearRequests(host?: string): number {
  const db = getProxyDb();
  if (host) {
    return db.run("DELETE FROM requests WHERE host LIKE ?", [`%${host}%`]).changes;
  }
  return db.run("DELETE FROM requests").changes;
}

export function getProxyStats(): { totalRequests: number; uniqueHosts: number; flagged: number; avgDuration: number } {
  const db = getProxyDb();
  const total = (db.query("SELECT COUNT(*) as c FROM requests").get() as { c: number }).c;
  const hosts = (db.query("SELECT COUNT(DISTINCT host) as c FROM requests").get() as { c: number }).c;
  const flagged = (db.query("SELECT COUNT(*) as c FROM requests WHERE flagged = 1").get() as { c: number }).c;
  const avg = (db.query("SELECT COALESCE(AVG(duration_ms), 0) as a FROM requests").get() as { a: number }).a;
  return { totalRequests: total, uniqueHosts: hosts, flagged, avgDuration: Math.round(avg) };
}

export function getTopHosts(limit: number = 10): Array<{ host: string; count: number }> {
  return getProxyDb().query("SELECT host, COUNT(*) as count FROM requests GROUP BY host ORDER BY count DESC LIMIT ?").all(limit) as Array<{ host: string; count: number }>;
}
