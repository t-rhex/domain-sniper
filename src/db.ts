import { Database } from "bun:sqlite";
import { mkdirSync, existsSync, readdirSync, readFileSync } from "fs";
import { join } from "path";
import { APP_DIR, DB_FILE } from "./paths.js";
import type { DomainEntry } from "./types.js";

// ─── Ensure directory exists ─────────────────────────────
function ensureAppDir(): void {
  if (!existsSync(APP_DIR)) {
    mkdirSync(APP_DIR, { recursive: true });
  }
}

// ─── Database singleton ──────────────────────────────────
let _db: Database | null = null;

export function getDb(): Database {
  if (_db) return _db;
  ensureAppDir();
  _db = new Database(DB_FILE);
  _db.run("PRAGMA journal_mode = WAL");
  _db.run("PRAGMA foreign_keys = ON");
  _db.run("PRAGMA busy_timeout = 5000");
  migrate(_db);
  return _db;
}

export function closeDb(): void {
  if (_db) {
    _db.close();
    _db = null;
  }
}

// ─── Migration types ─────────────────────────────────────

interface Migration {
  name: string;
  sql: string;
}

interface MigrationRow {
  name: string;
}

// ─── Migrations ──────────────────────────────────────────
function migrate(db: Database): void {
  db.run(`
    CREATE TABLE IF NOT EXISTS migrations (
      id INTEGER PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      applied_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);

  const applied = new Set(
    db
      .query<MigrationRow, []>("SELECT name FROM migrations")
      .all()
      .map((r) => r.name),
  );

  for (const m of MIGRATIONS) {
    if (!applied.has(m.name)) {
      db.run(m.sql);
      db.run("INSERT INTO migrations (name) VALUES (?)", [m.name]);
    }
  }
}

const MIGRATIONS: Migration[] = [
  {
    name: "001_create_domains",
    sql: `
      CREATE TABLE IF NOT EXISTS domains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL UNIQUE,
        first_seen TEXT NOT NULL DEFAULT (datetime('now')),
        last_scanned TEXT,
        scan_count INTEGER NOT NULL DEFAULT 0,
        tags TEXT DEFAULT '[]',
        notes TEXT DEFAULT ''
      );
      CREATE INDEX IF NOT EXISTS idx_domains_domain ON domains(domain);
    `,
  },
  {
    name: "002_create_scans",
    sql: `
      CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
        session_id INTEGER REFERENCES sessions(id) ON DELETE SET NULL,
        scanned_at TEXT NOT NULL DEFAULT (datetime('now')),
        status TEXT NOT NULL,
        score INTEGER,
        data TEXT NOT NULL DEFAULT '{}',
        FOREIGN KEY (domain_id) REFERENCES domains(id)
      );
      CREATE INDEX IF NOT EXISTS idx_scans_domain_id ON scans(domain_id);
      CREATE INDEX IF NOT EXISTS idx_scans_scanned_at ON scans(scanned_at);
      CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
    `,
  },
  {
    name: "003_create_sessions",
    sql: `
      CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        domain_count INTEGER NOT NULL DEFAULT 0,
        metadata TEXT DEFAULT '{}'
      );
    `,
  },
  {
    name: "004_create_portfolio",
    sql: `
      CREATE TABLE IF NOT EXISTS portfolio (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL UNIQUE,
        registrar TEXT DEFAULT 'unknown',
        purchase_date TEXT,
        expiry_date TEXT,
        purchase_price REAL DEFAULT 0,
        renewal_price REAL DEFAULT 0,
        currency TEXT DEFAULT 'USD',
        auto_renew INTEGER DEFAULT 0,
        tags TEXT DEFAULT '[]',
        notes TEXT DEFAULT '',
        added_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX IF NOT EXISTS idx_portfolio_domain ON portfolio(domain);
      CREATE INDEX IF NOT EXISTS idx_portfolio_expiry ON portfolio(expiry_date);
    `,
  },
  {
    name: "005_create_whois_history",
    sql: `
      CREATE TABLE IF NOT EXISTS whois_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        snapshot_at TEXT NOT NULL DEFAULT (datetime('now')),
        registrar TEXT,
        expiry_date TEXT,
        created_date TEXT,
        updated_date TEXT,
        status TEXT DEFAULT '[]',
        name_servers TEXT DEFAULT '[]',
        available INTEGER DEFAULT 0,
        expired INTEGER DEFAULT 0,
        raw_text TEXT DEFAULT ''
      );
      CREATE INDEX IF NOT EXISTS idx_whois_domain ON whois_history(domain);
      CREATE INDEX IF NOT EXISTS idx_whois_snapshot_at ON whois_history(snapshot_at);
    `,
  },
  {
    name: "006_create_cache",
    sql: `
      CREATE TABLE IF NOT EXISTS cache (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        cache_key TEXT NOT NULL,
        data TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        expires_at TEXT NOT NULL,
        UNIQUE(domain, cache_key)
      );
      CREATE INDEX IF NOT EXISTS idx_cache_domain_key ON cache(domain, cache_key);
      CREATE INDEX IF NOT EXISTS idx_cache_expires ON cache(expires_at);
    `,
  },
  {
    name: "007_portfolio_expand",
    sql: `
      ALTER TABLE portfolio ADD COLUMN status TEXT DEFAULT 'active';
      ALTER TABLE portfolio ADD COLUMN category TEXT DEFAULT 'uncategorized';
      ALTER TABLE portfolio ADD COLUMN estimated_value REAL DEFAULT 0;
      ALTER TABLE portfolio ADD COLUMN last_health_check TEXT;
    `,
  },
  {
    name: "008_create_transactions",
    sql: `
      CREATE TABLE IF NOT EXISTS portfolio_transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        type TEXT NOT NULL,
        amount REAL NOT NULL,
        currency TEXT DEFAULT 'USD',
        description TEXT DEFAULT '',
        date TEXT NOT NULL DEFAULT (date('now')),
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX IF NOT EXISTS idx_txn_domain ON portfolio_transactions(domain);
      CREATE INDEX IF NOT EXISTS idx_txn_date ON portfolio_transactions(date);
      CREATE INDEX IF NOT EXISTS idx_txn_type ON portfolio_transactions(type);
    `,
  },
  {
    name: "009_create_valuations",
    sql: `
      CREATE TABLE IF NOT EXISTS portfolio_valuations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        estimated_value REAL NOT NULL,
        source TEXT DEFAULT 'manual',
        valued_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX IF NOT EXISTS idx_val_domain ON portfolio_valuations(domain);
    `,
  },
  {
    name: "010_create_pipeline",
    sql: `
      CREATE TABLE IF NOT EXISTS acquisition_pipeline (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL UNIQUE,
        status TEXT NOT NULL DEFAULT 'watching',
        max_bid REAL,
        current_price REAL,
        source TEXT DEFAULT '',
        notes TEXT DEFAULT '',
        priority TEXT DEFAULT 'medium',
        added_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX IF NOT EXISTS idx_pipeline_status ON acquisition_pipeline(status);
    `,
  },
  {
    name: "011_create_categories",
    sql: `
      CREATE TABLE IF NOT EXISTS portfolio_categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        color TEXT DEFAULT '#5c9cf5',
        description TEXT DEFAULT '',
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      INSERT OR IGNORE INTO portfolio_categories (name, description) VALUES
        ('uncategorized', 'Default category'),
        ('investments', 'Domains held for resale'),
        ('projects', 'Domains used for active projects'),
        ('clients', 'Domains managed for clients'),
        ('for-sale', 'Domains actively listed for sale'),
        ('archived', 'Domains no longer maintained');
    `,
  },
  {
    name: "012_create_alerts",
    sql: `
      CREATE TABLE IF NOT EXISTS portfolio_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        type TEXT NOT NULL,
        severity TEXT NOT NULL DEFAULT 'info',
        message TEXT NOT NULL,
        acknowledged INTEGER DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX IF NOT EXISTS idx_alerts_domain ON portfolio_alerts(domain);
      CREATE INDEX IF NOT EXISTS idx_alerts_ack ON portfolio_alerts(acknowledged);
    `,
  },
];

// ─── Row types ───────────────────────────────────────────

interface DomainRow {
  id: number;
  domain: string;
  first_seen: string;
  last_scanned: string | null;
  scan_count: number;
  tags: string;
  notes: string;
}

interface IdRow {
  id: number;
}

interface DataRow {
  data: string;
}

interface ScanHistoryRow {
  id: number;
  scanned_at: string;
  status: string;
  score: number | null;
}

interface SessionRow {
  id: number;
  name: string;
  created_at: string;
  domain_count: number;
  metadata: string;
}

interface CountRow {
  c: number;
}

interface SumRow {
  s: number;
}

interface RegistrarCountRow {
  registrar: string;
  c: number;
}

// ─── Domain CRUD ─────────────────────────────────────────

export function upsertDomain(domain: string): number {
  const db = getDb();
  db.run(
    `INSERT INTO domains (domain) VALUES (?)
     ON CONFLICT(domain) DO UPDATE SET
       last_scanned = datetime('now'),
       scan_count = scan_count + 1`,
    [domain],
  );
  const row = db
    .query<IdRow, [string]>("SELECT id FROM domains WHERE domain = ?")
    .get(domain);
  return row!.id;
}

export function getDomainByName(domain: string): DomainRow | null {
  const db = getDb();
  return db
    .query<DomainRow, [string]>("SELECT * FROM domains WHERE domain = ?")
    .get(domain);
}

export function getAllDomains(
  limit: number = 100,
  offset: number = 0,
): DomainRow[] {
  const db = getDb();
  return db
    .query<DomainRow, [number, number]>(
      "SELECT * FROM domains ORDER BY last_scanned DESC LIMIT ? OFFSET ?",
    )
    .all(limit, offset);
}

export function searchDomains(
  query: string,
  limit: number = 50,
): DomainRow[] {
  const db = getDb();
  return db
    .query<DomainRow, [string, number]>(
      "SELECT * FROM domains WHERE domain LIKE ? ORDER BY scan_count DESC LIMIT ?",
    )
    .all(`%${query}%`, limit);
}

// ─── Scan CRUD ───────────────────────────────────────────

export function saveScan(
  domainId: number,
  status: string,
  data: DomainEntry,
  sessionId?: number,
  score?: number,
): number {
  const db = getDb();
  const result = db.run(
    `INSERT INTO scans (domain_id, session_id, status, score, data) VALUES (?, ?, ?, ?, ?)`,
    [domainId, sessionId ?? null, status, score ?? null, JSON.stringify(data)],
  );
  return Number(result.lastInsertRowid);
}

export function getLatestScan(domain: string): DomainEntry | null {
  const db = getDb();
  const row = db
    .query<DataRow, [string]>(
      `SELECT s.data FROM scans s
       JOIN domains d ON s.domain_id = d.id
       WHERE d.domain = ?
       ORDER BY s.scanned_at DESC LIMIT 1`,
    )
    .get(domain);
  if (!row) return null;
  try {
    return JSON.parse(row.data) as DomainEntry;
  } catch {
    return null;
  }
}

export function getScanHistory(
  domain: string,
  limit: number = 20,
): ScanHistoryRow[] {
  const db = getDb();
  return db
    .query<ScanHistoryRow, [string, number]>(
      `SELECT s.id, s.scanned_at, s.status, s.score FROM scans s
       JOIN domains d ON s.domain_id = d.id
       WHERE d.domain = ?
       ORDER BY s.scanned_at DESC LIMIT ?`,
    )
    .all(domain, limit);
}

export function getScanById(scanId: number): DomainEntry | null {
  const db = getDb();
  const row = db
    .query<DataRow, [number]>("SELECT data FROM scans WHERE id = ?")
    .get(scanId);
  if (!row) return null;
  try {
    return JSON.parse(row.data) as DomainEntry;
  } catch {
    return null;
  }
}

// ─── Session CRUD ────────────────────────────────────────

export function createSession(name?: string): number {
  const db = getDb();
  const sessionName = name || `scan-${Date.now()}`;
  const result = db.run(
    "INSERT INTO sessions (name) VALUES (?)",
    [sessionName],
  );
  return Number(result.lastInsertRowid);
}

export function updateSessionCount(
  sessionId: number,
  count: number,
): void {
  const db = getDb();
  db.run(
    "UPDATE sessions SET domain_count = ? WHERE id = ?",
    [count, sessionId],
  );
}

export function getSession(sessionId: number): SessionRow | null {
  const db = getDb();
  return db
    .query<SessionRow, [number]>("SELECT * FROM sessions WHERE id = ?")
    .get(sessionId);
}

export function listAllSessions(limit: number = 50): SessionRow[] {
  const db = getDb();
  return db
    .query<SessionRow, [number]>(
      "SELECT * FROM sessions ORDER BY created_at DESC LIMIT ?",
    )
    .all(limit);
}

export function deleteSessionById(sessionId: number): void {
  const db = getDb();
  db.run("DELETE FROM sessions WHERE id = ?", [sessionId]);
}

export function getSessionScans(sessionId: number): DomainEntry[] {
  const db = getDb();
  const rows = db
    .query<DataRow, [number]>(
      "SELECT data FROM scans WHERE session_id = ? ORDER BY id",
    )
    .all(sessionId);
  return rows
    .map((r) => {
      try {
        return JSON.parse(r.data) as DomainEntry;
      } catch {
        return null;
      }
    })
    .filter((entry): entry is DomainEntry => entry !== null);
}

// ─── Portfolio CRUD ──────────────────────────────────────

export interface DbPortfolioDomain {
  id: number;
  domain: string;
  registrar: string;
  purchase_date: string | null;
  expiry_date: string | null;
  purchase_price: number;
  renewal_price: number;
  currency: string;
  auto_renew: number;
  tags: string;
  notes: string;
  added_at: string;
  updated_at: string;
}

export interface PortfolioDomainDetails {
  registrar?: string;
  purchaseDate?: string;
  expiryDate?: string;
  purchasePrice?: number;
  renewalPrice?: number;
  currency?: string;
  autoRenew?: boolean;
  tags?: string[];
  notes?: string;
}

export function addPortfolioDomain(
  domain: string,
  details: PortfolioDomainDetails = {},
): void {
  const db = getDb();
  db.run(
    `INSERT INTO portfolio (domain, registrar, purchase_date, expiry_date, purchase_price, renewal_price, currency, auto_renew, tags, notes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(domain) DO UPDATE SET
       registrar = excluded.registrar,
       purchase_date = excluded.purchase_date,
       expiry_date = excluded.expiry_date,
       purchase_price = excluded.purchase_price,
       renewal_price = excluded.renewal_price,
       currency = excluded.currency,
       auto_renew = excluded.auto_renew,
       tags = excluded.tags,
       notes = excluded.notes,
       updated_at = datetime('now')`,
    [
      domain,
      details.registrar || "unknown",
      details.purchaseDate || null,
      details.expiryDate || null,
      details.purchasePrice || 0,
      details.renewalPrice || 0,
      details.currency || "USD",
      details.autoRenew ? 1 : 0,
      JSON.stringify(details.tags || []),
      details.notes || "",
    ],
  );
}

export function removePortfolioDomain(domain: string): void {
  const db = getDb();
  db.run("DELETE FROM portfolio WHERE domain = ?", [domain]);
}

export function getPortfolioDomains(): DbPortfolioDomain[] {
  const db = getDb();
  return db
    .query<DbPortfolioDomain, []>(
      "SELECT * FROM portfolio ORDER BY domain",
    )
    .all();
}

export function getPortfolioExpiring(
  withinDays: number = 30,
): DbPortfolioDomain[] {
  const db = getDb();
  return db
    .query<DbPortfolioDomain, [number]>(
      `SELECT * FROM portfolio
       WHERE expiry_date IS NOT NULL
       AND date(expiry_date) <= date('now', '+' || ? || ' days')
       AND date(expiry_date) >= date('now')
       ORDER BY expiry_date`,
    )
    .all(withinDays);
}

export interface PortfolioStats {
  total: number;
  totalSpent: number;
  expiringIn30: number;
  expiringIn90: number;
  byRegistrar: Record<string, number>;
}

export function getPortfolioStatsDb(): PortfolioStats {
  const db = getDb();
  const totalRow = db
    .query<CountRow, []>("SELECT COUNT(*) as c FROM portfolio")
    .get();
  const total = totalRow?.c ?? 0;

  const spentRow = db
    .query<SumRow, []>(
      "SELECT COALESCE(SUM(purchase_price), 0) as s FROM portfolio",
    )
    .get();
  const totalSpent = spentRow?.s ?? 0;

  const expiringIn30 = getPortfolioExpiring(30).length;
  const expiringIn90 = getPortfolioExpiring(90).length;

  const registrars = db
    .query<RegistrarCountRow, []>(
      "SELECT registrar, COUNT(*) as c FROM portfolio GROUP BY registrar",
    )
    .all();
  const byRegistrar: Record<string, number> = {};
  for (const r of registrars) {
    byRegistrar[r.registrar] = r.c;
  }

  return { total, totalSpent, expiringIn30, expiringIn90, byRegistrar };
}

// ─── WHOIS History ───────────────────────────────────────

export interface WhoisSnapshotInput {
  registrar: string | null;
  expiryDate: string | null;
  createdDate: string | null;
  updatedDate: string | null;
  status: string[];
  nameServers: string[];
  available: boolean;
  expired: boolean;
  rawText?: string;
}

export interface WhoisHistoryRow {
  id: number;
  domain: string;
  snapshot_at: string;
  registrar: string | null;
  expiry_date: string | null;
  created_date: string | null;
  updated_date: string | null;
  available: number;
  expired: number;
  status: string;
  name_servers: string;
  raw_text: string;
}

export function saveWhoisSnapshotDb(
  domain: string,
  snapshot: WhoisSnapshotInput,
): number {
  const db = getDb();
  const result = db.run(
    `INSERT INTO whois_history (domain, registrar, expiry_date, created_date, updated_date, status, name_servers, available, expired, raw_text)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      domain,
      snapshot.registrar,
      snapshot.expiryDate,
      snapshot.createdDate,
      snapshot.updatedDate,
      JSON.stringify(snapshot.status),
      JSON.stringify(snapshot.nameServers),
      snapshot.available ? 1 : 0,
      snapshot.expired ? 1 : 0,
      snapshot.rawText || "",
    ],
  );
  return Number(result.lastInsertRowid);
}

export function getWhoisHistoryDb(
  domain: string,
  limit: number = 20,
): WhoisHistoryRow[] {
  const db = getDb();
  return db
    .query<WhoisHistoryRow, [string, number]>(
      "SELECT * FROM whois_history WHERE domain = ? ORDER BY snapshot_at DESC LIMIT ?",
    )
    .all(domain, limit);
}

export function getWhoisHistoryCountDb(domain: string): number {
  const db = getDb();
  const row = db
    .query<CountRow, [string]>(
      "SELECT COUNT(*) as c FROM whois_history WHERE domain = ?",
    )
    .get(domain);
  return row?.c ?? 0;
}

// ─── Cache ───────────────────────────────────────────────

interface CacheDataRow {
  data: string;
}

export function getCached(domain: string, key: string): string | null {
  const db = getDb();
  // Clean expired entries
  db.run("DELETE FROM cache WHERE expires_at < datetime('now')");
  const row = db
    .query<CacheDataRow, [string, string]>(
      "SELECT data FROM cache WHERE domain = ? AND cache_key = ? AND expires_at > datetime('now')",
    )
    .get(domain, key);
  return row?.data ?? null;
}

export function setCache(
  domain: string,
  key: string,
  data: string,
  ttlMinutes: number = 60,
): void {
  const db = getDb();
  db.run(
    `INSERT INTO cache (domain, cache_key, data, expires_at)
     VALUES (?, ?, ?, datetime('now', '+' || ? || ' minutes'))
     ON CONFLICT(domain, cache_key) DO UPDATE SET
       data = excluded.data,
       created_at = datetime('now'),
       expires_at = excluded.expires_at`,
    [domain, key, data, ttlMinutes],
  );
}

export function clearCache(domain?: string): number {
  const db = getDb();
  if (domain) {
    const result = db.run("DELETE FROM cache WHERE domain = ?", [domain]);
    return result.changes;
  }
  const result = db.run("DELETE FROM cache");
  return result.changes;
}

export function clearExpiredCache(): number {
  const db = getDb();
  const result = db.run(
    "DELETE FROM cache WHERE expires_at < datetime('now')",
  );
  return result.changes;
}

// ─── Stats ───────────────────────────────────────────────

export interface DbStats {
  totalDomains: number;
  totalScans: number;
  totalSessions: number;
  portfolioSize: number;
  whoisSnapshots: number;
  cacheEntries: number;
  dbSizeBytes: number;
}

export function getDbStats(): DbStats {
  const db = getDb();

  const domains =
    db
      .query<CountRow, []>("SELECT COUNT(*) as c FROM domains")
      .get()?.c ?? 0;
  const scans =
    db
      .query<CountRow, []>("SELECT COUNT(*) as c FROM scans")
      .get()?.c ?? 0;
  const sessions =
    db
      .query<CountRow, []>("SELECT COUNT(*) as c FROM sessions")
      .get()?.c ?? 0;
  const portfolio =
    db
      .query<CountRow, []>("SELECT COUNT(*) as c FROM portfolio")
      .get()?.c ?? 0;
  const whois =
    db
      .query<CountRow, []>("SELECT COUNT(*) as c FROM whois_history")
      .get()?.c ?? 0;
  const cache =
    db
      .query<CountRow, []>(
        "SELECT COUNT(*) as c FROM cache WHERE expires_at > datetime('now')",
      )
      .get()?.c ?? 0;

  // Get file size
  let dbSizeBytes = 0;
  try {
    const file = Bun.file(DB_FILE);
    dbSizeBytes = file.size;
  } catch {
    // File may not exist yet
  }

  return {
    totalDomains: domains,
    totalScans: scans,
    totalSessions: sessions,
    portfolioSize: portfolio,
    whoisSnapshots: whois,
    cacheEntries: cache,
    dbSizeBytes,
  };
}

// ─── Data import from legacy JSON ────────────────────────

interface LegacyPortfolioFile {
  domains?: Array<{
    domain: string;
    registrar?: string;
    purchaseDate?: string;
    expiryDate?: string;
    purchasePrice?: number;
    renewalPrice?: number;
    currency?: string;
    autoRenew?: boolean;
    tags?: string[];
    notes?: string;
  }>;
}

interface LegacySessionFile {
  id?: string;
  domains?: Array<DomainEntry & { status?: string }>;
}

export function importLegacyPortfolio(jsonPath: string): number {
  if (!existsSync(jsonPath)) return 0;
  try {
    const content = readFileSync(jsonPath, "utf-8");
    const data = JSON.parse(content) as LegacyPortfolioFile;
    if (!data || !Array.isArray(data.domains)) return 0;
    let count = 0;
    for (const d of data.domains) {
      addPortfolioDomain(d.domain, {
        registrar: d.registrar,
        purchaseDate: d.purchaseDate,
        expiryDate: d.expiryDate,
        purchasePrice: d.purchasePrice,
        renewalPrice: d.renewalPrice,
        currency: d.currency,
        autoRenew: d.autoRenew,
        tags: d.tags,
        notes: d.notes,
      });
      count++;
    }
    return count;
  } catch {
    return 0;
  }
}

export function importLegacySessions(sessionDir: string): number {
  if (!existsSync(sessionDir)) return 0;
  try {
    const files = readdirSync(sessionDir).filter((f: string) =>
      f.endsWith(".json"),
    );
    let count = 0;
    for (const f of files) {
      try {
        const content = readFileSync(join(sessionDir, f), "utf-8");
        const session = JSON.parse(content) as LegacySessionFile;
        if (!session || !Array.isArray(session.domains)) continue;
        const sessionId = createSession(
          session.id || f.replace(".json", ""),
        );
        for (const d of session.domains) {
          const domainId = upsertDomain(d.domain);
          saveScan(domainId, d.status || "unknown", d, sessionId);
        }
        updateSessionCount(sessionId, session.domains.length);
        count++;
      } catch {
        continue;
      }
    }
    return count;
  } catch {
    return 0;
  }
}
