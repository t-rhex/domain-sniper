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

// ─── Portfolio Status & Category ─────────────────────────

export type PortfolioStatus = "active" | "parked" | "for-sale" | "development" | "archived";
export type PipelineStatus = "watching" | "bidding" | "negotiating" | "won" | "lost" | "cancelled";
export type TransactionType = "purchase" | "renewal" | "sale" | "parking-revenue" | "affiliate-revenue" | "expense" | "refund";
export type AlertSeverity = "critical" | "warning" | "info";

export function updatePortfolioStatus(domain: string, status: PortfolioStatus): void {
  const db = getDb();
  db.run("UPDATE portfolio SET status = ?, updated_at = datetime('now') WHERE domain = ?", [status, domain]);
}

export function updatePortfolioCategory(domain: string, category: string): void {
  const db = getDb();
  db.run("UPDATE portfolio SET category = ?, updated_at = datetime('now') WHERE domain = ?", [category, domain]);
}

export function updatePortfolioValue(domain: string, value: number): void {
  const db = getDb();
  db.run("UPDATE portfolio SET estimated_value = ?, updated_at = datetime('now') WHERE domain = ?", [value, domain]);
  // Also save valuation history
  db.run("INSERT INTO portfolio_valuations (domain, estimated_value, source) VALUES (?, ?, 'manual')", [domain, value]);
}

export function getPortfolioByStatus(status: PortfolioStatus): DbPortfolioDomain[] {
  const db = getDb();
  return db.query("SELECT * FROM portfolio WHERE status = ? ORDER BY domain").all(status) as DbPortfolioDomain[];
}

export function getPortfolioByCategory(category: string): DbPortfolioDomain[] {
  const db = getDb();
  return db.query("SELECT * FROM portfolio WHERE category = ? ORDER BY domain").all(category) as DbPortfolioDomain[];
}

// ─── Transactions ────────────────────────────────────────

export function addTransaction(
  domain: string,
  type: TransactionType,
  amount: number,
  description: string = "",
  date?: string,
  currency: string = "USD"
): number {
  const db = getDb();
  const result = db.run(
    "INSERT INTO portfolio_transactions (domain, type, amount, currency, description, date) VALUES (?, ?, ?, ?, ?, ?)",
    [domain, type, amount, currency, description, date || new Date().toISOString().split("T")[0]!]
  );
  return Number(result.lastInsertRowid);
}

export function getTransactions(domain?: string, limit: number = 50): Array<{
  id: number; domain: string; type: string; amount: number; currency: string; description: string; date: string;
}> {
  const db = getDb();
  if (domain) {
    return db.query("SELECT * FROM portfolio_transactions WHERE domain = ? ORDER BY date DESC LIMIT ?").all(domain, limit) as any[];
  }
  return db.query("SELECT * FROM portfolio_transactions ORDER BY date DESC LIMIT ?").all(limit) as any[];
}

export function getTransactionsByType(type: TransactionType, limit: number = 100): any[] {
  const db = getDb();
  return db.query("SELECT * FROM portfolio_transactions WHERE type = ? ORDER BY date DESC LIMIT ?").all(type, limit) as any[];
}

export function getDomainPnL(domain: string): { costs: number; revenue: number; profit: number } {
  const db = getDb();
  const costs = (db.query(
    "SELECT COALESCE(SUM(amount), 0) as total FROM portfolio_transactions WHERE domain = ? AND type IN ('purchase','renewal','expense')"
  ).get(domain) as { total: number }).total;

  const revenue = (db.query(
    "SELECT COALESCE(SUM(amount), 0) as total FROM portfolio_transactions WHERE domain = ? AND type IN ('sale','parking-revenue','affiliate-revenue','refund')"
  ).get(domain) as { total: number }).total;

  return { costs, revenue, profit: revenue - costs };
}

export function getPortfolioPnL(): { totalCosts: number; totalRevenue: number; totalProfit: number; domainCount: number } {
  const db = getDb();
  const totalCosts = (db.query(
    "SELECT COALESCE(SUM(amount), 0) as total FROM portfolio_transactions WHERE type IN ('purchase','renewal','expense')"
  ).get() as { total: number }).total;

  const totalRevenue = (db.query(
    "SELECT COALESCE(SUM(amount), 0) as total FROM portfolio_transactions WHERE type IN ('sale','parking-revenue','affiliate-revenue','refund')"
  ).get() as { total: number }).total;

  const domainCount = (db.query("SELECT COUNT(DISTINCT domain) as c FROM portfolio_transactions").get() as { c: number }).c;

  return { totalCosts, totalRevenue, totalProfit: totalRevenue - totalCosts, domainCount };
}

export function getMonthlyReport(months: number = 12): Array<{
  month: string; costs: number; revenue: number; profit: number;
}> {
  const db = getDb();
  const rows = db.query(`
    SELECT
      strftime('%Y-%m', date) as month,
      SUM(CASE WHEN type IN ('purchase','renewal','expense') THEN amount ELSE 0 END) as costs,
      SUM(CASE WHEN type IN ('sale','parking-revenue','affiliate-revenue','refund') THEN amount ELSE 0 END) as revenue
    FROM portfolio_transactions
    WHERE date >= date('now', '-' || ? || ' months')
    GROUP BY month
    ORDER BY month DESC
  `).all(months) as Array<{ month: string; costs: number; revenue: number }>;

  return rows.map((r) => ({ ...r, profit: r.revenue - r.costs }));
}

// ─── Valuations ──────────────────────────────────────────

export function saveValuation(domain: string, value: number, source: string = "manual"): void {
  const db = getDb();
  db.run("INSERT INTO portfolio_valuations (domain, estimated_value, source) VALUES (?, ?, ?)", [domain, value, source]);
  db.run("UPDATE portfolio SET estimated_value = ?, updated_at = datetime('now') WHERE domain = ?", [value, domain]);
}

export function getValuationHistory(domain: string, limit: number = 20): Array<{
  id: number; estimated_value: number; source: string; valued_at: string;
}> {
  const db = getDb();
  return db.query("SELECT * FROM portfolio_valuations WHERE domain = ? ORDER BY valued_at DESC LIMIT ?").all(domain, limit) as any[];
}

export function getTotalPortfolioValue(): number {
  const db = getDb();
  return (db.query("SELECT COALESCE(SUM(estimated_value), 0) as total FROM portfolio").get() as { total: number }).total;
}

// ─── Pipeline ────────────────────────────────────────────

export function addToPipeline(domain: string, details: {
  maxBid?: number; currentPrice?: number; source?: string; notes?: string; priority?: string;
} = {}): void {
  const db = getDb();
  db.run(`
    INSERT INTO acquisition_pipeline (domain, max_bid, current_price, source, notes, priority)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(domain) DO UPDATE SET
      max_bid = excluded.max_bid,
      current_price = excluded.current_price,
      source = excluded.source,
      notes = excluded.notes,
      priority = excluded.priority,
      updated_at = datetime('now')
  `, [domain, details.maxBid ?? null, details.currentPrice ?? null, details.source || "", details.notes || "", details.priority || "medium"]);
}

export function updatePipelineStatus(domain: string, status: PipelineStatus): void {
  const db = getDb();
  db.run("UPDATE acquisition_pipeline SET status = ?, updated_at = datetime('now') WHERE domain = ?", [status, domain]);
}

export function getPipeline(status?: PipelineStatus): any[] {
  const db = getDb();
  if (status) {
    return db.query("SELECT * FROM acquisition_pipeline WHERE status = ? ORDER BY priority, added_at DESC").all(status) as any[];
  }
  return db.query("SELECT * FROM acquisition_pipeline ORDER BY status, priority, added_at DESC").all() as any[];
}

export function removeFromPipeline(domain: string): void {
  const db = getDb();
  db.run("DELETE FROM acquisition_pipeline WHERE domain = ?", [domain]);
}

// ─── Categories ──────────────────────────────────────────

export function getCategories(): Array<{ id: number; name: string; color: string; description: string; count: number }> {
  const db = getDb();
  return db.query(`
    SELECT c.*, COALESCE(p.cnt, 0) as count
    FROM portfolio_categories c
    LEFT JOIN (SELECT category, COUNT(*) as cnt FROM portfolio GROUP BY category) p ON c.name = p.category
    ORDER BY c.name
  `).all() as any[];
}

export function addCategory(name: string, color: string = "#5c9cf5", description: string = ""): void {
  const db = getDb();
  db.run("INSERT OR IGNORE INTO portfolio_categories (name, color, description) VALUES (?, ?, ?)", [name, color, description]);
}

// ─── Alerts ──────────────────────────────────────────────

export function createAlert(domain: string, type: string, severity: AlertSeverity, message: string): number {
  const db = getDb();
  const result = db.run(
    "INSERT INTO portfolio_alerts (domain, type, severity, message) VALUES (?, ?, ?, ?)",
    [domain, type, severity, message]
  );
  return Number(result.lastInsertRowid);
}

export function getUnacknowledgedAlerts(): Array<{
  id: number; domain: string; type: string; severity: string; message: string; created_at: string;
}> {
  const db = getDb();
  return db.query("SELECT * FROM portfolio_alerts WHERE acknowledged = 0 ORDER BY severity DESC, created_at DESC").all() as any[];
}

export function acknowledgeAlert(alertId: number): void {
  const db = getDb();
  db.run("UPDATE portfolio_alerts SET acknowledged = 1 WHERE id = ?", [alertId]);
}

export function acknowledgeAllAlerts(): void {
  const db = getDb();
  db.run("UPDATE portfolio_alerts SET acknowledged = 1 WHERE acknowledged = 0");
}

// ─── Portfolio Dashboard Stats ───────────────────────────

export function getPortfolioDashboard(): {
  totalDomains: number;
  totalValue: number;
  totalCosts: number;
  totalRevenue: number;
  totalProfit: number;
  expiringIn30: number;
  expiringIn90: number;
  activeAlerts: number;
  pipelineCount: number;
  byStatus: Record<string, number>;
  byCategory: Record<string, number>;
  topValueDomains: Array<{ domain: string; estimated_value: number }>;
  recentTransactions: Array<{ domain: string; type: string; amount: number; date: string }>;
} {
  const db = getDb();
  const totalDomains = (db.query("SELECT COUNT(*) as c FROM portfolio").get() as { c: number }).c;
  const totalValue = getTotalPortfolioValue();
  const pnl = getPortfolioPnL();
  const exp30 = getPortfolioExpiring(30).length;
  const exp90 = getPortfolioExpiring(90).length;
  const activeAlerts = (db.query("SELECT COUNT(*) as c FROM portfolio_alerts WHERE acknowledged = 0").get() as { c: number }).c;
  const pipelineCount = (db.query("SELECT COUNT(*) as c FROM acquisition_pipeline WHERE status IN ('watching','bidding','negotiating')").get() as { c: number }).c;

  const statusRows = db.query("SELECT status, COUNT(*) as c FROM portfolio GROUP BY status").all() as Array<{ status: string; c: number }>;
  const byStatus: Record<string, number> = {};
  for (const r of statusRows) byStatus[r.status] = r.c;

  const catRows = db.query("SELECT category, COUNT(*) as c FROM portfolio GROUP BY category").all() as Array<{ category: string; c: number }>;
  const byCategory: Record<string, number> = {};
  for (const r of catRows) byCategory[r.category] = r.c;

  const topValueDomains = db.query("SELECT domain, estimated_value FROM portfolio WHERE estimated_value > 0 ORDER BY estimated_value DESC LIMIT 5").all() as Array<{ domain: string; estimated_value: number }>;
  const recentTransactions = db.query("SELECT domain, type, amount, date FROM portfolio_transactions ORDER BY date DESC LIMIT 5").all() as Array<{ domain: string; type: string; amount: number; date: string }>;

  return {
    totalDomains, totalValue,
    totalCosts: pnl.totalCosts, totalRevenue: pnl.totalRevenue, totalProfit: pnl.totalProfit,
    expiringIn30: exp30, expiringIn90: exp90,
    activeAlerts, pipelineCount,
    byStatus, byCategory,
    topValueDomains, recentTransactions,
  };
}

// ─── Tax Export ───────────────────────────────────────────

export function getTaxExportData(year: number): Array<{
  domain: string;
  purchaseDate: string;
  purchasePrice: number;
  saleDate: string | null;
  salePrice: number | null;
  holdingDays: number | null;
  profit: number;
  currency: string;
}> {
  const db = getDb();
  const yearStr = String(year);

  // Get all domains with transactions in the given year
  const domains = db.query(`
    SELECT DISTINCT domain FROM portfolio_transactions
    WHERE strftime('%Y', date) = ?
  `).all(yearStr) as Array<{ domain: string }>;

  return domains.map((d) => {
    const purchases = db.query(
      "SELECT amount, date FROM portfolio_transactions WHERE domain = ? AND type = 'purchase' ORDER BY date ASC LIMIT 1"
    ).get(d.domain) as { amount: number; date: string } | null;

    const sales = db.query(
      "SELECT amount, date FROM portfolio_transactions WHERE domain = ? AND type = 'sale' AND strftime('%Y', date) = ? ORDER BY date DESC LIMIT 1"
    ).get(d.domain, yearStr) as { amount: number; date: string } | null;

    const totalCosts = (db.query(
      "SELECT COALESCE(SUM(amount), 0) as total FROM portfolio_transactions WHERE domain = ? AND type IN ('purchase', 'renewal', 'expense')"
    ).get(d.domain) as { total: number }).total;

    const totalRevenue = (db.query(
      "SELECT COALESCE(SUM(amount), 0) as total FROM portfolio_transactions WHERE domain = ? AND type IN ('sale', 'parking-revenue', 'affiliate-revenue') AND strftime('%Y', date) = ?"
    ).get(d.domain, yearStr) as { total: number }).total;

    let holdingDays: number | null = null;
    if (purchases && sales) {
      holdingDays = Math.floor((new Date(sales.date).getTime() - new Date(purchases.date).getTime()) / 86400000);
    }

    return {
      domain: d.domain,
      purchaseDate: purchases?.date || "",
      purchasePrice: purchases?.amount || 0,
      saleDate: sales?.date || null,
      salePrice: sales?.amount || null,
      holdingDays,
      profit: totalRevenue - totalCosts,
      currency: "USD",
    };
  });
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
