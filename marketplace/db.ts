import { Database } from "bun:sqlite";
import { mkdirSync, existsSync } from "fs";
import { join } from "path";
import { homedir } from "os";

const APP_DIR = process.env.DATA_DIR || join(homedir(), ".domain-sniper");
const MARKET_DB_FILE = join(APP_DIR, "marketplace.db");

let _db: Database | null = null;

export function getMarketDb(): Database {
  if (_db) return _db;
  if (!existsSync(APP_DIR)) mkdirSync(APP_DIR, { recursive: true });
  _db = new Database(MARKET_DB_FILE);
  _db.run("PRAGMA journal_mode = WAL");
  _db.run("PRAGMA foreign_keys = ON");
  _db.run("PRAGMA busy_timeout = 5000");
  runMigrations(_db);
  return _db;
}

export function closeMarketDb(): void {
  if (_db) {
    _db.close();
    _db = null;
  }
}

function runMigrations(db: Database): void {
  db.run(`CREATE TABLE IF NOT EXISTS market_migrations (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, applied_at TEXT DEFAULT (datetime('now'))
  )`);

  const applied = new Set(
    db
      .query("SELECT name FROM market_migrations")
      .all()
      .map((r) => (r as { name: string }).name),
  );

  for (const m of MIGRATIONS) {
    if (!applied.has(m.name)) {
      for (const stmt of m.statements) {
        db.run(stmt);
      }
      db.run("INSERT INTO market_migrations (name) VALUES (?)", [m.name]);
    }
  }
}

interface Migration {
  name: string;
  statements: string[];
}

const MIGRATIONS: Migration[] = [
  {
    name: "001_listings",
    statements: [
      `CREATE TABLE IF NOT EXISTS listings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        domain TEXT NOT NULL,
        title TEXT DEFAULT '',
        description TEXT DEFAULT '',
        asking_price REAL NOT NULL,
        min_offer REAL DEFAULT 0,
        currency TEXT DEFAULT 'USD',
        buy_now INTEGER DEFAULT 0,
        verified INTEGER DEFAULT 0,
        verification_method TEXT,
        verification_token TEXT,
        verification_expires TEXT,
        status TEXT DEFAULT 'draft',
        views INTEGER DEFAULT 0,
        category TEXT DEFAULT 'other',
        tags TEXT DEFAULT '[]',
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now'))
      )`,
      `CREATE INDEX IF NOT EXISTS idx_listings_domain ON listings(domain)`,
      `CREATE INDEX IF NOT EXISTS idx_listings_user ON listings(user_id)`,
      `CREATE INDEX IF NOT EXISTS idx_listings_status ON listings(status)`,
      `CREATE UNIQUE INDEX IF NOT EXISTS idx_listings_domain_active ON listings(domain) WHERE status IN ('active', 'pending')`,
    ],
  },
  {
    name: "002_offers",
    statements: [
      `CREATE TABLE IF NOT EXISTS offers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        listing_id INTEGER NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
        buyer_id TEXT NOT NULL,
        seller_id TEXT NOT NULL,
        amount REAL NOT NULL,
        currency TEXT DEFAULT 'USD',
        message TEXT DEFAULT '',
        status TEXT DEFAULT 'pending',
        counter_amount REAL,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now')),
        expires_at TEXT
      )`,
      `CREATE INDEX IF NOT EXISTS idx_offers_listing ON offers(listing_id)`,
      `CREATE INDEX IF NOT EXISTS idx_offers_buyer ON offers(buyer_id)`,
      `CREATE INDEX IF NOT EXISTS idx_offers_seller ON offers(seller_id)`,
      `CREATE INDEX IF NOT EXISTS idx_offers_status ON offers(status)`,
    ],
  },
  {
    name: "003_user_profiles",
    statements: [
      `CREATE TABLE IF NOT EXISTS user_profiles (
        user_id TEXT PRIMARY KEY,
        display_name TEXT DEFAULT '',
        bio TEXT DEFAULT '',
        website TEXT DEFAULT '',
        verified_seller INTEGER DEFAULT 0,
        total_sales INTEGER DEFAULT 0,
        total_purchases INTEGER DEFAULT 0,
        rating REAL DEFAULT 0,
        rating_count INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now'))
      )`,
    ],
  },
  {
    name: "004_reviews",
    statements: [
      `CREATE TABLE IF NOT EXISTS reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        listing_id INTEGER NOT NULL REFERENCES listings(id),
        reviewer_id TEXT NOT NULL,
        reviewed_id TEXT NOT NULL,
        rating INTEGER NOT NULL CHECK(rating >= 1 AND rating <= 5),
        comment TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now'))
      )`,
      `CREATE INDEX IF NOT EXISTS idx_reviews_reviewed ON reviews(reviewed_id)`,
    ],
  },
  {
    name: "005_messages",
    statements: [
      `CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        offer_id INTEGER REFERENCES offers(id) ON DELETE CASCADE,
        sender_id TEXT NOT NULL,
        recipient_id TEXT NOT NULL,
        content TEXT NOT NULL,
        read INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now'))
      )`,
      `CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id, read)`,
    ],
  },
  {
    name: "006_watchlist",
    statements: [
      `CREATE TABLE IF NOT EXISTS market_watchlist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        listing_id INTEGER NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
        created_at TEXT DEFAULT (datetime('now')),
        UNIQUE(user_id, listing_id)
      )`,
    ],
  },
];

// ─── Listing CRUD ────────────────────────────────────────

export type ListingStatus =
  | "draft"
  | "pending"
  | "active"
  | "sold"
  | "cancelled"
  | "expired";
export type OfferStatus =
  | "pending"
  | "accepted"
  | "rejected"
  | "countered"
  | "withdrawn"
  | "expired";

interface ListingRow {
  id: number;
  user_id: string;
  domain: string;
  title: string;
  description: string;
  asking_price: number;
  min_offer: number;
  currency: string;
  buy_now: number;
  verified: number;
  verification_method: string | null;
  verification_token: string | null;
  verification_expires: string | null;
  status: string;
  views: number;
  category: string;
  tags: string;
  created_at: string;
  updated_at: string;
}

interface OfferRow {
  id: number;
  listing_id: number;
  buyer_id: string;
  seller_id: string;
  amount: number;
  currency: string;
  message: string;
  status: string;
  counter_amount: number | null;
  created_at: string;
  updated_at: string;
  expires_at: string | null;
}

interface UserProfileRow {
  user_id: string;
  display_name: string;
  bio: string;
  website: string;
  verified_seller: number;
  total_sales: number;
  total_purchases: number;
  rating: number;
  rating_count: number;
  created_at: string;
}

interface MessageRow {
  id: number;
  offer_id: number;
  sender_id: string;
  recipient_id: string;
  content: string;
  read: number;
  created_at: string;
}

interface CountRow {
  c: number;
}

export function createListing(
  userId: string,
  domain: string,
  askingPrice: number,
  details: {
    title?: string;
    description?: string;
    minOffer?: number;
    buyNow?: boolean;
    category?: string;
    tags?: string[];
  } = {},
): number {
  const db = getMarketDb();
  const token = crypto.randomUUID();
  const result = db.run(
    `
    INSERT INTO listings (user_id, domain, title, description, asking_price, min_offer, buy_now, category, tags, verification_token, verification_expires)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '+7 days'))
  `,
    [
      userId,
      domain,
      details.title || domain,
      details.description || "",
      askingPrice,
      details.minOffer || 0,
      details.buyNow ? 1 : 0,
      details.category || "other",
      JSON.stringify(details.tags || []),
      token,
    ],
  );
  return Number(result.lastInsertRowid);
}

export function getListing(id: number): ListingRow | null {
  return getMarketDb()
    .query("SELECT * FROM listings WHERE id = ?")
    .get(id) as ListingRow | null;
}

export function getListingByDomain(domain: string): ListingRow | null {
  return getMarketDb()
    .query(
      "SELECT * FROM listings WHERE domain = ? AND status IN ('active','pending') ORDER BY created_at DESC LIMIT 1",
    )
    .get(domain) as ListingRow | null;
}

export function updateListingStatus(id: number, status: ListingStatus): void {
  getMarketDb().run(
    "UPDATE listings SET status = ?, updated_at = datetime('now') WHERE id = ?",
    [status, id],
  );
}

export function verifyListing(id: number, method: string): void {
  getMarketDb().run(
    "UPDATE listings SET verified = 1, verification_method = ?, status = 'active', updated_at = datetime('now') WHERE id = ?",
    [method, id],
  );
}

export function searchListings(query: {
  search?: string;
  category?: string;
  minPrice?: number;
  maxPrice?: number;
  verified?: boolean;
  sortBy?: string;
  limit?: number;
  offset?: number;
}): { listings: ListingRow[]; total: number } {
  const db = getMarketDb();
  const conditions: string[] = ["status = 'active'"];
  const params: (string | number)[] = [];

  if (query.search) {
    conditions.push(
      "(domain LIKE ? OR title LIKE ? OR description LIKE ?)",
    );
    params.push(
      `%${query.search}%`,
      `%${query.search}%`,
      `%${query.search}%`,
    );
  }
  if (query.category) {
    conditions.push("category = ?");
    params.push(query.category);
  }
  if (query.minPrice !== undefined) {
    conditions.push("asking_price >= ?");
    params.push(query.minPrice);
  }
  if (query.maxPrice !== undefined) {
    conditions.push("asking_price <= ?");
    params.push(query.maxPrice);
  }
  if (query.verified) {
    conditions.push("verified = 1");
  }

  const where =
    conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
  const sortMap: Record<string, string> = {
    price_asc: "asking_price ASC",
    price_desc: "asking_price DESC",
    newest: "created_at DESC",
    popular: "views DESC",
  };
  const orderBy = sortMap[query.sortBy || "newest"] || "created_at DESC";
  const limit = Math.min(query.limit || 20, 100);
  const offset = query.offset || 0;

  const total = (
    db
      .query(`SELECT COUNT(*) as c FROM listings ${where}`)
      .get(...params) as CountRow
  ).c;
  const listings = db
    .query(
      `SELECT * FROM listings ${where} ORDER BY ${orderBy} LIMIT ? OFFSET ?`,
    )
    .all(...params, limit, offset) as ListingRow[];

  return { listings, total };
}

export function getUserListings(userId: string): ListingRow[] {
  return getMarketDb()
    .query(
      "SELECT * FROM listings WHERE user_id = ? ORDER BY created_at DESC",
    )
    .all(userId) as ListingRow[];
}

export function incrementViews(listingId: number): void {
  getMarketDb().run(
    "UPDATE listings SET views = views + 1 WHERE id = ?",
    [listingId],
  );
}

// ─── Offers ──────────────────────────────────────────────

export function createOffer(
  listingId: number,
  buyerId: string,
  sellerId: string,
  amount: number,
  message: string = "",
): number {
  const db = getMarketDb();
  const result = db.run(
    `
    INSERT INTO offers (listing_id, buyer_id, seller_id, amount, message, expires_at)
    VALUES (?, ?, ?, ?, ?, datetime('now', '+7 days'))
  `,
    [listingId, buyerId, sellerId, amount, message],
  );
  return Number(result.lastInsertRowid);
}

export function getOffer(id: number): OfferRow | null {
  return getMarketDb()
    .query("SELECT * FROM offers WHERE id = ?")
    .get(id) as OfferRow | null;
}

export function updateOfferStatus(
  id: number,
  status: OfferStatus,
  counterAmount?: number,
): void {
  const db = getMarketDb();
  if (counterAmount !== undefined) {
    db.run(
      "UPDATE offers SET status = ?, counter_amount = ?, updated_at = datetime('now') WHERE id = ?",
      [status, counterAmount, id],
    );
  } else {
    db.run(
      "UPDATE offers SET status = ?, updated_at = datetime('now') WHERE id = ?",
      [status, id],
    );
  }
}

export function getOffersForListing(listingId: number): OfferRow[] {
  return getMarketDb()
    .query(
      "SELECT * FROM offers WHERE listing_id = ? ORDER BY created_at DESC",
    )
    .all(listingId) as OfferRow[];
}

interface OfferWithListingRow extends OfferRow {
  domain: string;
  asking_price: number;
}

export function getUserOffers(
  userId: string,
  role: "buyer" | "seller",
): OfferWithListingRow[] {
  const col = role === "buyer" ? "buyer_id" : "seller_id";
  return getMarketDb()
    .query(
      `SELECT o.*, l.domain, l.asking_price FROM offers o JOIN listings l ON o.listing_id = l.id WHERE o.${col} = ? ORDER BY o.created_at DESC`,
    )
    .all(userId) as OfferWithListingRow[];
}

// ─── User Profiles ───────────────────────────────────────

export function getOrCreateProfile(userId: string): UserProfileRow {
  const db = getMarketDb();
  let profile = db
    .query("SELECT * FROM user_profiles WHERE user_id = ?")
    .get(userId) as UserProfileRow | null;
  if (!profile) {
    db.run("INSERT INTO user_profiles (user_id) VALUES (?)", [userId]);
    profile = db
      .query("SELECT * FROM user_profiles WHERE user_id = ?")
      .get(userId) as UserProfileRow;
  }
  return profile;
}

export function updateProfile(
  userId: string,
  data: { displayName?: string; bio?: string; website?: string },
): void {
  const db = getMarketDb();
  if (data.displayName !== undefined)
    db.run("UPDATE user_profiles SET display_name = ? WHERE user_id = ?", [
      data.displayName,
      userId,
    ]);
  if (data.bio !== undefined)
    db.run("UPDATE user_profiles SET bio = ? WHERE user_id = ?", [
      data.bio,
      userId,
    ]);
  if (data.website !== undefined)
    db.run("UPDATE user_profiles SET website = ? WHERE user_id = ?", [
      data.website,
      userId,
    ]);
}

// ─── Messages ────────────────────────────────────────────

export function sendMessage(
  offerId: number,
  senderId: string,
  recipientId: string,
  content: string,
): number {
  const result = getMarketDb().run(
    "INSERT INTO messages (offer_id, sender_id, recipient_id, content) VALUES (?, ?, ?, ?)",
    [offerId, senderId, recipientId, content],
  );
  return Number(result.lastInsertRowid);
}

export function getMessages(offerId: number): MessageRow[] {
  return getMarketDb()
    .query(
      "SELECT * FROM messages WHERE offer_id = ? ORDER BY created_at ASC",
    )
    .all(offerId) as MessageRow[];
}

export function getUnreadCount(userId: string): number {
  return (
    getMarketDb()
      .query(
        "SELECT COUNT(*) as c FROM messages WHERE recipient_id = ? AND read = 0",
      )
      .get(userId) as CountRow
  ).c;
}

export function markRead(userId: string, offerId: number): void {
  getMarketDb().run(
    "UPDATE messages SET read = 1 WHERE recipient_id = ? AND offer_id = ?",
    [userId, offerId],
  );
}

// ─── Watchlist ───────────────────────────────────────────

export function addToWatchlist(userId: string, listingId: number): void {
  getMarketDb().run(
    "INSERT OR IGNORE INTO market_watchlist (user_id, listing_id) VALUES (?, ?)",
    [userId, listingId],
  );
}

export function removeFromWatchlist(
  userId: string,
  listingId: number,
): void {
  getMarketDb().run(
    "DELETE FROM market_watchlist WHERE user_id = ? AND listing_id = ?",
    [userId, listingId],
  );
}

export function getWatchlist(userId: string): ListingRow[] {
  return getMarketDb()
    .query(
      `
    SELECT l.* FROM market_watchlist w JOIN listings l ON w.listing_id = l.id
    WHERE w.user_id = ? ORDER BY w.created_at DESC
  `,
    )
    .all(userId) as ListingRow[];
}

// ─── Stats ───────────────────────────────────────────────

export function getMarketStats(): {
  totalListings: number;
  activeListings: number;
  totalOffers: number;
  totalUsers: number;
} {
  const db = getMarketDb();
  return {
    totalListings: (
      db.query("SELECT COUNT(*) as c FROM listings").get() as CountRow
    ).c,
    activeListings: (
      db
        .query(
          "SELECT COUNT(*) as c FROM listings WHERE status = 'active'",
        )
        .get() as CountRow
    ).c,
    totalOffers: (
      db.query("SELECT COUNT(*) as c FROM offers").get() as CountRow
    ).c,
    totalUsers: (
      db
        .query("SELECT COUNT(*) as c FROM user_profiles")
        .get() as CountRow
    ).c,
  };
}
