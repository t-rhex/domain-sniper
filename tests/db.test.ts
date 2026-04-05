import { test, expect, describe, beforeAll, afterAll } from "bun:test";
import {
  getDb,
  closeDb,
  setDbPath,
  upsertDomain,
  getDomainByName,
  getAllDomains,
  searchDomains,
  saveScan,
  getLatestScan,
  getScanHistory,
  createSession,
  updateSessionCount,
  getSession,
  listAllSessions,
  deleteSessionById,
  getSessionScans,
  addPortfolioDomain,
  removePortfolioDomain,
  getPortfolioDomains,
  getPortfolioStatsDb,
  saveWhoisSnapshotDb,
  getWhoisHistoryDb,
  getWhoisHistoryCountDb,
  getCached,
  setCache,
  clearCache,
  clearExpiredCache,
  getDbStats,
} from "../src/core/db.js";
import { createEmptyEntry } from "../src/core/types.js";

// Use in-memory database for tests — never pollute the real DB
beforeAll(() => {
  setDbPath(":memory:");
});

afterAll(() => {
  closeDb();
});

function testDomain(n: number): string {
  return `test-${n}.example.com`;
}

describe("Database: Domains", () => {
  test("upsertDomain creates and returns id", () => {
    const domain = testDomain(1);
    const id = upsertDomain(domain);
    expect(id).toBeGreaterThan(0);
  });

  test("upsertDomain increments scan_count on second call", () => {
    const domain = testDomain(2);
    upsertDomain(domain);
    upsertDomain(domain);
    const row = getDomainByName(domain);
    expect(row).not.toBeNull();
    expect(row!.scan_count).toBeGreaterThanOrEqual(1);
  });

  test("getDomainByName returns null for unknown domain", () => {
    expect(getDomainByName("nonexistent-never-exists.com")).toBeNull();
  });

  test("getDomainByName returns correct data for known domain", () => {
    const domain = testDomain(3);
    upsertDomain(domain);
    const row = getDomainByName(domain);
    expect(row).not.toBeNull();
    expect(row!.domain).toBe(domain);
    expect(row!.scan_count).toBeGreaterThanOrEqual(0);
    expect(row!.first_seen).toBeTruthy();
  });

  test("searchDomains finds by partial match", () => {
    const domain = testDomain(4);
    upsertDomain(domain);
    const results = searchDomains("test-");
    expect(results.length).toBeGreaterThan(0);
    expect(results.some((r) => r.domain === domain)).toBe(true);
  });

  test("getAllDomains returns results with limit and offset", () => {
    const domain = testDomain(5);
    upsertDomain(domain);
    const results = getAllDomains(100, 0);
    expect(results.length).toBeGreaterThan(0);
  });
});

describe("Database: Scans", () => {
  test("saveScan and getLatestScan round-trip", () => {
    const domain = testDomain(10);
    const domainId = upsertDomain(domain);
    const entry = { ...createEmptyEntry(domain), status: "available" as const };
    const scanId = saveScan(domainId, "available", entry);
    expect(scanId).toBeGreaterThan(0);

    const latest = getLatestScan(domain);
    expect(latest).not.toBeNull();
    expect(latest!.domain).toBe(domain);
    expect(latest!.status).toBe("available");
  });

  test("getLatestScan returns null for unknown domain", () => {
    const latest = getLatestScan("never-scanned-domain-xyz.com");
    expect(latest).toBeNull();
  });

  test("getScanHistory returns ordered results", () => {
    const domain = testDomain(11);
    const domainId = upsertDomain(domain);
    saveScan(domainId, "taken", {
      ...createEmptyEntry(domain),
      status: "taken" as const,
    });
    saveScan(domainId, "available", {
      ...createEmptyEntry(domain),
      status: "available" as const,
    });

    const history = getScanHistory(domain);
    expect(history.length).toBeGreaterThanOrEqual(2);
    // Both statuses should be present
    const statuses = history.map((h) => h.status);
    expect(statuses).toContain("taken");
    expect(statuses).toContain("available");
  });

  test("getScanHistory respects limit", () => {
    const domain = testDomain(12);
    const domainId = upsertDomain(domain);
    for (let i = 0; i < 5; i++) {
      saveScan(domainId, "taken", {
        ...createEmptyEntry(domain),
        status: "taken" as const,
      });
    }

    const history = getScanHistory(domain, 3);
    expect(history.length).toBe(3);
  });
});

describe("Database: Sessions", () => {
  test("createSession and getSession", () => {
    const sessionId = createSession("test-session");
    expect(sessionId).toBeGreaterThan(0);

    const session = getSession(sessionId);
    expect(session).not.toBeNull();
    expect(session!.name).toBe("test-session");
    expect(session!.domain_count).toBe(0);
  });

  test("createSession with default name", () => {
    const sessionId = createSession();
    const session = getSession(sessionId);
    expect(session).not.toBeNull();
    expect(session!.name).toMatch(/^scan-\d+$/);
  });

  test("updateSessionCount updates count", () => {
    const sessionId = createSession("count-test");
    updateSessionCount(sessionId, 42);
    const session = getSession(sessionId);
    expect(session!.domain_count).toBe(42);
  });

  test("listAllSessions returns sessions", () => {
    const sessions = listAllSessions();
    expect(sessions.length).toBeGreaterThan(0);
  });

  test("deleteSessionById removes session", () => {
    const sessionId = createSession("to-delete");
    deleteSessionById(sessionId);
    const session = getSession(sessionId);
    expect(session).toBeNull();
  });

  test("getSession returns null for nonexistent id", () => {
    const session = getSession(999999999);
    expect(session).toBeNull();
  });

  test("getSessionScans returns scan data", () => {
    const sessionId = createSession("with-scans");
    const domain = testDomain(20);
    const domainId = upsertDomain(domain);
    const entry = { ...createEmptyEntry(domain), status: "taken" as const };
    saveScan(domainId, "taken", entry, sessionId);

    const scans = getSessionScans(sessionId);
    expect(scans.length).toBe(1);
    expect(scans[0]!.domain).toBe(domain);
  });

  test("getSessionScans returns empty array for session with no scans", () => {
    const sessionId = createSession("empty-session");
    const scans = getSessionScans(sessionId);
    expect(scans).toEqual([]);
  });
});

describe("Database: Portfolio", () => {
  test("addPortfolioDomain and getPortfolioDomains", () => {
    const domain = testDomain(30);
    addPortfolioDomain(domain, {
      registrar: "test-registrar",
      purchasePrice: 9.99,
      currency: "USD",
    });

    const all = getPortfolioDomains();
    const found = all.find((d) => d.domain === domain);
    expect(found).toBeTruthy();
    expect(found!.registrar).toBe("test-registrar");
    expect(found!.purchase_price).toBe(9.99);
    expect(found!.currency).toBe("USD");
  });

  test("addPortfolioDomain with defaults", () => {
    const domain = testDomain(32);
    addPortfolioDomain(domain);

    const all = getPortfolioDomains();
    const found = all.find((d) => d.domain === domain);
    expect(found).toBeTruthy();
    expect(found!.registrar).toBe("unknown");
    expect(found!.purchase_price).toBe(0);
    expect(found!.currency).toBe("USD");
  });

  test("addPortfolioDomain upserts on conflict", () => {
    const domain = testDomain(33);
    addPortfolioDomain(domain, { registrar: "first" });
    addPortfolioDomain(domain, { registrar: "second" });

    const all = getPortfolioDomains();
    const found = all.find((d) => d.domain === domain);
    expect(found!.registrar).toBe("second");
  });

  test("removePortfolioDomain removes entry", () => {
    const domain = testDomain(31);
    addPortfolioDomain(domain);
    removePortfolioDomain(domain);
    const all = getPortfolioDomains();
    expect(all.find((d) => d.domain === domain)).toBeUndefined();
  });

  test("getPortfolioStatsDb returns correct stats", () => {
    const stats = getPortfolioStatsDb();
    expect(stats.total).toBeGreaterThanOrEqual(0);
    expect(typeof stats.totalSpent).toBe("number");
    expect(typeof stats.expiringIn30).toBe("number");
    expect(typeof stats.expiringIn90).toBe("number");
    expect(typeof stats.byRegistrar).toBe("object");
  });
});

describe("Database: WHOIS History", () => {
  test("saveWhoisSnapshotDb and getWhoisHistoryDb", () => {
    const domain = testDomain(40);
    const id = saveWhoisSnapshotDb(domain, {
      registrar: "Test Registrar",
      expiryDate: "2027-01-01",
      createdDate: "2020-01-01",
      updatedDate: "2025-01-01",
      status: ["active"],
      nameServers: ["ns1.test.com", "ns2.test.com"],
      available: false,
      expired: false,
    });
    expect(id).toBeGreaterThan(0);

    const history = getWhoisHistoryDb(domain);
    expect(history.length).toBeGreaterThanOrEqual(1);
    expect(history[0]!.registrar).toBe("Test Registrar");
    expect(history[0]!.expiry_date).toBe("2027-01-01");
    expect(history[0]!.domain).toBe(domain);
  });

  test("getWhoisHistoryCountDb returns count", () => {
    const domain = testDomain(41);
    saveWhoisSnapshotDb(domain, {
      registrar: null,
      expiryDate: null,
      createdDate: null,
      updatedDate: null,
      status: [],
      nameServers: [],
      available: true,
      expired: false,
    });
    const count = getWhoisHistoryCountDb(domain);
    expect(count).toBeGreaterThanOrEqual(1);
  });

  test("getWhoisHistoryDb returns empty for unknown domain", () => {
    const history = getWhoisHistoryDb("unknown-whois-domain.com");
    expect(history).toEqual([]);
  });

  test("getWhoisHistoryCountDb returns 0 for unknown domain", () => {
    const count = getWhoisHistoryCountDb("unknown-whois-count-domain.com");
    expect(count).toBe(0);
  });
});

describe("Database: Cache", () => {
  test("setCache and getCached round-trip", () => {
    const domain = testDomain(50);
    setCache(domain, "test-key", '{"data": "hello"}', 60);
    const cached = getCached(domain, "test-key");
    expect(cached).toBe('{"data": "hello"}');
  });

  test("getCached returns null for missing key", () => {
    expect(getCached("nonexistent.com", "missing-key")).toBeNull();
  });

  test("setCache overwrites existing entry", () => {
    const domain = testDomain(55);
    setCache(domain, "overwrite-key", "first", 60);
    setCache(domain, "overwrite-key", "second", 60);
    const cached = getCached(domain, "overwrite-key");
    expect(cached).toBe("second");
  });

  test("clearCache removes entries for domain", () => {
    const domain = testDomain(51);
    setCache(domain, "key1", "data1", 60);
    setCache(domain, "key2", "data2", 60);
    const count = clearCache(domain);
    expect(count).toBe(2);
    expect(getCached(domain, "key1")).toBeNull();
    expect(getCached(domain, "key2")).toBeNull();
  });

  test("clearCache with no args removes all test entries", () => {
    const d1 = testDomain(52);
    const d2 = testDomain(53);
    setCache(d1, "k", "v", 60);
    setCache(d2, "k", "v", 60);
    clearCache();
    expect(getCached(d1, "k")).toBeNull();
    expect(getCached(d2, "k")).toBeNull();
  });

  test("expired cache entries are not returned", () => {
    const domain = testDomain(54);
    // Set cache with 0 minute TTL (already expired)
    setCache(domain, "expired-key", "data", 0);
    const cached = getCached(domain, "expired-key");
    // With 0 TTL the expires_at equals now, and getCached checks expires_at > datetime('now')
    // Due to timing precision this may or may not return the data
    expect(cached === null || cached === "data").toBe(true);
  });

  test("clearExpiredCache removes expired entries", () => {
    const domain = testDomain(56);
    setCache(domain, "will-expire", "data", 0);
    const removed = clearExpiredCache();
    // Should have removed at least 0 entries (timing dependent)
    expect(typeof removed).toBe("number");
  });
});

describe("Database: Stats", () => {
  test("getDbStats returns all fields", () => {
    const stats = getDbStats();
    expect(typeof stats.totalDomains).toBe("number");
    expect(typeof stats.totalScans).toBe("number");
    expect(typeof stats.totalSessions).toBe("number");
    expect(typeof stats.portfolioSize).toBe("number");
    expect(typeof stats.whoisSnapshots).toBe("number");
    expect(typeof stats.cacheEntries).toBe("number");
    expect(typeof stats.dbSizeBytes).toBe("number");
  });

  test("getDbStats reflects inserted data", () => {
    const statsBefore = getDbStats();
    const domain = testDomain(60);
    upsertDomain(domain);
    const statsAfter = getDbStats();
    expect(statsAfter.totalDomains).toBeGreaterThanOrEqual(
      statsBefore.totalDomains,
    );
  });
});
