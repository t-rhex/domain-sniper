import { test, expect, describe } from "bun:test";
import { filterDomains, nextStatus, nextSort, DEFAULT_FILTER } from "../src/core/features/filter.js";
import { createEmptyEntry } from "../src/core/types.js";
import type { DomainEntry } from "../src/core/types.js";

function makeEntry(domain: string, status: DomainEntry["status"]): DomainEntry {
  return { ...createEmptyEntry(domain), status };
}

describe("filterDomains", () => {
  const entries = [
    makeEntry("available.com", "available"),
    makeEntry("expired.net", "expired"),
    makeEntry("taken.io", "taken"),
    makeEntry("another.com", "available"),
    makeEntry("error.dev", "error"),
  ];

  test("returns all with default filter", () => {
    const result = filterDomains(entries, DEFAULT_FILTER);
    expect(result.length).toBe(5);
  });

  test("filters by status", () => {
    const result = filterDomains(entries, { ...DEFAULT_FILTER, status: "available" });
    expect(result.length).toBe(2);
    expect(result.every((d) => d.status === "available")).toBe(true);
  });

  test("filters actionable (available + expired)", () => {
    const result = filterDomains(entries, { ...DEFAULT_FILTER, status: "actionable" });
    expect(result.length).toBe(3);
  });

  test("search filters by domain name", () => {
    const result = filterDomains(entries, { ...DEFAULT_FILTER, search: "another" });
    expect(result.length).toBe(1);
    expect(result[0]!.domain).toBe("another.com");
  });

  test("sorts by domain name", () => {
    const result = filterDomains(entries, { ...DEFAULT_FILTER, sort: "domain", order: "asc" });
    expect(result[0]!.domain).toBe("another.com");
  });

  test("sorts by status", () => {
    const result = filterDomains(entries, { ...DEFAULT_FILTER, sort: "status", order: "asc" });
    expect(result[0]!.status).toBe("available");
  });

  test("respects sort order", () => {
    const asc = filterDomains(entries, { ...DEFAULT_FILTER, sort: "domain", order: "asc" });
    const desc = filterDomains(entries, { ...DEFAULT_FILTER, sort: "domain", order: "desc" });
    expect(asc[0]!.domain).not.toBe(desc[0]!.domain);
  });
});

describe("nextStatus", () => {
  test("cycles through statuses", () => {
    expect(nextStatus("all")).toBe("available");
    expect(nextStatus("available")).toBe("expired");
    expect(nextStatus("actionable")).toBe("all");
  });
});

describe("nextSort", () => {
  test("cycles through sort fields", () => {
    expect(nextSort("domain")).toBe("status");
    expect(nextSort("price")).toBe("domain");
  });
});
