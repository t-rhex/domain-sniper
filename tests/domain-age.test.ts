import { test, expect, describe } from "bun:test";
import { calculateDomainAge, daysUntilExpiry } from "../src/features/domain-age.js";

describe("calculateDomainAge", () => {
  test("returns null for null input", () => {
    expect(calculateDomainAge(null)).toBeNull();
  });

  test("returns null for invalid date", () => {
    expect(calculateDomainAge("not-a-date")).toBeNull();
  });

  test("formats years and months", () => {
    // 5 years ago
    const fiveYearsAgo = new Date(Date.now() - 5 * 365 * 86400000).toISOString();
    const result = calculateDomainAge(fiveYearsAgo);
    expect(result).toContain("5y");
  });

  test("formats months for <1 year", () => {
    const threeMonthsAgo = new Date(Date.now() - 90 * 86400000).toISOString();
    const result = calculateDomainAge(threeMonthsAgo);
    expect(result).toContain("mo");
  });

  test("formats days for <30 days", () => {
    const fiveDaysAgo = new Date(Date.now() - 5 * 86400000).toISOString();
    const result = calculateDomainAge(fiveDaysAgo);
    expect(result).toBe("5d");
  });

  test("handles future date", () => {
    const future = new Date(Date.now() + 86400000).toISOString();
    expect(calculateDomainAge(future)).toBe("Not yet created");
  });
});

describe("daysUntilExpiry", () => {
  test("returns null for null input", () => {
    expect(daysUntilExpiry(null)).toBeNull();
  });

  test("returns positive for future dates", () => {
    const inThirtyDays = new Date(Date.now() + 30 * 86400000).toISOString();
    const result = daysUntilExpiry(inThirtyDays);
    expect(result).toBeGreaterThanOrEqual(29);
    expect(result).toBeLessThanOrEqual(31);
  });

  test("returns negative for past dates", () => {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 86400000).toISOString();
    const result = daysUntilExpiry(thirtyDaysAgo);
    expect(result).toBeLessThan(0);
  });
});
