import { test, expect, describe } from "bun:test";
import { generateVariations } from "../src/core/features/variations.js";

describe("generateVariations", () => {
  test("generates variations", () => {
    const result = generateVariations("example.com");
    expect(result.length).toBeGreaterThan(0);
  });

  test("does not include the original domain", () => {
    const result = generateVariations("test.com");
    expect(result).not.toContain("test.com");
  });

  test("generates plurals", () => {
    const result = generateVariations("app.com", { plurals: true, hyphens: false, prefixes: false, suffixes: false, typos: false, abbreviations: false });
    expect(result).toContain("apps.com");
  });

  test("generates prefixes", () => {
    const result = generateVariations("domain.com", { plurals: false, hyphens: false, prefixes: true, suffixes: false, typos: false, abbreviations: false });
    expect(result).toContain("getdomain.com");
    expect(result).toContain("mydomain.com");
  });

  test("handles domain without TLD", () => {
    const result = generateVariations("test");
    expect(result.length).toBeGreaterThan(0);
    // Should default to .com
    expect(result.some((d) => d.endsWith(".com"))).toBe(true);
  });

  test("returns unique variations", () => {
    const result = generateVariations("test.com");
    const unique = new Set(result);
    expect(unique.size).toBe(result.length);
  });
});
