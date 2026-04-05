import { test, expect, describe } from "bun:test";
import { generateSuggestions } from "../src/core/features/domain-suggest.js";

describe("generateSuggestions", () => {
  test("generates suggestions from keyword", () => {
    const result = generateSuggestions("cloud");
    expect(result.length).toBeGreaterThan(0);
  });

  test("respects maxResults", () => {
    const result = generateSuggestions("startup", "com", 5);
    expect(result.length).toBeLessThanOrEqual(5);
  });

  test("uses specified TLD", () => {
    const result = generateSuggestions("test", "io", 10);
    expect(result.every((s) => s.domain.endsWith(".io"))).toBe(true);
  });

  test("returns empty for empty keyword", () => {
    expect(generateSuggestions("")).toEqual([]);
    expect(generateSuggestions("  ")).toEqual([]);
  });

  test("includes strategy description", () => {
    const result = generateSuggestions("data", "com", 5);
    expect(result.every((s) => s.strategy.length > 0)).toBe(true);
  });

  test("strips non-alpha characters from keyword", () => {
    const result = generateSuggestions("my-app_123");
    expect(result.length).toBeGreaterThan(0);
  });
});
