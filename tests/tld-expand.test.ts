import { test, expect, describe } from "bun:test";
import { expandTlds, POPULAR_TLDS, PREMIUM_TLDS, STARTUP_TLDS } from "../src/core/features/tld-expand.js";

describe("expandTlds", () => {
  test("expands base name across popular TLDs", () => {
    const result = expandTlds("coolapp", "popular");
    expect(result.length).toBe(POPULAR_TLDS.length);
    expect(result).toContain("coolapp.com");
    expect(result).toContain("coolapp.io");
  });

  test("strips existing TLD", () => {
    const result = expandTlds("coolapp.com", "premium");
    expect(result).toContain("coolapp.com");
    expect(result.length).toBe(PREMIUM_TLDS.length);
  });

  test("uses custom TLDs", () => {
    const result = expandTlds("test", "popular", ["com", "net", "org"]);
    expect(result).toEqual(["test.com", "test.net", "test.org"]);
  });

  test("returns empty for empty input", () => {
    expect(expandTlds("", "popular")).toEqual([]);
    expect(expandTlds("  ", "popular")).toEqual([]);
  });

  test("lowercases input", () => {
    const result = expandTlds("HELLO", "premium");
    expect(result[0]).toBe("hello.com");
  });
});
