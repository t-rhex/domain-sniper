import { test, expect, describe } from "bun:test";
import { scoreDomain, scoreGrade } from "../src/features/scoring.js";

describe("scoreDomain", () => {
  test("scores short .com domains highest", () => {
    const result = scoreDomain("go.com");
    expect(result.total).toBeGreaterThan(70);
    expect(result.length).toBe(20); // ultra-short
    expect(result.tld).toBe(20); // .com
  });

  test("scores long obscure TLD domains lower", () => {
    const result = scoreDomain("superlongdomainname123.xyz");
    expect(result.total).toBeLessThan(60);
  });

  test("penalizes numbers and hyphens", () => {
    const clean = scoreDomain("coolapp.com");
    const dirty = scoreDomain("cool-app-123.com");
    expect(clean.readability).toBeGreaterThan(dirty.readability);
  });

  test("returns all score components", () => {
    const result = scoreDomain("test.com");
    expect(result).toHaveProperty("total");
    expect(result).toHaveProperty("length");
    expect(result).toHaveProperty("tld");
    expect(result).toHaveProperty("readability");
    expect(result).toHaveProperty("brandable");
    expect(result).toHaveProperty("seo");
    expect(result).toHaveProperty("breakdown");
    expect(result.total).toBeGreaterThanOrEqual(0);
    expect(result.total).toBeLessThanOrEqual(100);
  });

  test("breakdown is non-empty", () => {
    const result = scoreDomain("example.com");
    expect(result.breakdown.length).toBeGreaterThan(0);
  });
});

describe("scoreGrade", () => {
  test("returns correct grades", () => {
    expect(scoreGrade(90).grade).toBe("A+");
    expect(scoreGrade(80).grade).toBe("A");
    expect(scoreGrade(70).grade).toBe("B+");
    expect(scoreGrade(60).grade).toBe("B");
    expect(scoreGrade(50).grade).toBe("C+");
    expect(scoreGrade(40).grade).toBe("C");
    expect(scoreGrade(30).grade).toBe("D");
    expect(scoreGrade(10).grade).toBe("F");
  });

  test("returns colors for grades", () => {
    const result = scoreGrade(90);
    expect(result.color).toBeTruthy();
    expect(result.color.startsWith("#")).toBe(true);
  });
});
