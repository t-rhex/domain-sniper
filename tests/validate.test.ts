import { test, expect, describe } from "bun:test";
import { isValidDomain, assertValidDomain, sanitizeDomainList, isValidSessionId, safePath, detectTldTypo } from "../src/core/validate.js";

describe("isValidDomain", () => {
  test("accepts valid domains", () => {
    expect(isValidDomain("example.com")).toBe(true);
    expect(isValidDomain("sub.example.com")).toBe(true);
    expect(isValidDomain("my-domain.io")).toBe(true);
    expect(isValidDomain("a.co")).toBe(true);
    expect(isValidDomain("test.dev")).toBe(true);
    expect(isValidDomain("deep.sub.domain.example.com")).toBe(true);
  });

  test("accepts uppercase (case insensitive)", () => {
    expect(isValidDomain("Example.COM")).toBe(true);
    expect(isValidDomain("GOOGLE.COM")).toBe(true);
  });

  test("rejects invalid domains", () => {
    expect(isValidDomain("")).toBe(false);
    expect(isValidDomain("localhost")).toBe(false);
    expect(isValidDomain("-invalid.com")).toBe(false);
    expect(isValidDomain("invalid-.com")).toBe(false);
    expect(isValidDomain(".com")).toBe(false);
    expect(isValidDomain("domain.")).toBe(false);
    expect(isValidDomain("dom ain.com")).toBe(false);
    expect(isValidDomain("domain.c")).toBe(false);  // TLD too short
  });

  test("rejects shell injection attempts", () => {
    expect(isValidDomain("example.com; rm -rf /")).toBe(false);
    expect(isValidDomain("$(whoami).com")).toBe(false);
    expect(isValidDomain("example.com | cat /etc/passwd")).toBe(false);
    expect(isValidDomain("`whoami`.com")).toBe(false);
    expect(isValidDomain("example.com && echo pwned")).toBe(false);
  });

  test("rejects domains over 253 characters", () => {
    const longDomain = "a".repeat(250) + ".com";
    expect(isValidDomain(longDomain)).toBe(false);
  });
});

describe("assertValidDomain", () => {
  test("does not throw for valid domains", () => {
    expect(() => assertValidDomain("example.com")).not.toThrow();
  });

  test("throws for invalid domains", () => {
    expect(() => assertValidDomain("")).toThrow("Invalid domain");
    expect(() => assertValidDomain("; rm -rf /")).toThrow("Invalid domain");
  });
});

describe("sanitizeDomainList", () => {
  test("filters invalid domains", () => {
    const input = ["example.com", "invalid", "test.io", "; rm -rf /", "good.dev"];
    const result = sanitizeDomainList(input);
    expect(result).toEqual(["example.com", "test.io", "good.dev"]);
  });

  test("lowercases domains", () => {
    const result = sanitizeDomainList(["EXAMPLE.COM", "Test.IO"]);
    expect(result).toEqual(["example.com", "test.io"]);
  });

  test("returns empty array for all invalid", () => {
    expect(sanitizeDomainList(["invalid", "also-invalid"])).toEqual([]);
  });

  test("handles empty array", () => {
    expect(sanitizeDomainList([])).toEqual([]);
  });
});

describe("isValidSessionId", () => {
  test("accepts valid session IDs", () => {
    expect(isValidSessionId("scan-123456")).toBe(true);
    expect(isValidSessionId("abc")).toBe(true);
    expect(isValidSessionId("a-b-c")).toBe(true);
  });

  test("rejects invalid session IDs", () => {
    expect(isValidSessionId("")).toBe(false);
    expect(isValidSessionId("../etc/passwd")).toBe(false);
    expect(isValidSessionId("/absolute/path")).toBe(false);
    expect(isValidSessionId("has spaces")).toBe(false);
    expect(isValidSessionId("a".repeat(101))).toBe(false);
  });
});

describe("safePath", () => {
  test("allows paths within allowed roots", () => {
    const result = safePath("./test.csv", [process.cwd()]);
    expect(result).toContain("test.csv");
  });

  test("rejects paths outside allowed roots", () => {
    expect(() => safePath("/etc/passwd", [process.cwd()])).toThrow("outside allowed roots");
    expect(() => safePath("../../etc/passwd", ["/tmp"])).toThrow("outside allowed roots");
  });
});

describe("detectTldTypo", () => {
  test("detects common typos from correction table", () => {
    expect(detectTldTypo("google.commm")).toBe("google.com");
    expect(detectTldTypo("test.conn")).toBe("test.com");
    expect(detectTldTypo("site.nett")).toBe("site.net");
    expect(detectTldTypo("example.orgg")).toBe("example.org");
    expect(detectTldTypo("app.ioo")).toBe("app.io");
    expect(detectTldTypo("tool.deev")).toBe("tool.dev");
    expect(detectTldTypo("my.appp")).toBe("my.app");
  });

  test("returns null for valid TLDs", () => {
    expect(detectTldTypo("google.com")).toBeNull();
    expect(detectTldTypo("test.io")).toBeNull();
    expect(detectTldTypo("site.dev")).toBeNull();
    expect(detectTldTypo("example.org")).toBeNull();
    expect(detectTldTypo("app.xyz")).toBeNull();
  });

  test("suggests close matches via edit distance", () => {
    expect(detectTldTypo("test.cim")).toBe("test.com");
    expect(detectTldTypo("test.vom")).toBe("test.com");
  });

  test("returns null for strings without dots", () => {
    expect(detectTldTypo("localhost")).toBeNull();
    expect(detectTldTypo("nodots")).toBeNull();
  });

  test("handles subdomains correctly", () => {
    expect(detectTldTypo("sub.domain.commm")).toBe("sub.domain.com");
    expect(detectTldTypo("a.b.c.nett")).toBe("a.b.c.net");
  });
});
