import { test, expect, describe } from "bun:test";
import { parseDomainList } from "../src/whois.js";

describe("parseDomainList", () => {
  test("parses valid domains", () => {
    const input = "example.com\ntest.io\ngood.dev";
    const result = parseDomainList(input);
    expect(result).toEqual(["example.com", "test.io", "good.dev"]);
  });

  test("strips comments", () => {
    const input = "# comment\nexample.com\n// another comment\ntest.io";
    const result = parseDomainList(input);
    expect(result).toEqual(["example.com", "test.io"]);
  });

  test("skips blank lines", () => {
    const input = "example.com\n\n\ntest.io\n";
    const result = parseDomainList(input);
    expect(result).toEqual(["example.com", "test.io"]);
  });

  test("lowercases domains", () => {
    const input = "EXAMPLE.COM\nTest.IO";
    const result = parseDomainList(input);
    expect(result).toEqual(["example.com", "test.io"]);
  });

  test("rejects invalid domains", () => {
    const input = "example.com\nnot-valid\n; rm -rf /\ntest.io";
    const result = parseDomainList(input);
    expect(result).toEqual(["example.com", "test.io"]);
  });

  test("returns empty for empty input", () => {
    expect(parseDomainList("")).toEqual([]);
    expect(parseDomainList("# only comments")).toEqual([]);
  });
});
