import { test, expect, describe } from "bun:test";
import { statusStyle, theme, palette } from "../src/theme.js";
import type { DomainStatus } from "../src/theme.js";

describe("statusStyle", () => {
  const allStatuses: DomainStatus[] = ["pending", "checking", "available", "expired", "taken", "error", "registered", "registering"];

  test("returns icon, fg, and label for all statuses", () => {
    for (const status of allStatuses) {
      const result = statusStyle(status);
      expect(result.icon).toBeTruthy();
      expect(result.fg).toBeTruthy();
      expect(result.label).toBeTruthy();
    }
  });

  test("available is green", () => {
    expect(statusStyle("available").fg).toBe(theme.primary);
  });

  test("taken is red", () => {
    expect(statusStyle("taken").fg).toBe(theme.error);
  });
});

describe("theme", () => {
  test("has all semantic colors", () => {
    expect(theme.primary).toBeTruthy();
    expect(theme.error).toBeTruthy();
    expect(theme.warning).toBeTruthy();
    expect(theme.info).toBeTruthy();
    expect(theme.text).toBeTruthy();
    expect(theme.background).toBeTruthy();
  });
});
