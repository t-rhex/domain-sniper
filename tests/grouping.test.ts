import { test, expect, describe } from "bun:test";
import { extractBaseName, groupDomains, shouldShowGroups } from "../src/core/features/grouping.js";

describe("extractBaseName", () => {
  test("strips TLD", () => {
    expect(extractBaseName("coolstartup.com")).toBe("coolstartup");
    expect(extractBaseName("coolstartup.io")).toBe("coolstartup");
  });

  test("strips common prefixes", () => {
    expect(extractBaseName("getcoolstartup.com")).toBe("coolstartup");
    expect(extractBaseName("mycoolstartup.io")).toBe("coolstartup");
    expect(extractBaseName("trycoolstartup.dev")).toBe("coolstartup");
  });

  test("strips common suffixes", () => {
    expect(extractBaseName("coolstartupapp.com")).toBe("coolstartup");
    expect(extractBaseName("coolstartuphq.io")).toBe("coolstartup");
    expect(extractBaseName("coolstartupkit.dev")).toBe("coolstartup");
  });

  test("strips hyphens", () => {
    expect(extractBaseName("cool-startup.com")).toBe("coolstartup");
  });

  test("doesn't strip if result too short", () => {
    expect(extractBaseName("getapp.com")).toBe("getapp");
    expect(extractBaseName("myai.io")).toBe("myai");
  });
});

describe("groupDomains", () => {
  test("groups related domains", () => {
    const domains = [
      { domain: "coolstartup.com", status: "taken" },
      { domain: "coolstartup.io", status: "available" },
      { domain: "getcoolstartup.com", status: "taken" },
      { domain: "random.net", status: "taken" },
    ];
    const groups = groupDomains(domains);
    const coolGroup = groups.find((g) => g.baseName === "coolstartup");
    expect(coolGroup).toBeTruthy();
    expect(coolGroup!.total).toBe(3);
    expect(coolGroup!.available).toBe(1);
  });

  test("puts multi-domain groups first", () => {
    const domains = [
      { domain: "a.com", status: "taken" },
      { domain: "test.com", status: "taken" },
      { domain: "test.io", status: "available" },
      { domain: "test.dev", status: "taken" },
    ];
    const groups = groupDomains(domains);
    expect(groups[0]!.baseName).toBe("test");
  });
});

describe("shouldShowGroups", () => {
  test("returns false for too few domains", () => {
    expect(shouldShowGroups([
      { domain: "a.com", status: "taken" },
      { domain: "b.com", status: "taken" },
    ])).toBe(false);
  });

  test("returns true when groupable", () => {
    expect(shouldShowGroups([
      { domain: "test.com", status: "taken" },
      { domain: "test.io", status: "taken" },
      { domain: "test.dev", status: "taken" },
      { domain: "other.com", status: "taken" },
    ])).toBe(true);
  });
});
