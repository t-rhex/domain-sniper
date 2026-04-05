import { test, expect, describe } from "bun:test";
import { APP_DIR, CONFIG_FILE, PORTFOLIO_FILE, SESSION_DIR, WHOIS_HISTORY_DIR } from "../src/core/paths.js";
import { homedir } from "os";

describe("shared paths", () => {
  test("APP_DIR is under home directory", () => {
    expect(APP_DIR).toContain(homedir());
    expect(APP_DIR).toContain(".domain-sniper");
  });

  test("all paths are under APP_DIR", () => {
    expect(CONFIG_FILE).toContain(APP_DIR);
    expect(PORTFOLIO_FILE).toContain(APP_DIR);
    expect(SESSION_DIR).toContain(APP_DIR);
    expect(WHOIS_HISTORY_DIR).toContain(APP_DIR);
  });
});
