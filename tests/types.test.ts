import { test, expect, describe } from "bun:test";
import { createEmptyEntry } from "../src/types.js";

describe("createEmptyEntry", () => {
  test("creates entry with correct domain", () => {
    const entry = createEmptyEntry("test.com");
    expect(entry.domain).toBe("test.com");
  });

  test("initializes with pending status", () => {
    const entry = createEmptyEntry("test.com");
    expect(entry.status).toBe("pending");
  });

  test("initializes all fields as null", () => {
    const entry = createEmptyEntry("test.com");
    expect(entry.whois).toBeNull();
    expect(entry.dns).toBeNull();
    expect(entry.httpProbe).toBeNull();
    expect(entry.wayback).toBeNull();
    expect(entry.rdap).toBeNull();
    expect(entry.ssl).toBeNull();
    expect(entry.subdomains).toBeNull();
    expect(entry.marketplace).toBeNull();
    expect(entry.socialMedia).toBeNull();
    expect(entry.techStack).toBeNull();
    expect(entry.blacklist).toBeNull();
    expect(entry.backlinks).toBeNull();
    expect(entry.portScan).toBeNull();
    expect(entry.reverseIp).toBeNull();
    expect(entry.asn).toBeNull();
    expect(entry.emailSecurity).toBeNull();
    expect(entry.zoneTransfer).toBeNull();
    expect(entry.certTransparency).toBeNull();
    expect(entry.takeover).toBeNull();
    expect(entry.securityHeaders).toBeNull();
    expect(entry.waf).toBeNull();
    expect(entry.pathScan).toBeNull();
    expect(entry.cors).toBeNull();
    expect(entry.error).toBeNull();
    expect(entry.domainAge).toBeNull();
    expect(entry.tagged).toBe(false);
  });
});
