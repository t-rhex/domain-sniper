import { execFile } from "child_process";
import { promisify } from "util";
import { assertValidDomain, isValidDomain } from "./validate.js";

const execFileAsync = promisify(execFile);

export interface WhoisResult {
  domain: string;
  available: boolean;
  expired: boolean;
  expiryDate: string | null;
  registrar: string | null;
  createdDate: string | null;
  updatedDate: string | null;
  status: string[];
  nameServers: string[];
  rawText: string;
  error: string | null;
}

/**
 * Parse a WHOIS response to extract domain info
 */
function parseWhoisResponse(domain: string, raw: string): WhoisResult {
  const lines = raw.split("\n").map((l) => l.trim());

  const result: WhoisResult = {
    domain,
    available: false,
    expired: false,
    expiryDate: null,
    registrar: null,
    createdDate: null,
    updatedDate: null,
    status: [],
    nameServers: [],
    rawText: raw,
    error: null,
  };

  // Check for "not found" / available indicators
  const notFoundPatterns = [
    "no match for",
    "not found",
    "no entries found",
    "no data found",
    "domain not found",
    "no object found",
    "nothing found",
    "status: free",
    "status: available",
    "is available for registration",
  ];

  const lowerRaw = raw.toLowerCase();
  for (const pattern of notFoundPatterns) {
    if (lowerRaw.includes(pattern)) {
      result.available = true;
      return result;
    }
  }

  // Extract fields
  for (const line of lines) {
    const lower = line.toLowerCase();

    // Expiry date
    if (
      !result.expiryDate &&
      (lower.startsWith("registry expiry date:") ||
        lower.startsWith("registrar registration expiration date:") ||
        lower.startsWith("expiration date:") ||
        lower.startsWith("expires:") ||
        lower.startsWith("expiry date:") ||
        lower.startsWith("paid-till:") ||
        lower.startsWith("expire:"))
    ) {
      result.expiryDate = line.split(":").slice(1).join(":").trim();
    }

    // Registrar
    if (!result.registrar && lower.startsWith("registrar:")) {
      result.registrar = line.split(":").slice(1).join(":").trim();
    }

    // Created date — prefer "Creation Date:" (registrar-level) over "created:" (TLD-level)
    if (
      lower.startsWith("creation date:") ||
      lower.startsWith("created date:") ||
      lower.startsWith("registration date:")
    ) {
      result.createdDate = line.split(":").slice(1).join(":").trim();
    } else if (!result.createdDate && lower.startsWith("created:")) {
      result.createdDate = line.split(":").slice(1).join(":").trim();
    }

    // Updated date
    if (
      !result.updatedDate &&
      (lower.startsWith("updated date:") || lower.startsWith("last updated:"))
    ) {
      result.updatedDate = line.split(":").slice(1).join(":").trim();
    }

    // Status
    if (
      lower.startsWith("domain status:") ||
      lower.startsWith("status:")
    ) {
      const status = line.split(":").slice(1).join(":").trim();
      if (status) result.status.push(status);
    }

    // Name servers
    if (lower.startsWith("name server:") || lower.startsWith("nserver:")) {
      const ns = line.split(":").slice(1).join(":").trim();
      if (ns) result.nameServers.push(ns);
    }
  }

  // Check if domain is expired
  if (result.expiryDate) {
    try {
      const expiry = new Date(result.expiryDate);
      const now = new Date();
      if (expiry < now) {
        result.expired = true;
      }
    } catch {
      // Could not parse date
    }
  }

  // Check status for expiration indicators
  const expiredStatuses = [
    "redemptionperiod",
    "pendingdelete",
    "expired",
    "autorenewperiod",
  ];
  for (const s of result.status) {
    const lowerStatus = s.toLowerCase();
    for (const es of expiredStatuses) {
      if (lowerStatus.includes(es)) {
        result.expired = true;
        break;
      }
    }
  }

  return result;
}

/**
 * Perform a WHOIS lookup for a domain
 */
export async function whoisLookup(domain: string): Promise<WhoisResult> {
  assertValidDomain(domain);
  try {
    const { stdout, stderr } = await execFileAsync("whois", [domain], {
      timeout: 15000,
    });

    const raw = stdout || stderr || "";
    return parseWhoisResponse(domain, raw);
  } catch (err: any) {
    // whois command may return non-zero but still have useful output
    if (err.stdout) {
      return parseWhoisResponse(domain, err.stdout);
    }
    return {
      domain,
      available: false,
      expired: false,
      expiryDate: null,
      registrar: null,
      createdDate: null,
      updatedDate: null,
      status: [],
      nameServers: [],
      rawText: "",
      error: err.message || "WHOIS lookup failed",
    };
  }
}

/**
 * Verify domain availability using multiple methods to avoid false positives
 */
export async function verifyAvailability(
  domain: string
): Promise<{ available: boolean; confidence: "high" | "medium" | "low"; checks: string[] }> {
  assertValidDomain(domain);
  const checks: string[] = [];
  let availableCount = 0;
  let totalChecks = 0;

  // Check 1: WHOIS lookup
  const whois = await whoisLookup(domain);
  totalChecks++;
  if (whois.available) {
    availableCount++;
    checks.push("✓ WHOIS: Domain not found in registry");
  } else if (whois.expired) {
    availableCount += 0.5;
    checks.push("⚠ WHOIS: Domain expired (may be in grace period)");
  } else {
    checks.push("✗ WHOIS: Domain is registered");
  }

  // Check 2: DNS resolution check
  try {
    const { stdout } = await execFileAsync("dig", ["+short", domain, "A"], {
      timeout: 10000,
    });
    totalChecks++;
    if (!stdout.trim()) {
      availableCount++;
      checks.push("✓ DNS: No A records found");
    } else {
      checks.push(`✗ DNS: Resolves to ${stdout.trim().split("\n")[0]}`);
    }
  } catch {
    checks.push("⚠ DNS: Check failed");
  }

  // Check 3: NS record check
  try {
    const { stdout } = await execFileAsync("dig", ["+short", domain, "NS"], {
      timeout: 10000,
    });
    totalChecks++;
    if (!stdout.trim()) {
      availableCount++;
      checks.push("✓ NS: No nameservers found");
    } else {
      checks.push(`✗ NS: Has nameservers (${stdout.trim().split("\n")[0]})`);
    }
  } catch {
    checks.push("⚠ NS: Check failed");
  }

  const ratio = totalChecks > 0 ? availableCount / totalChecks : 0;
  let confidence: "high" | "medium" | "low" = "low";
  if (ratio >= 0.8) confidence = "high";
  else if (ratio >= 0.5) confidence = "medium";

  return {
    available: ratio >= 0.5,
    confidence,
    checks,
  };
}

/**
 * Parse a domain list from file content (one domain per line)
 */
export function parseDomainList(content: string): string[] {
  return content
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#") && !line.startsWith("//"))
    .map((line) => line.toLowerCase())
    .filter(isValidDomain);
}
