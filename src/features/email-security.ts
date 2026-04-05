import { execFile } from "child_process";
import { promisify } from "util";
import { assertValidDomain } from "../validate.js";

const execFileAsync = promisify(execFile);

export interface EmailSecurityResult {
  domain: string;
  spf: { found: boolean; record: string | null; issues: string[] };
  dkim: { found: boolean; record: string | null; selector: string | null };
  dmarc: { found: boolean; record: string | null; policy: string | null; issues: string[] };
  grade: "A" | "B" | "C" | "D" | "F";
  issues: string[];
}

async function digTxt(query: string): Promise<string[]> {
  try {
    const { stdout } = await execFileAsync("dig", ["+short", query, "TXT"], { timeout: 8000 });
    return stdout.trim().split("\n").filter(Boolean).map((l) => l.replace(/^"|"$/g, "").replace(/"\s*"/g, ""));
  } catch {
    return [];
  }
}

export async function checkEmailSecurity(domain: string): Promise<EmailSecurityResult> {
  assertValidDomain(domain);

  const result: EmailSecurityResult = {
    domain,
    spf: { found: false, record: null, issues: [] },
    dkim: { found: false, record: null, selector: null },
    dmarc: { found: false, record: null, policy: null, issues: [] },
    grade: "F",
    issues: [],
  };

  // SPF check
  const txtRecords = await digTxt(domain);
  const spfRecord = txtRecords.find((r) => r.startsWith("v=spf1"));
  if (spfRecord) {
    result.spf.found = true;
    result.spf.record = spfRecord;
    if (spfRecord.includes("+all")) {
      result.spf.issues.push("SPF uses +all (allows anyone to send)");
      result.issues.push("SPF +all: anyone can spoof emails from this domain");
    }
    if (spfRecord.includes("?all")) {
      result.spf.issues.push("SPF uses ?all (neutral — no enforcement)");
    }
    if (!spfRecord.includes("-all") && !spfRecord.includes("~all")) {
      result.spf.issues.push("SPF missing strict -all or ~all");
    }
    // Check for too many lookups (max 10)
    const lookups = (spfRecord.match(/include:|redirect=|a:|mx:|ptr:/g) || []).length;
    if (lookups > 10) {
      result.spf.issues.push(`SPF has ${lookups} lookups (max 10 allowed)`);
    }
  } else {
    result.issues.push("No SPF record found");
  }

  // DMARC check
  const dmarcRecords = await digTxt(`_dmarc.${domain}`);
  const dmarcRecord = dmarcRecords.find((r) => r.startsWith("v=DMARC1"));
  if (dmarcRecord) {
    result.dmarc.found = true;
    result.dmarc.record = dmarcRecord;
    const policyMatch = dmarcRecord.match(/;\s*p\s*=\s*(\w+)/);
    result.dmarc.policy = policyMatch ? policyMatch[1]! : null;
    if (result.dmarc.policy === "none") {
      result.dmarc.issues.push("DMARC policy is 'none' (monitoring only, no enforcement)");
      result.issues.push("DMARC p=none: emails failing checks are still delivered");
    }
    if (!dmarcRecord.includes("rua=")) {
      result.dmarc.issues.push("No aggregate reporting URI (rua) configured");
    }
  } else {
    result.issues.push("No DMARC record found");
  }

  // DKIM check — try common selectors
  const selectors = ["default", "google", "selector1", "selector2", "k1", "s1", "s2", "dkim", "mail"];
  for (const selector of selectors) {
    const dkimRecords = await digTxt(`${selector}._domainkey.${domain}`);
    const dkimRecord = dkimRecords.find((r) => r.includes("v=DKIM1") || r.includes("p="));
    if (dkimRecord) {
      result.dkim.found = true;
      result.dkim.record = dkimRecord;
      result.dkim.selector = selector;
      break;
    }
  }
  if (!result.dkim.found) {
    result.issues.push("No DKIM record found (checked common selectors)");
  }

  // Grade calculation
  let score = 0;
  if (result.spf.found && result.spf.issues.length === 0) score += 3;
  else if (result.spf.found) score += 1;
  if (result.dmarc.found && result.dmarc.policy !== "none") score += 4;
  else if (result.dmarc.found) score += 1;
  if (result.dkim.found) score += 3;

  if (score >= 9) result.grade = "A";
  else if (score >= 7) result.grade = "B";
  else if (score >= 4) result.grade = "C";
  else if (score >= 2) result.grade = "D";
  else result.grade = "F";

  return result;
}
