import { execFile } from "child_process";
import { promisify } from "util";
import { verifyListing, getListing } from "./db.js";

const execFileAsync = promisify(execFile);

export type VerificationMethod = "dns" | "http" | "meta";

export interface VerificationStatus {
  verified: boolean;
  method: VerificationMethod | null;
  token: string;
  instructions: Record<VerificationMethod, string>;
}

export function getVerificationInstructions(
  domain: string,
  token: string,
): VerificationStatus {
  return {
    verified: false,
    method: null,
    token,
    instructions: {
      dns: `Add a TXT record to ${domain}:\n  Name: @  (or ${domain})\n  Value: domain-sniper-verify=${token}\n\nThen run: domain-sniper market verify ${domain}`,
      http: `Create a file at:\n  https://${domain}/.well-known/domain-sniper-verify.txt\n\nWith contents:\n  ${token}\n\nThen run: domain-sniper market verify ${domain}`,
      meta: `Add this meta tag to your homepage (${domain}):\n  <meta name="domain-sniper-verify" content="${token}">\n\nThen run: domain-sniper market verify ${domain}`,
    },
  };
}

export async function verifyDomainOwnership(
  listingId: number,
): Promise<{
  verified: boolean;
  method: VerificationMethod | null;
  error: string | null;
}> {
  const listing = getListing(listingId);
  if (!listing)
    return { verified: false, method: null, error: "Listing not found" };
  if (listing.verified)
    return {
      verified: true,
      method: listing.verification_method as VerificationMethod,
      error: null,
    };

  const token = listing.verification_token;
  const domain = listing.domain;
  if (!token)
    return { verified: false, method: null, error: "No verification token" };

  // Method 1: DNS TXT record
  try {
    const { stdout } = await execFileAsync(
      "dig",
      ["+short", domain, "TXT"],
      { timeout: 10000 },
    );
    const records = stdout
      .trim()
      .split("\n")
      .map((r: string) => r.replace(/"/g, ""));
    for (const record of records) {
      if (record.includes(`domain-sniper-verify=${token}`)) {
        verifyListing(listingId, "dns");
        return { verified: true, method: "dns", error: null };
      }
    }
  } catch {
    // DNS check failed, try next method
  }

  // Method 2: HTTP file
  try {
    const resp = await fetch(
      `https://${domain}/.well-known/domain-sniper-verify.txt`,
      {
        signal: AbortSignal.timeout(8000),
      },
    );
    if (resp.ok) {
      const body = await resp.text();
      if (body.trim().includes(token)) {
        verifyListing(listingId, "http");
        return { verified: true, method: "http", error: null };
      }
    }
  } catch {
    // HTTP check failed, try next method
  }

  // Method 3: Meta tag
  try {
    const resp = await fetch(`https://${domain}`, {
      signal: AbortSignal.timeout(8000),
    });
    if (resp.ok) {
      const body = await resp.text();
      if (body.includes(`domain-sniper-verify`) && body.includes(token)) {
        verifyListing(listingId, "meta");
        return { verified: true, method: "meta", error: null };
      }
    }
  } catch {
    // Meta tag check failed
  }

  return {
    verified: false,
    method: null,
    error:
      "Verification failed -- token not found via DNS TXT, HTTP file, or meta tag",
  };
}
