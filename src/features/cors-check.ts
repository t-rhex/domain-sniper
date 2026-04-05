import { assertValidDomain } from "../validate.js";

export interface CorsResult {
  domain: string;
  vulnerable: boolean;
  findings: CorsFinding[];
  error: string | null;
}

export interface CorsFinding {
  test: string;
  origin: string;
  allowed: boolean;
  credentials: boolean;
  severity: "critical" | "high" | "medium" | "low" | "info";
  detail: string;
}

const CORS_TESTS: { name: string; origin: string; severity: "critical" | "high" | "medium" }[] = [
  { name: "Wildcard origin", origin: "https://evil.com", severity: "critical" },
  { name: "Null origin", origin: "null", severity: "high" },
  { name: "Subdomain reflection", origin: "https://evil.TARGET", severity: "high" },
  { name: "Prefix match bypass", origin: "https://TARGETevil.com", severity: "medium" },
  { name: "Suffix match bypass", origin: "https://evil-TARGET", severity: "medium" },
  { name: "HTTP downgrade", origin: "http://TARGET", severity: "medium" },
];

export async function checkCors(domain: string): Promise<CorsResult> {
  assertValidDomain(domain);

  const result: CorsResult = {
    domain, vulnerable: false, findings: [], error: null,
  };

  try {
    for (const test of CORS_TESTS) {
      const origin = test.origin
        .replace(/TARGET/g, domain);

      try {
        const resp = await fetch(`https://${domain}`, {
          signal: AbortSignal.timeout(8000),
          headers: {
            "Origin": origin,
            "User-Agent": "DomainSniper/2.0",
          },
        });

        const acao = resp.headers.get("access-control-allow-origin");
        const acac = resp.headers.get("access-control-allow-credentials");
        const allowed = acao === origin || acao === "*";
        const credentials = acac === "true";

        if (allowed) {
          const finding: CorsFinding = {
            test: test.name,
            origin,
            allowed: true,
            credentials,
            severity: credentials ? "critical" : test.severity,
            detail: credentials
              ? `Reflects origin ${origin} WITH credentials — full account takeover possible`
              : `Reflects origin ${origin} (no credentials)`,
          };

          result.findings.push(finding);
          if (credentials || test.severity === "critical") {
            result.vulnerable = true;
          }
        } else if (acao === "*") {
          result.findings.push({
            test: test.name,
            origin,
            allowed: true,
            credentials: false,
            severity: "medium",
            detail: "Wildcard ACAO (*) — allows any origin to read responses",
          });
        }
      } catch {
        // Connection error — skip this test
      }
    }

    return result;
  } catch (err: unknown) {
    result.error = err instanceof Error ? err.message : "CORS check failed";
    return result;
  }
}
