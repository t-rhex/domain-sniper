import { assertValidDomain } from "../validate.js";

export interface SecurityHeadersResult {
  domain: string;
  grade: "A+" | "A" | "B" | "C" | "D" | "F";
  score: number;
  headers: HeaderCheck[];
  missing: string[];
  error: string | null;
}

export interface HeaderCheck {
  name: string;
  present: boolean;
  value: string | null;
  status: "good" | "warn" | "bad" | "missing";
  detail: string;
}

const HEADER_CHECKS: {
  name: string;
  header: string;
  weight: number;
  check: (value: string | null) => { status: "good" | "warn" | "bad" | "missing"; detail: string };
}[] = [
  {
    name: "Strict-Transport-Security",
    header: "strict-transport-security",
    weight: 20,
    check: (v) => {
      if (!v) return { status: "missing", detail: "HSTS not set — allows protocol downgrade attacks" };
      if (v.includes("max-age=0")) return { status: "bad", detail: "HSTS max-age=0 effectively disables it" };
      const maxAge = parseInt(v.match(/max-age=(\d+)/)?.[1] || "0", 10);
      if (maxAge < 31536000) return { status: "warn", detail: `HSTS max-age=${maxAge} (recommended: 31536000+)` };
      if (v.includes("includeSubDomains") && v.includes("preload")) return { status: "good", detail: "HSTS with preload and includeSubDomains" };
      return { status: "good", detail: `HSTS max-age=${maxAge}` };
    },
  },
  {
    name: "Content-Security-Policy",
    header: "content-security-policy",
    weight: 20,
    check: (v) => {
      if (!v) return { status: "missing", detail: "No CSP — vulnerable to XSS and injection" };
      if (v.includes("unsafe-inline") && v.includes("unsafe-eval")) return { status: "warn", detail: "CSP allows unsafe-inline and unsafe-eval" };
      if (v.includes("unsafe-inline")) return { status: "warn", detail: "CSP allows unsafe-inline" };
      return { status: "good", detail: "CSP configured" };
    },
  },
  {
    name: "X-Frame-Options",
    header: "x-frame-options",
    weight: 15,
    check: (v) => {
      if (!v) return { status: "missing", detail: "No X-Frame-Options — clickjacking possible" };
      if (v.toUpperCase() === "DENY" || v.toUpperCase() === "SAMEORIGIN") return { status: "good", detail: `X-Frame-Options: ${v}` };
      return { status: "warn", detail: `X-Frame-Options: ${v} (unusual value)` };
    },
  },
  {
    name: "X-Content-Type-Options",
    header: "x-content-type-options",
    weight: 10,
    check: (v) => {
      if (!v) return { status: "missing", detail: "No X-Content-Type-Options — MIME sniffing possible" };
      return { status: "good", detail: "nosniff enabled" };
    },
  },
  {
    name: "Referrer-Policy",
    header: "referrer-policy",
    weight: 10,
    check: (v) => {
      if (!v) return { status: "missing", detail: "No Referrer-Policy — may leak URLs to third parties" };
      if (v === "unsafe-url") return { status: "bad", detail: "Referrer-Policy: unsafe-url leaks full URLs" };
      return { status: "good", detail: `Referrer-Policy: ${v}` };
    },
  },
  {
    name: "Permissions-Policy",
    header: "permissions-policy",
    weight: 10,
    check: (v) => {
      if (!v) return { status: "missing", detail: "No Permissions-Policy — browser features unrestricted" };
      return { status: "good", detail: "Permissions-Policy configured" };
    },
  },
  {
    name: "X-XSS-Protection",
    header: "x-xss-protection",
    weight: 5,
    check: (v) => {
      if (!v) return { status: "warn", detail: "No X-XSS-Protection (deprecated but still useful)" };
      if (v.startsWith("0")) return { status: "warn", detail: "XSS Protection explicitly disabled" };
      return { status: "good", detail: `X-XSS-Protection: ${v}` };
    },
  },
  {
    name: "Server Header",
    header: "server",
    weight: 5,
    check: (v) => {
      if (!v) return { status: "good", detail: "Server header hidden (good practice)" };
      if (/\d+\.\d+/.test(v)) return { status: "warn", detail: `Server: ${v} (version exposed)` };
      return { status: "good", detail: `Server: ${v}` };
    },
  },
  {
    name: "X-Powered-By",
    header: "x-powered-by",
    weight: 5,
    check: (v) => {
      if (!v) return { status: "good", detail: "X-Powered-By hidden (good practice)" };
      return { status: "warn", detail: `X-Powered-By: ${v} (leaks technology info)` };
    },
  },
];

export async function auditSecurityHeaders(domain: string): Promise<SecurityHeadersResult> {
  assertValidDomain(domain);

  const result: SecurityHeadersResult = {
    domain, grade: "F", score: 0, headers: [], missing: [], error: null,
  };

  try {
    const resp = await fetch(`https://${domain}`, {
      signal: AbortSignal.timeout(10000),
      headers: { "User-Agent": "DomainSniper/2.0" },
    });

    let totalWeight = 0;
    let earnedWeight = 0;

    for (const hc of HEADER_CHECKS) {
      const value = resp.headers.get(hc.header);
      const { status, detail } = hc.check(value);
      totalWeight += hc.weight;

      if (status === "good") earnedWeight += hc.weight;
      else if (status === "warn") earnedWeight += hc.weight * 0.5;
      // bad and missing = 0 points

      result.headers.push({ name: hc.name, present: !!value, value, status, detail });
      if (status === "missing") result.missing.push(hc.name);
    }

    result.score = Math.round((earnedWeight / totalWeight) * 100);

    if (result.score >= 95) result.grade = "A+";
    else if (result.score >= 80) result.grade = "A";
    else if (result.score >= 65) result.grade = "B";
    else if (result.score >= 45) result.grade = "C";
    else if (result.score >= 25) result.grade = "D";
    else result.grade = "F";

    return result;
  } catch (err: unknown) {
    result.error = err instanceof Error ? err.message : "Security headers check failed";
    return result;
  }
}
