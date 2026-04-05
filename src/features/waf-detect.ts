import { assertValidDomain } from "../validate.js";

export interface WafResult {
  domain: string;
  detected: boolean;
  waf: string | null;
  confidence: "high" | "medium" | "low";
  indicators: string[];
  error: string | null;
}

interface WafSignature {
  name: string;
  headerPatterns: { header: string; pattern: RegExp }[];
  bodyPatterns: RegExp[];
  cookiePatterns: RegExp[];
}

const WAF_SIGNATURES: WafSignature[] = [
  {
    name: "Cloudflare",
    headerPatterns: [
      { header: "server", pattern: /cloudflare/i },
      { header: "cf-ray", pattern: /.+/ },
      { header: "cf-cache-status", pattern: /.+/ },
    ],
    bodyPatterns: [/cloudflare/i, /cf-browser-verification/i],
    cookiePatterns: [/__cfduid/i, /__cf_bm/i],
  },
  {
    name: "AWS WAF / CloudFront",
    headerPatterns: [
      { header: "x-amz-cf-id", pattern: /.+/ },
      { header: "x-amz-cf-pop", pattern: /.+/ },
      { header: "x-amzn-waf", pattern: /.+/ },
    ],
    bodyPatterns: [/awswaf/i],
    cookiePatterns: [/awsalb/i, /awsalbcors/i],
  },
  {
    name: "Akamai",
    headerPatterns: [
      { header: "x-akamai-transformed", pattern: /.+/ },
      { header: "server", pattern: /akamaighost/i },
      { header: "x-akamai-session-info", pattern: /.+/ },
    ],
    bodyPatterns: [/akamai/i, /reference.*akamai/i],
    cookiePatterns: [/akamai/i, /ak_bmsc/i],
  },
  {
    name: "Sucuri",
    headerPatterns: [
      { header: "server", pattern: /sucuri/i },
      { header: "x-sucuri-id", pattern: /.+/ },
      { header: "x-sucuri-cache", pattern: /.+/ },
    ],
    bodyPatterns: [/sucuri/i, /sucuri cloudproxy/i],
    cookiePatterns: [/sucuri/i],
  },
  {
    name: "Imperva / Incapsula",
    headerPatterns: [
      { header: "x-cdn", pattern: /incapsula/i },
      { header: "x-iinfo", pattern: /.+/ },
    ],
    bodyPatterns: [/incapsula/i, /imperva/i],
    cookiePatterns: [/incap_ses/i, /visid_incap/i],
  },
  {
    name: "F5 BIG-IP",
    headerPatterns: [
      { header: "server", pattern: /big-?ip/i },
      { header: "x-cnection", pattern: /.+/ },
    ],
    bodyPatterns: [],
    cookiePatterns: [/bigipserver/i, /BIGipServer/i],
  },
  {
    name: "ModSecurity",
    headerPatterns: [
      { header: "server", pattern: /mod_security|modsecurity/i },
    ],
    bodyPatterns: [/mod_security|modsecurity|owasp/i],
    cookiePatterns: [],
  },
  {
    name: "Fastly",
    headerPatterns: [
      { header: "via", pattern: /varnish/i },
      { header: "x-fastly-request-id", pattern: /.+/ },
      { header: "x-served-by", pattern: /cache-/i },
    ],
    bodyPatterns: [/fastly error/i],
    cookiePatterns: [],
  },
  {
    name: "DDoS-Guard",
    headerPatterns: [
      { header: "server", pattern: /ddos-guard/i },
    ],
    bodyPatterns: [/ddos-guard/i],
    cookiePatterns: [/__ddg/i],
  },
  {
    name: "Wordfence",
    headerPatterns: [],
    bodyPatterns: [/wordfence/i, /wfwaf-/i],
    cookiePatterns: [/wordfence/i, /wfwaf/i],
  },
];

export async function detectWaf(domain: string): Promise<WafResult> {
  assertValidDomain(domain);

  const result: WafResult = {
    domain, detected: false, waf: null, confidence: "low", indicators: [], error: null,
  };

  try {
    const resp = await fetch(`https://${domain}`, {
      signal: AbortSignal.timeout(10000),
      headers: { "User-Agent": "DomainSniper/2.0" },
    });

    const body = await resp.text();
    const cookies = resp.headers.get("set-cookie") || "";

    for (const sig of WAF_SIGNATURES) {
      let matchCount = 0;
      const indicators: string[] = [];

      // Check headers
      for (const hp of sig.headerPatterns) {
        const val = resp.headers.get(hp.header);
        if (val && hp.pattern.test(val)) {
          matchCount++;
          indicators.push(`Header: ${hp.header}=${val.slice(0, 50)}`);
        }
      }

      // Check body
      for (const bp of sig.bodyPatterns) {
        if (bp.test(body)) {
          matchCount++;
          indicators.push(`Body pattern: ${bp.source.slice(0, 30)}`);
        }
      }

      // Check cookies
      for (const cp of sig.cookiePatterns) {
        if (cp.test(cookies)) {
          matchCount++;
          indicators.push(`Cookie pattern: ${cp.source.slice(0, 30)}`);
        }
      }

      if (matchCount > 0) {
        result.detected = true;
        result.waf = sig.name;
        result.indicators = indicators;
        result.confidence = matchCount >= 3 ? "high" : matchCount >= 2 ? "medium" : "low";
        return result; // Return first match (most likely)
      }
    }

    return result;
  } catch (err: unknown) {
    result.error = err instanceof Error ? err.message : "WAF detection failed";
    return result;
  }
}
