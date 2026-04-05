import { execFile } from "child_process";
import { promisify } from "util";
import { assertValidDomain } from "../validate.js";

const execFileAsync = promisify(execFile);

export interface TakeoverResult {
  domain: string;
  vulnerable: boolean;
  findings: TakeoverFinding[];
  checkedSubdomains: number;
  error: string | null;
}

export interface TakeoverFinding {
  subdomain: string;
  cname: string;
  service: string;
  status: "vulnerable" | "potential" | "safe";
  detail: string;
}

// Services known to be susceptible to subdomain takeover
const TAKEOVER_SIGNATURES: { service: string; cnames: string[]; responseIndicators: string[] }[] = [
  { service: "GitHub Pages", cnames: ["github.io"], responseIndicators: ["There isn't a GitHub Pages site here"] },
  { service: "Heroku", cnames: ["herokuapp.com", "herokussl.com"], responseIndicators: ["No such app", "no-such-app"] },
  { service: "AWS S3", cnames: ["s3.amazonaws.com", "s3-website"], responseIndicators: ["NoSuchBucket", "The specified bucket does not exist"] },
  { service: "Netlify", cnames: ["netlify.app", "netlify.com"], responseIndicators: ["Not Found - Request ID"] },
  { service: "Vercel", cnames: ["vercel.app", "now.sh"], responseIndicators: ["The deployment could not be found"] },
  { service: "Surge.sh", cnames: ["surge.sh"], responseIndicators: ["project not found"] },
  { service: "Fly.io", cnames: ["fly.dev"], responseIndicators: ["404 Not Found"] },
  { service: "Shopify", cnames: ["myshopify.com"], responseIndicators: ["Sorry, this shop is currently unavailable"] },
  { service: "Tumblr", cnames: ["tumblr.com"], responseIndicators: ["There's nothing here", "Whatever you were looking for doesn't currently exist"] },
  { service: "WordPress.com", cnames: ["wordpress.com"], responseIndicators: ["Do you want to register"] },
  { service: "Ghost", cnames: ["ghost.io"], responseIndicators: ["Site not found"] },
  { service: "Fastly", cnames: ["fastly.net"], responseIndicators: ["Fastly error: unknown domain"] },
  { service: "Pantheon", cnames: ["pantheonsite.io"], responseIndicators: ["404 error unknown site"] },
  { service: "Azure", cnames: ["azurewebsites.net", "cloudapp.azure.com", "trafficmanager.net"], responseIndicators: ["404 Web Site not found"] },
  { service: "Unbounce", cnames: ["unbouncepages.com"], responseIndicators: ["The requested URL was not found"] },
  { service: "Cargo", cnames: ["cargocollective.com"], responseIndicators: ["404 Not Found"] },
];

async function getCname(subdomain: string): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync("dig", ["+short", subdomain, "CNAME"], { timeout: 5000 });
    const cname = stdout.trim().replace(/\.$/, "");
    return cname || null;
  } catch {
    return null;
  }
}

async function checkResponse(url: string): Promise<string | null> {
  try {
    const resp = await fetch(url, {
      signal: AbortSignal.timeout(6000),
      headers: { "User-Agent": "DomainSniper/2.0" },
    });
    const body = await resp.text();
    return body.slice(0, 5000);
  } catch {
    return null;
  }
}

export async function detectTakeover(
  domain: string,
  subdomains?: string[]
): Promise<TakeoverResult> {
  assertValidDomain(domain);

  const result: TakeoverResult = {
    domain,
    vulnerable: false,
    findings: [],
    checkedSubdomains: 0,
    error: null,
  };

  // Default subdomains to check
  const toCheck = subdomains || [
    domain,
    `www.${domain}`, `blog.${domain}`, `shop.${domain}`, `app.${domain}`,
    `dev.${domain}`, `staging.${domain}`, `beta.${domain}`, `docs.${domain}`,
    `api.${domain}`, `cdn.${domain}`, `mail.${domain}`, `status.${domain}`,
    `portal.${domain}`, `admin.${domain}`, `help.${domain}`, `support.${domain}`,
  ];

  try {
    for (const sub of toCheck) {
      result.checkedSubdomains++;
      const cname = await getCname(sub);
      if (!cname) continue;

      // Check if CNAME points to a known vulnerable service
      for (const sig of TAKEOVER_SIGNATURES) {
        const matchesCname = sig.cnames.some((c) => cname.toLowerCase().includes(c));
        if (!matchesCname) continue;

        // Check if the service returns a "not found" indicator
        const body = await checkResponse(`https://${sub}`);
        if (body) {
          const isVulnerable = sig.responseIndicators.some((ind) =>
            body.toLowerCase().includes(ind.toLowerCase())
          );

          if (isVulnerable) {
            result.vulnerable = true;
            result.findings.push({
              subdomain: sub,
              cname,
              service: sig.service,
              status: "vulnerable",
              detail: `CNAME points to ${sig.service} but the resource is unclaimed`,
            });
          } else {
            result.findings.push({
              subdomain: sub,
              cname,
              service: sig.service,
              status: "safe",
              detail: `CNAME points to ${sig.service} and resource exists`,
            });
          }
        } else {
          // Couldn't connect — could be vulnerable
          result.findings.push({
            subdomain: sub,
            cname,
            service: sig.service,
            status: "potential",
            detail: `CNAME points to ${sig.service} but could not verify (connection failed)`,
          });
        }
      }
    }

    return result;
  } catch (err: unknown) {
    result.error = err instanceof Error ? err.message : "Takeover detection failed";
    return result;
  }
}
