import { assertValidDomain } from "../validate.js";

export interface TechStackResult {
  server: string | null;
  poweredBy: string | null;
  cms: string | null;
  framework: string | null;
  analytics: string[];
  cdn: string | null;
  ssl: string | null;
  technologies: TechDetection[];
  error: string | null;
}

export interface TechDetection {
  name: string;
  category: string;
  confidence: "high" | "medium" | "low";
}

// Detection patterns for HTML content
const HTML_PATTERNS: { name: string; category: string; pattern: RegExp }[] = [
  // CMS
  { name: "WordPress", category: "CMS", pattern: /wp-content|wp-includes|wordpress/i },
  { name: "Drupal", category: "CMS", pattern: /drupal|sites\/default\/files/i },
  { name: "Joomla", category: "CMS", pattern: /joomla|\/media\/system\/js/i },
  { name: "Shopify", category: "CMS", pattern: /shopify|cdn\.shopify\.com/i },
  { name: "Squarespace", category: "CMS", pattern: /squarespace|sqsp/i },
  { name: "Wix", category: "CMS", pattern: /wix\.com|wixstatic\.com/i },
  { name: "Webflow", category: "CMS", pattern: /webflow/i },
  { name: "Ghost", category: "CMS", pattern: /ghost\.io|ghost-api/i },
  { name: "Hugo", category: "CMS", pattern: /hugo-/i },
  // Frameworks
  { name: "React", category: "Framework", pattern: /react|__next|_next\/static/i },
  { name: "Next.js", category: "Framework", pattern: /_next\/|__NEXT_DATA__/i },
  { name: "Vue.js", category: "Framework", pattern: /vue\.js|__vue|nuxt/i },
  { name: "Nuxt", category: "Framework", pattern: /__nuxt|nuxt\.js/i },
  { name: "Angular", category: "Framework", pattern: /ng-version|angular/i },
  { name: "Svelte", category: "Framework", pattern: /svelte/i },
  { name: "Remix", category: "Framework", pattern: /remix/i },
  { name: "Astro", category: "Framework", pattern: /astro/i },
  { name: "Laravel", category: "Framework", pattern: /laravel/i },
  { name: "Ruby on Rails", category: "Framework", pattern: /csrf-token.*authenticity|ruby/i },
  { name: "Django", category: "Framework", pattern: /csrfmiddlewaretoken|django/i },
  // Analytics
  { name: "Google Analytics", category: "Analytics", pattern: /google-analytics|gtag|googletagmanager/i },
  { name: "Plausible", category: "Analytics", pattern: /plausible\.io/i },
  { name: "Fathom", category: "Analytics", pattern: /usefathom\.com/i },
  { name: "Hotjar", category: "Analytics", pattern: /hotjar/i },
  { name: "Segment", category: "Analytics", pattern: /segment\.com|analytics\.js/i },
  { name: "Mixpanel", category: "Analytics", pattern: /mixpanel/i },
  // Hosting/CDN
  { name: "Vercel", category: "Hosting", pattern: /vercel/i },
  { name: "Netlify", category: "Hosting", pattern: /netlify/i },
  { name: "AWS", category: "Hosting", pattern: /amazonaws\.com/i },
  { name: "Google Cloud", category: "Hosting", pattern: /googleapis\.com|gstatic\.com/i },
  // Other
  { name: "jQuery", category: "Library", pattern: /jquery/i },
  { name: "Bootstrap", category: "Library", pattern: /bootstrap/i },
  { name: "Tailwind CSS", category: "Library", pattern: /tailwindcss|tailwind/i },
  { name: "Stripe", category: "Payment", pattern: /stripe\.com|stripe\.js/i },
  { name: "Intercom", category: "Support", pattern: /intercom/i },
  { name: "Crisp", category: "Support", pattern: /crisp\.chat/i },
  { name: "Cloudflare", category: "CDN", pattern: /cloudflare/i },
];

// Header-based detection
const HEADER_PATTERNS: { header: string; name: string; category: string; pattern?: RegExp }[] = [
  { header: "x-powered-by", name: "Express", category: "Framework", pattern: /express/i },
  { header: "x-powered-by", name: "PHP", category: "Language", pattern: /php/i },
  { header: "x-powered-by", name: "ASP.NET", category: "Framework", pattern: /asp\.net/i },
  { header: "x-powered-by", name: "Next.js", category: "Framework", pattern: /next/i },
  { header: "server", name: "nginx", category: "Server", pattern: /nginx/i },
  { header: "server", name: "Apache", category: "Server", pattern: /apache/i },
  { header: "server", name: "Cloudflare", category: "CDN", pattern: /cloudflare/i },
  { header: "server", name: "LiteSpeed", category: "Server", pattern: /litespeed/i },
  { header: "server", name: "Caddy", category: "Server", pattern: /caddy/i },
  { header: "x-vercel-id", name: "Vercel", category: "Hosting" },
  { header: "x-nf-request-id", name: "Netlify", category: "Hosting" },
  { header: "fly-request-id", name: "Fly.io", category: "Hosting" },
  { header: "cf-ray", name: "Cloudflare", category: "CDN" },
  { header: "x-cache", name: "CDN Cache", category: "CDN" },
];

export async function detectTechStack(domain: string): Promise<TechStackResult> {
  assertValidDomain(domain);

  const result: TechStackResult = {
    server: null, poweredBy: null, cms: null, framework: null,
    analytics: [], cdn: null, ssl: null, technologies: [], error: null,
  };

  try {
    const resp = await fetch(`https://${domain}`, {
      signal: AbortSignal.timeout(10000),
      headers: { "User-Agent": "DomainSniper/2.0" },
    });

    // Extract from headers
    result.server = resp.headers.get("server");
    result.poweredBy = resp.headers.get("x-powered-by");

    for (const hp of HEADER_PATTERNS) {
      const val = resp.headers.get(hp.header);
      if (val && (!hp.pattern || hp.pattern.test(val))) {
        const exists = result.technologies.some((t) => t.name === hp.name);
        if (!exists) {
          result.technologies.push({ name: hp.name, category: hp.category, confidence: "high" });
        }
        if (hp.category === "CDN" && !result.cdn) result.cdn = hp.name;
      }
    }

    // Parse HTML body for patterns
    const body = await resp.text();
    const seen = new Set<string>();

    for (const pat of HTML_PATTERNS) {
      if (pat.pattern.test(body) && !seen.has(pat.name)) {
        seen.add(pat.name);
        result.technologies.push({ name: pat.name, category: pat.category, confidence: "medium" });

        if (pat.category === "CMS" && !result.cms) result.cms = pat.name;
        if (pat.category === "Framework" && !result.framework) result.framework = pat.name;
        if (pat.category === "Analytics") result.analytics.push(pat.name);
        if (pat.category === "CDN" && !result.cdn) result.cdn = pat.name;
      }
    }

    return result;
  } catch (err: unknown) {
    result.error = err instanceof Error ? err.message : "Tech detection failed";
    return result;
  }
}
