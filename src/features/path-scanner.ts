import { assertValidDomain } from "../validate.js";

export interface PathScanResult {
  domain: string;
  findings: PathFinding[];
  scannedPaths: number;
  error: string | null;
}

export interface PathFinding {
  path: string;
  status: number;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  size: number | null;
}

const SENSITIVE_PATHS: { path: string; severity: "critical" | "high" | "medium" | "low" | "info"; description: string }[] = [
  // Critical — secrets and credentials
  { path: "/.env", severity: "critical", description: "Environment file — may contain API keys and passwords" },
  { path: "/.env.local", severity: "critical", description: "Local environment file" },
  { path: "/.env.production", severity: "critical", description: "Production environment file" },
  { path: "/.git/config", severity: "critical", description: "Git config exposed — repo may be cloneable" },
  { path: "/.git/HEAD", severity: "critical", description: "Git HEAD exposed — confirms .git directory" },
  { path: "/wp-config.php.bak", severity: "critical", description: "WordPress config backup with DB credentials" },
  { path: "/.aws/credentials", severity: "critical", description: "AWS credentials file" },
  { path: "/config.json", severity: "high", description: "Configuration file possibly containing secrets" },
  { path: "/config.yaml", severity: "high", description: "YAML configuration file" },
  // High — admin and debug
  { path: "/wp-admin/", severity: "high", description: "WordPress admin panel" },
  { path: "/admin/", severity: "high", description: "Admin panel" },
  { path: "/phpinfo.php", severity: "high", description: "PHP info page — exposes server configuration" },
  { path: "/server-status", severity: "high", description: "Apache server status page" },
  { path: "/server-info", severity: "high", description: "Apache server info page" },
  { path: "/.htpasswd", severity: "high", description: "htpasswd file with hashed credentials" },
  { path: "/debug/", severity: "high", description: "Debug endpoint" },
  { path: "/_debug/", severity: "high", description: "Debug endpoint" },
  { path: "/actuator", severity: "high", description: "Spring Boot actuator endpoints" },
  { path: "/actuator/health", severity: "medium", description: "Spring Boot health endpoint" },
  { path: "/actuator/env", severity: "critical", description: "Spring Boot environment — may expose secrets" },
  // Medium — information disclosure
  { path: "/robots.txt", severity: "info", description: "Robots.txt — may reveal hidden paths" },
  { path: "/sitemap.xml", severity: "info", description: "Sitemap — shows site structure" },
  { path: "/.DS_Store", severity: "medium", description: "macOS directory metadata — leaks filenames" },
  { path: "/crossdomain.xml", severity: "medium", description: "Flash crossdomain policy" },
  { path: "/security.txt", severity: "info", description: "Security contact information" },
  { path: "/.well-known/security.txt", severity: "info", description: "Security contact (standard location)" },
  { path: "/package.json", severity: "medium", description: "Node.js package manifest — shows dependencies" },
  { path: "/composer.json", severity: "medium", description: "PHP Composer manifest" },
  { path: "/Gemfile", severity: "medium", description: "Ruby Gemfile" },
  { path: "/wp-json/", severity: "low", description: "WordPress REST API" },
  { path: "/api/", severity: "info", description: "API endpoint" },
  { path: "/graphql", severity: "medium", description: "GraphQL endpoint — may allow introspection" },
  { path: "/swagger.json", severity: "medium", description: "Swagger/OpenAPI spec" },
  { path: "/api-docs", severity: "medium", description: "API documentation endpoint" },
  { path: "/.well-known/openid-configuration", severity: "info", description: "OpenID Connect configuration" },
  { path: "/backup.sql", severity: "critical", description: "SQL database backup" },
  { path: "/dump.sql", severity: "critical", description: "SQL database dump" },
  { path: "/db.sql", severity: "critical", description: "SQL database file" },
];

export async function scanPaths(
  domain: string,
  paths: typeof SENSITIVE_PATHS = SENSITIVE_PATHS,
  concurrency: number = 5
): Promise<PathScanResult> {
  assertValidDomain(domain);

  const result: PathScanResult = {
    domain, findings: [], scannedPaths: 0, error: null,
  };

  try {
    for (let i = 0; i < paths.length; i += concurrency) {
      const batch = paths.slice(i, i + concurrency);
      const batchResults = await Promise.all(
        batch.map(async (p) => {
          result.scannedPaths++;
          try {
            const resp = await fetch(`https://${domain}${p.path}`, {
              method: "HEAD",
              redirect: "manual",
              signal: AbortSignal.timeout(5000),
              headers: { "User-Agent": "DomainSniper/2.0" },
            });

            // 200 = found, 403 = exists but forbidden (still interesting)
            if (resp.status === 200 || resp.status === 403) {
              const size = resp.headers.get("content-length");
              return {
                path: p.path,
                status: resp.status,
                severity: p.severity,
                description: resp.status === 403
                  ? `${p.description} (403 Forbidden — exists but protected)`
                  : p.description,
                size: size ? parseInt(size, 10) : null,
              };
            }
            return null;
          } catch {
            return null;
          }
        })
      );

      for (const r of batchResults) {
        if (r) result.findings.push(r);
      }
    }

    // Sort by severity
    const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    result.findings.sort((a, b) => (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5));

    return result;
  } catch (err: unknown) {
    result.error = err instanceof Error ? err.message : "Path scan failed";
    return result;
  }
}

export { SENSITIVE_PATHS };
