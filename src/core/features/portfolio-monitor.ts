import {
  getPortfolioDomains,
  createAlert,
  type DbPortfolioDomain,
  type AlertSeverity,
} from "../db.js";
import { whoisLookup } from "../whois.js";
import { checkSsl } from "./ssl-check.js";
import { httpProbe } from "./http-probe.js";
import { lookupDns } from "./dns-details.js";

export interface HealthCheckResult {
  domain: string;
  whoisOk: boolean;
  dnsOk: boolean;
  httpOk: boolean;
  sslOk: boolean;
  sslDaysLeft: number | null;
  expiryDaysLeft: number | null;
  issues: string[];
  checkedAt: string;
}

export interface MonitorReport {
  checked: number;
  healthy: number;
  warnings: number;
  critical: number;
  results: HealthCheckResult[];
  alerts: Array<{ domain: string; severity: string; message: string }>;
}

function daysUntil(dateStr: string | null): number | null {
  if (!dateStr) return null;
  try {
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return null;
    return Math.floor((d.getTime() - Date.now()) / 86400000);
  } catch { return null; }
}

export async function checkDomainHealth(domain: string): Promise<HealthCheckResult> {
  const result: HealthCheckResult = {
    domain,
    whoisOk: false,
    dnsOk: false,
    httpOk: false,
    sslOk: false,
    sslDaysLeft: null,
    expiryDaysLeft: null,
    issues: [],
    checkedAt: new Date().toISOString(),
  };

  // WHOIS check
  try {
    const whois = await whoisLookup(domain);
    if (!whois.error && !whois.available) {
      result.whoisOk = true;
      result.expiryDaysLeft = daysUntil(whois.expiryDate);
    } else if (whois.available) {
      result.issues.push("Domain appears unregistered!");
    }
  } catch { result.issues.push("WHOIS check failed"); }

  // DNS check
  try {
    const dns = await lookupDns(domain);
    if (dns.a.length > 0 || dns.cname.length > 0) {
      result.dnsOk = true;
    } else {
      result.issues.push("No DNS A/CNAME records");
    }
  } catch { result.issues.push("DNS check failed"); }

  // HTTP check
  try {
    const probe = await httpProbe(domain);
    if (probe.reachable && probe.status !== null && probe.status < 500) {
      result.httpOk = true;
    } else {
      result.issues.push(probe.reachable ? `HTTP ${probe.status}` : "Site unreachable");
    }
  } catch { result.issues.push("HTTP check failed"); }

  // SSL check
  try {
    const ssl = await checkSsl(domain);
    if (ssl.valid && !ssl.error) {
      result.sslOk = true;
      result.sslDaysLeft = ssl.daysUntilExpiry;
      if (ssl.daysUntilExpiry !== null && ssl.daysUntilExpiry < 30) {
        result.issues.push(`SSL expires in ${ssl.daysUntilExpiry} days`);
      }
    } else {
      result.issues.push(ssl.error || "Invalid SSL certificate");
    }
  } catch { result.issues.push("SSL check failed"); }

  return result;
}

export async function runPortfolioHealthCheck(
  onProgress?: (domain: string, index: number, total: number) => void
): Promise<MonitorReport> {
  const domains = getPortfolioDomains();
  const report: MonitorReport = {
    checked: 0,
    healthy: 0,
    warnings: 0,
    critical: 0,
    results: [],
    alerts: [],
  };

  for (let i = 0; i < domains.length; i++) {
    const d = domains[i]!;
    onProgress?.(d.domain, i, domains.length);

    const health = await checkDomainHealth(d.domain);
    report.results.push(health);
    report.checked++;

    // Generate alerts
    // Domain expiry
    if (health.expiryDaysLeft !== null) {
      if (health.expiryDaysLeft <= 7) {
        const msg = `Domain expires in ${health.expiryDaysLeft} days!`;
        createAlert(d.domain, "expiry", "critical", msg);
        report.alerts.push({ domain: d.domain, severity: "critical", message: msg });
        report.critical++;
      } else if (health.expiryDaysLeft <= 30) {
        const msg = `Domain expires in ${health.expiryDaysLeft} days`;
        createAlert(d.domain, "expiry", "warning", msg);
        report.alerts.push({ domain: d.domain, severity: "warning", message: msg });
        report.warnings++;
      } else if (health.expiryDaysLeft <= 90) {
        const msg = `Domain expires in ${health.expiryDaysLeft} days`;
        createAlert(d.domain, "expiry", "info", msg);
        report.alerts.push({ domain: d.domain, severity: "info", message: msg });
      }
    }

    // SSL expiry
    if (health.sslDaysLeft !== null && health.sslDaysLeft <= 14) {
      const severity: AlertSeverity = health.sslDaysLeft <= 3 ? "critical" : "warning";
      const msg = `SSL certificate expires in ${health.sslDaysLeft} days`;
      createAlert(d.domain, "ssl-expiry", severity, msg);
      report.alerts.push({ domain: d.domain, severity, message: msg });
      if (severity === "critical") report.critical++; else report.warnings++;
    }

    // Site down
    if (!health.httpOk) {
      const msg = "Site is unreachable or returning errors";
      createAlert(d.domain, "downtime", "warning", msg);
      report.alerts.push({ domain: d.domain, severity: "warning", message: msg });
      report.warnings++;
    }

    // DNS missing
    if (!health.dnsOk) {
      const msg = "No DNS records found";
      createAlert(d.domain, "dns", "warning", msg);
      report.alerts.push({ domain: d.domain, severity: "warning", message: msg });
      report.warnings++;
    }

    if (health.issues.length === 0) report.healthy++;

    // Rate limit
    await new Promise((r) => setTimeout(r, 1000));
  }

  return report;
}

export function generateRenewalCalendar(monthsAhead: number = 12): Array<{
  domain: string;
  expiryDate: string;
  daysLeft: number;
  renewalPrice: number;
  autoRenew: boolean;
}> {
  const domains = getPortfolioDomains();
  const calendar: Array<{
    domain: string; expiryDate: string; daysLeft: number; renewalPrice: number; autoRenew: boolean;
  }> = [];

  const cutoff = Date.now() + monthsAhead * 30 * 86400000;

  for (const d of domains) {
    if (!d.expiry_date) continue;
    const expiry = new Date(d.expiry_date).getTime();
    if (isNaN(expiry)) continue;
    const daysLeft = Math.floor((expiry - Date.now()) / 86400000);
    if (daysLeft >= 0 && expiry <= cutoff) {
      calendar.push({
        domain: d.domain,
        expiryDate: d.expiry_date,
        daysLeft,
        renewalPrice: d.renewal_price,
        autoRenew: !!d.auto_renew,
      });
    }
  }

  return calendar.sort((a, b) => a.daysLeft - b.daysLeft);
}

export function estimateAnnualRenewalCost(): number {
  const domains = getPortfolioDomains();
  return domains.reduce((sum, d) => sum + (d.renewal_price || 0), 0);
}
