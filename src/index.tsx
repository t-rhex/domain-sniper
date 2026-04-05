#!/usr/bin/env bun
import { createCliRenderer } from "@opentui/core";
import { createRoot } from "@opentui/react";
import { App } from "./app.js";
import { Command } from "commander";
import { lookupDns } from "./features/dns-details.js";
import { httpProbe } from "./features/http-probe.js";
import { checkWayback } from "./features/wayback.js";
import { calculateDomainAge } from "./features/domain-age.js";
import { sanitizeDomainList, safePath } from "./validate.js";
import { bashCompletions, zshCompletions, fishCompletions } from "./completions.js";
import { checkSocialMedia } from "./features/social-check.js";
import { detectTechStack } from "./features/tech-stack.js";
import { checkBlacklists } from "./features/blacklist-check.js";
import { estimateBacklinks } from "./features/backlinks.js";
import { scanPorts } from "./features/port-scanner.js";
import { reverseIpLookup } from "./features/reverse-ip.js";
import { lookupAsn } from "./features/asn-lookup.js";
import { checkEmailSecurity } from "./features/email-security.js";
import { checkZoneTransfer } from "./features/zone-transfer.js";
import { queryCertTransparency } from "./features/cert-transparency.js";
import { detectTakeover } from "./features/takeover-detect.js";
import { auditSecurityHeaders } from "./features/security-headers.js";
import { detectWaf } from "./features/waf-detect.js";
import { scanPaths } from "./features/path-scanner.js";
import { checkCors } from "./features/cors-check.js";
import { rdapLookup } from "./features/rdap.js";
import { checkSsl } from "./features/ssl-check.js";
import type { PortScanResult } from "./features/port-scanner.js";
import type { ReverseIpResult } from "./features/reverse-ip.js";
import type { AsnResult } from "./features/asn-lookup.js";
import type { EmailSecurityResult } from "./features/email-security.js";
import type { ZoneTransferResult } from "./features/zone-transfer.js";
import type { CertTransparencyResult } from "./features/cert-transparency.js";
import type { TakeoverResult } from "./features/takeover-detect.js";
import type { SecurityHeadersResult } from "./features/security-headers.js";
import type { WafResult } from "./features/waf-detect.js";
import type { PathScanResult } from "./features/path-scanner.js";
import type { CorsResult } from "./features/cors-check.js";

const program = new Command();

program
  .name("domain-sniper")
  .description("Check domain availability, detect expired domains, and auto-register them")
  .version("2.0.0")
  .argument("[domains...]", "Domain(s) to check")
  .option("-f, --file <path>", "Path to file with domains (one per line)")
  .option("-a, --auto-register", "Automatically register available domains", false)
  .option("--headless", "Run in non-interactive mode (print results to stdout)", false)
  .option("--json", "Output results as JSON", false)
  .option("-c, --concurrency <n>", "Concurrent lookups (default: 5)", "5")
  .option("--recon", "Enable full recon mode in headless scanning", false)
  .action(async (domains: string[], options: CliOptions) => {
    // Stdin pipe support: read from stdin when no TTY and no domains/file provided
    if (!process.stdin.isTTY && domains.length === 0 && !options.file) {
      const { parseDomainList } = await import("./whois.js");
      const chunks: Buffer[] = [];
      for await (const chunk of process.stdin) {
        chunks.push(chunk as Buffer);
      }
      const stdinContent = Buffer.concat(chunks).toString("utf-8");
      const stdinDomains = parseDomainList(stdinContent);
      domains.push(...stdinDomains);
    }

    if (options.headless || !process.stdout.isTTY) {
      // Non-interactive mode
      await runHeadless(domains, options);
    } else {
      // TUI mode
      const renderer = await createCliRenderer({
        exitOnCtrlC: true,
        screenMode: "alternate-screen",
      });

      createRoot(renderer).render(
        <App
          initialDomains={domains.length > 0 ? domains : undefined}
          batchFile={options.file}
          autoRegister={options.autoRegister}
        />
      );
    }
  });

// ─── Completions subcommand ──────────────────────────────

program
  .command("completions <shell>")
  .description("Generate shell completions (bash, zsh, fish)")
  .action((shell: string) => {
    switch (shell.toLowerCase()) {
      case "bash":
        process.stdout.write(bashCompletions());
        break;
      case "zsh":
        process.stdout.write(zshCompletions());
        break;
      case "fish":
        process.stdout.write(fishCompletions());
        break;
      default:
        console.error(`Unknown shell: ${shell}. Supported: bash, zsh, fish`);
        process.exit(1);
    }
  });

// ─── Suggest subcommand ──────────────────────────────────

program
  .command("suggest <keyword>")
  .description("Generate domain name suggestions from a keyword")
  .option("-t, --tld <tld>", "TLD to use", "com")
  .option("-n, --count <n>", "Number of suggestions", "20")
  .option("--check", "Check availability of suggestions", false)
  .action(async (keyword: string, opts: { tld: string; count: string; check: boolean }) => {
    const { generateSuggestions } = await import("./features/domain-suggest.js");
    const suggestions = generateSuggestions(keyword, opts.tld, parseInt(opts.count, 10));

    if (opts.check) {
      const { whoisLookup } = await import("./whois.js");
      console.log(`\nChecking ${suggestions.length} suggestions for "${keyword}"...\n`);
      for (const s of suggestions) {
        const whois = await whoisLookup(s.domain);
        const status = whois.available ? "\x1b[32mAVAILABLE\x1b[0m" : "\x1b[31mTAKEN\x1b[0m";
        console.log(`  ${status}  ${s.domain}  (${s.strategy})`);
        await new Promise((r) => setTimeout(r, 1000));
      }
    } else {
      console.log(`\nSuggestions for "${keyword}" (.${opts.tld}):\n`);
      for (const s of suggestions) {
        console.log(`  ${s.domain}  (${s.strategy})`);
      }
    }
    console.log();
  });

// ─── Portfolio subcommand ────────────────────────────────

program
  .command("portfolio")
  .description("View and manage your domain portfolio")
  .option("--add <domain>", "Add a domain to portfolio")
  .option("--remove <domain>", "Remove a domain from portfolio")
  .option("--expiring [days]", "Show domains expiring within N days")
  .option("--stats", "Show portfolio statistics")
  .option("--json", "Output as JSON")
  .action(async (opts: { add?: string; remove?: string; expiring?: string; stats?: boolean; json?: boolean }) => {
    const { loadPortfolio, addToPortfolio, removeFromPortfolio, getExpiringDomains, getPortfolioStats } = await import("./features/portfolio.js");

    if (opts.add) {
      addToPortfolio(opts.add);
      console.log(`Added ${opts.add} to portfolio`);
      return;
    }

    if (opts.remove) {
      removeFromPortfolio(opts.remove);
      console.log(`Removed ${opts.remove} from portfolio`);
      return;
    }

    if (opts.expiring !== undefined) {
      const days = parseInt(opts.expiring || "30", 10) || 30;
      const expiring = getExpiringDomains(days);
      if (opts.json) { console.log(JSON.stringify(expiring, null, 2)); return; }
      console.log(`\nDomains expiring within ${days} days:\n`);
      if (expiring.length === 0) { console.log("  None"); }
      for (const d of expiring) { console.log(`  ${d.domain}  ${d.expiryDate}  ${d.registrar}`); }
      console.log();
      return;
    }

    if (opts.stats) {
      const stats = getPortfolioStats();
      if (opts.json) { console.log(JSON.stringify(stats, null, 2)); return; }
      console.log(`\nPortfolio Stats:`);
      console.log(`  Domains: ${stats.total}`);
      console.log(`  Total spent: $${stats.totalSpent}`);
      console.log(`  Expiring (30d): ${stats.expiringIn30}`);
      console.log(`  Expiring (90d): ${stats.expiringIn90}`);
      if (Object.keys(stats.byRegistrar).length > 0) {
        console.log(`  By registrar:`);
        for (const [reg, count] of Object.entries(stats.byRegistrar)) {
          console.log(`    ${reg}: ${count}`);
        }
      }
      console.log();
      return;
    }

    // Default: list all
    const portfolio = loadPortfolio();
    if (opts.json) { console.log(JSON.stringify(portfolio, null, 2)); return; }
    console.log(`\nDomain Portfolio (${portfolio.domains.length} domains, $${portfolio.totalSpent} spent):\n`);
    if (portfolio.domains.length === 0) { console.log("  Empty. Use --add <domain> to add domains."); }
    for (const d of portfolio.domains) {
      console.log(`  ${d.domain}  ${d.registrar}  ${d.expiryDate || "no expiry"}  $${d.purchasePrice}`);
    }
    console.log();
  });

// ─── Config subcommand ───────────────────────────────────

program
  .command("config")
  .description("View or edit configuration")
  .option("--path", "Show config file path")
  .option("--show", "Show current config")
  .option("--reset", "Reset to defaults")
  .option("--set <key=value>", "Set a config value (e.g., concurrency=10)")
  .action(async (opts: { path?: boolean; show?: boolean; reset?: boolean; set?: string }) => {
    const { loadConfig, saveConfig, getConfigPath, resetConfig } = await import("./features/config.js");

    if (opts.path) { console.log(getConfigPath()); return; }
    if (opts.reset) { resetConfig(); console.log("Config reset to defaults"); return; }
    if (opts.set) {
      const [key, ...valueParts] = opts.set.split("=");
      const value = valueParts.join("=");
      if (!key || !value) { console.error("Usage: --set key=value"); process.exit(1); }
      const config = loadConfig();
      // Handle nested keys like "notifications.webhookUrl"
      const keys = key.split(".");
      let obj: Record<string, unknown> = config as unknown as Record<string, unknown>;
      for (let i = 0; i < keys.length - 1; i++) {
        const k = keys[i]!;
        if (obj[k] === undefined || typeof obj[k] !== "object" || obj[k] === null) {
          console.error(`Unknown key: ${key}`);
          process.exit(1);
        }
        obj = obj[k] as Record<string, unknown>;
      }
      const lastKey = keys[keys.length - 1]!;
      // Try to preserve type
      const numVal = Number(value);
      if (value === "true") obj[lastKey] = true;
      else if (value === "false") obj[lastKey] = false;
      else if (value === "null") obj[lastKey] = null;
      else if (!isNaN(numVal) && value !== "") obj[lastKey] = numVal;
      else obj[lastKey] = value;
      saveConfig(config);
      console.log(`Set ${key} = ${value}`);
      return;
    }
    // Default: show config
    const config = loadConfig();
    console.log(JSON.stringify(config, null, 2));
  });

// ─── Expiring subcommand ────────────────────────────────

program
  .command("expiring")
  .description("Browse expiring/dropping domains")
  .option("--tld <tld>", "Filter by TLD (e.g., com, net)")
  .option("--min-age <years>", "Minimum domain age in years")
  .option("-n, --limit <n>", "Max results", "20")
  .option("--api-key <key>", "WhoisFreaks API key")
  .option("--json", "Output as JSON")
  .action(async (opts: { tld?: string; minAge?: string; limit: string; apiKey?: string; json?: boolean }) => {
    const { getExpiringFeed } = await import("./features/expiring-feed.js");
    const results = await getExpiringFeed({
      apiKey: opts.apiKey || process.env.WHOISFREAKS_API_KEY,
      tld: opts.tld,
      minAge: opts.minAge ? parseInt(opts.minAge, 10) : undefined,
      limit: parseInt(opts.limit, 10),
    });
    if (opts.json) { console.log(JSON.stringify(results, null, 2)); return; }
    console.log(`\nExpiring Domains (${results.length} found):\n`);
    if (results.length === 0) { console.log("  No results. Provide --api-key or set WHOISFREAKS_API_KEY env var."); }
    for (const d of results) {
      console.log(`  ${d.domain}  expires: ${d.expiryDate}${d.registrar ? `  [${d.registrar}]` : ""}${d.age ? `  age: ${d.age}` : ""}`);
    }
    console.log();
  });

// ─── Drop catch subcommand ──────────────────────────────

program
  .command("dropcatch <domain>")
  .description("Monitor an expiring domain and auto-register when it drops")
  .option("--interval <seconds>", "Poll interval in seconds", "30")
  .option("--max-hours <hours>", "Maximum hours to monitor", "24")
  .action(async (domain: string, opts: { interval: string; maxHours: string }) => {
    const { createDropCatcher, formatDropCatchStatus } = await import("./features/drop-catch.js");
    const { loadConfigFromEnv } = await import("./registrar.js");
    const config = loadConfigFromEnv();
    if (!config?.apiKey) { console.error("Registrar credentials required. Set REGISTRAR_PROVIDER and REGISTRAR_API_KEY."); process.exit(1); }
    const intervalMs = parseInt(opts.interval, 10) * 1000;
    const maxAttempts = Math.ceil((parseInt(opts.maxHours, 10) * 3600000) / intervalMs);
    console.log(`\nDrop Catch: ${domain}`);
    console.log(`  Polling every ${opts.interval}s for up to ${opts.maxHours}h (${maxAttempts} attempts)\n`);
    const catcher = createDropCatcher({
      domain, registrarConfig: config, pollIntervalMs: intervalMs, maxAttempts,
      onStatus: (s) => console.log(`  ${formatDropCatchStatus(s)}`),
      onSuccess: () => { console.log(`\n  SUCCESS — ${domain} registered!\n`); process.exit(0); },
      onFailed: (_d, err) => { console.log(`\n  FAILED — ${err}\n`); process.exit(1); },
    });
    await catcher.start();
  });

// ─── Recon subcommand ──────────────────────────────────

program
  .command("recon <domain>")
  .description("Full security reconnaissance scan — ports, headers, email security, WAF, paths, CORS, certificates, and more")
  .option("--json", "Output as JSON")
  .action(async (domain: string, opts: { json?: boolean }) => {
    await checkDependencies();
    const { whoisLookup, verifyAvailability } = await import("./whois.js");

    if (!opts.json) {
      console.log(`\n\x1b[1m=== RECON: ${domain} ===\x1b[0m\n`);
    }

    const results = await Promise.allSettled([
      whoisLookup(domain),
      lookupDns(domain),
      httpProbe(domain),
      checkWayback(domain),
      rdapLookup(domain),
      checkSsl(domain),
      checkSocialMedia(domain),
      detectTechStack(domain),
      checkBlacklists(domain),
      estimateBacklinks(domain),
      scanPorts(domain),
      reverseIpLookup(domain),
      lookupAsn(domain),
      checkEmailSecurity(domain),
      checkZoneTransfer(domain),
      queryCertTransparency(domain),
      detectTakeover(domain),
      auditSecurityHeaders(domain),
      detectWaf(domain),
      scanPaths(domain),
      checkCors(domain),
    ]);

    const val = <T,>(r: PromiseSettledResult<T>): T | null =>
      r.status === "fulfilled" ? r.value : null;

    const whois = val(results[0]!);
    const dns = val(results[1]!);
    const http = val(results[2]!);
    const wayback = val(results[3]!);
    const rdap = val(results[4]!);
    const ssl = val(results[5]!);
    const social = val(results[6]!);
    const tech = val(results[7]!);
    const blacklist = val(results[8]!);
    const backlinks = val(results[9]!);
    const ports = val(results[10]!) as PortScanResult | null;
    const reverseIp = val(results[11]!) as ReverseIpResult | null;
    const asn = val(results[12]!) as AsnResult | null;
    const emailSec = val(results[13]!) as EmailSecurityResult | null;
    const zoneXfer = val(results[14]!) as ZoneTransferResult | null;
    const certs = val(results[15]!) as CertTransparencyResult | null;
    const takeover = val(results[16]!) as TakeoverResult | null;
    const secHeaders = val(results[17]!) as SecurityHeadersResult | null;
    const waf = val(results[18]!) as WafResult | null;
    const paths = val(results[19]!) as PathScanResult | null;
    const cors = val(results[20]!) as CorsResult | null;

    if (opts.json) {
      console.log(JSON.stringify({
        domain,
        timestamp: new Date().toISOString(),
        whois, dns, http, wayback, rdap, ssl, social, tech, blacklist, backlinks,
        ports, reverseIp, asn, emailSecurity: emailSec, zoneTransfer: zoneXfer,
        certTransparency: certs, takeover, securityHeaders: secHeaders, waf,
        pathScan: paths, cors,
      }, null, 2));
      return;
    }

    // --- Text output ---
    const g = "\x1b[32m", r = "\x1b[31m", y = "\x1b[33m", c = "\x1b[36m";
    const b = "\x1b[1m", d = "\x1b[2m", x = "\x1b[0m";

    // WHOIS
    if (whois) {
      console.log(`${b}WHOIS${x}`);
      if (whois.available) console.log(`  ${g}AVAILABLE${x}`);
      else if (whois.expired) console.log(`  ${y}EXPIRED${x}`);
      else console.log(`  ${r}TAKEN${x}`);
      if (whois.registrar) console.log(`  Registrar:  ${whois.registrar}`);
      if (whois.createdDate) console.log(`  Created:    ${whois.createdDate}`);
      if (whois.expiryDate) console.log(`  Expires:    ${whois.expiryDate}`);
      const age = calculateDomainAge(whois.createdDate);
      if (age) console.log(`  Age:        ${age}`);
      console.log();
    }

    // DNS
    if (dns) {
      console.log(`${b}DNS RECORDS${x}`);
      if (dns.a.length) console.log(`  A:     ${dns.a.join(", ")}`);
      if (dns.aaaa.length) console.log(`  AAAA:  ${dns.aaaa.join(", ")}`);
      if (dns.mx.length) console.log(`  MX:    ${dns.mx.join(", ")}`);
      if (dns.txt.length) console.log(`  TXT:   ${dns.txt.slice(0, 3).join(", ")}`);
      if (dns.cname.length) console.log(`  CNAME: ${dns.cname.join(", ")}`);
      console.log();
    }

    // ASN / Network
    if (asn && !asn.error) {
      console.log(`${b}NETWORK${x}`);
      if (asn.asn) console.log(`  ASN:       ${asn.asn}${asn.asnName ? ` (${asn.asnName})` : ""}`);
      if (asn.org) console.log(`  Org:       ${asn.org}`);
      if (asn.country) console.log(`  Location:  ${asn.city || ""}${asn.city && asn.country ? ", " : ""}${asn.country}`);
      if (asn.isp) console.log(`  ISP:       ${asn.isp}`);
      console.log();
    }

    // Port scan
    if (ports && ports.openPorts.length > 0) {
      console.log(`${b}${r}OPEN PORTS (${ports.openPorts.length})${x}`);
      for (const p of ports.openPorts.slice(0, 20)) {
        console.log(`  ${y}${String(p.port).padEnd(6)}${x} ${p.service.padEnd(14)} ${d}${p.banner || ""}${x}`);
      }
      if (ports.ip) console.log(`  ${d}IP: ${ports.ip} (${ports.scanTime}ms)${x}`);
      console.log();
    }

    // Reverse IP
    if (reverseIp && reverseIp.sharedDomains.length > 0) {
      console.log(`${b}SHARED HOSTING (${reverseIp.sharedDomains.length} domains on ${reverseIp.ip})${x}`);
      for (const dd of reverseIp.sharedDomains.slice(0, 10)) console.log(`  ${dd}`);
      if (reverseIp.sharedDomains.length > 10) console.log(`  ${d}+${reverseIp.sharedDomains.length - 10} more${x}`);
      console.log();
    }

    // SSL
    if (ssl && !ssl.error) {
      console.log(`${b}SSL CERTIFICATE${x}`);
      console.log(`  Valid:    ${ssl.valid ? `${g}Yes${x}` : `${r}No${x}`}`);
      if (ssl.issuer) console.log(`  Issuer:   ${ssl.issuer}`);
      if (ssl.daysUntilExpiry !== null) console.log(`  Expires:  ${ssl.daysUntilExpiry}d`);
      console.log();
    }

    // Email Security
    if (emailSec) {
      const ec = emailSec.grade <= "B" ? g : r;
      console.log(`${b}EMAIL SECURITY (${ec}${emailSec.grade}${x}${b})${x}`);
      console.log(`  SPF:   ${emailSec.spf.found ? `${g}Found${x}` : `${r}Missing${x}`}`);
      console.log(`  DKIM:  ${emailSec.dkim.found ? `${g}Found (${emailSec.dkim.selector})${x}` : `${r}Missing${x}`}`);
      console.log(`  DMARC: ${emailSec.dmarc.found ? `${g}p=${emailSec.dmarc.policy || "?"}${x}` : `${r}Missing${x}`}`);
      for (const issue of emailSec.issues.slice(0, 5)) console.log(`  ${y}! ${issue}${x}`);
      console.log();
    }

    // Security Headers
    if (secHeaders && !secHeaders.error) {
      const hc = secHeaders.grade <= "B" ? g : r;
      console.log(`${b}SECURITY HEADERS (${hc}${secHeaders.grade}${x}${b} — ${secHeaders.score}/100)${x}`);
      for (const h of secHeaders.missing.slice(0, 6)) console.log(`  ${r}x ${h}${x}`);
      for (const h of secHeaders.headers.filter((h) => h.status === "good").slice(0, 4)) console.log(`  ${g}+ ${h.name}${x}`);
      console.log();
    }

    // WAF
    if (waf) {
      console.log(`${b}WAF${x}`);
      console.log(`  ${waf.detected ? `${c}${waf.waf} (${waf.confidence})${x}` : `${d}None detected${x}`}`);
      console.log();
    }

    // Zone Transfer
    if (zoneXfer && zoneXfer.vulnerable) {
      console.log(`${b}${r}!! ZONE TRANSFER VULNERABLE${x}`);
      for (const ns of zoneXfer.vulnerableNs) console.log(`  ${r}${ns}${x}`);
      console.log();
    }

    // Cert Transparency
    if (certs && certs.subdomains.length > 0) {
      console.log(`${b}CERT TRANSPARENCY (${certs.subdomains.length} subdomains, ${certs.totalCerts} certs)${x}`);
      for (const s of certs.subdomains.slice(0, 15)) console.log(`  ${s}`);
      if (certs.subdomains.length > 15) console.log(`  ${d}+${certs.subdomains.length - 15} more${x}`);
      console.log();
    }

    // Takeover
    if (takeover && takeover.vulnerable) {
      console.log(`${b}${r}!! SUBDOMAIN TAKEOVER${x}`);
      for (const f of takeover.findings.filter((f) => f.status === "vulnerable")) {
        console.log(`  ${r}${f.subdomain} -> ${f.service}${x}`);
      }
      console.log();
    }

    // Path Scanner
    if (paths && paths.findings.length > 0) {
      console.log(`${b}${r}EXPOSED PATHS (${paths.findings.length})${x}`);
      for (const f of paths.findings.slice(0, 15)) {
        const fc = f.severity === "critical" ? r : f.severity === "high" ? y : d;
        console.log(`  ${fc}${f.severity === "critical" ? "!!" : f.severity === "high" ? "! " : "  "} ${f.path} [${f.status}]${x}`);
      }
      console.log();
    }

    // CORS
    if (cors && cors.vulnerable) {
      console.log(`${b}${r}!! CORS MISCONFIGURATION${x}`);
      for (const f of cors.findings.filter((f) => f.allowed).slice(0, 5)) {
        console.log(`  ${r}${f.detail}${x}`);
      }
      console.log();
    }

    // Tech Stack
    if (tech && tech.technologies.length > 0) {
      console.log(`${b}TECH STACK${x}`);
      if (tech.cms) console.log(`  CMS:        ${tech.cms}`);
      if (tech.framework) console.log(`  Framework:  ${tech.framework}`);
      if (tech.cdn) console.log(`  CDN:        ${tech.cdn}`);
      console.log();
    }

    // Blacklist
    if (blacklist) {
      if (blacklist.listed) {
        const names = blacklist.lists.filter((l) => l.listed).map((l) => l.name).join(", ");
        console.log(`${b}${r}BLACKLISTED: ${names}${x}`);
      } else {
        console.log(`${b}REPUTATION${x}: ${g}clean (${blacklist.cleanCount}/${blacklist.lists.length})${x}`);
      }
      console.log();
    }

    // Backlinks
    if (backlinks) {
      const parts: string[] = [];
      if (backlinks.pageRank !== null) parts.push(`PageRank: ${backlinks.pageRank}`);
      if (backlinks.commonCrawlPages !== null) parts.push(`CC pages: ~${backlinks.commonCrawlPages}`);
      if (parts.length > 0) console.log(`${b}AUTHORITY${x}: ${parts.join(", ")}`);
      console.log();
    }

    // Social
    if (social) {
      const avail = social.filter((s) => s.available && !s.error);
      if (avail.length > 0) {
        console.log(`${b}SOCIAL AVAILABLE${x}: ${avail.map((s) => s.platform).join(", ")}`);
        console.log();
      }
    }

    console.log(`${d}Scan complete.${x}\n`);

    // Clean up database connection
    try {
      const { closeDb: closeReconDb } = await import("./db.js");
      closeReconDb();
    } catch {}
  });

// ─── Database management subcommand ─────────────────────

program
  .command("db")
  .description("Database management")
  .option("--stats", "Show database statistics")
  .option("--clear-cache", "Clear all cached scan results")
  .option("--import-legacy", "Import data from legacy JSON files")
  .option("--history <domain>", "Show scan history for a domain")
  .option("--json", "Output as JSON")
  .action(async (opts: { stats?: boolean; clearCache?: boolean; importLegacy?: boolean; history?: string; json?: boolean }) => {
    const { getDbStats, clearCache, importLegacyPortfolio, importLegacySessions, getScanHistory, closeDb } = await import("./db.js");
    const { PORTFOLIO_FILE, SESSION_DIR } = await import("./paths.js");

    if (opts.clearCache) {
      const count = clearCache();
      console.log(`Cleared ${count} cached entries`);
      closeDb();
      return;
    }

    if (opts.importLegacy) {
      const portfolioCount = importLegacyPortfolio(PORTFOLIO_FILE);
      const sessionCount = importLegacySessions(SESSION_DIR);
      console.log(`Imported: ${portfolioCount} portfolio domains, ${sessionCount} sessions`);
      closeDb();
      return;
    }

    if (opts.history) {
      const history = getScanHistory(opts.history, 20);
      if (opts.json) { console.log(JSON.stringify(history, null, 2)); closeDb(); return; }
      console.log(`\nScan history for ${opts.history} (${history.length} scans):\n`);
      for (const h of history) {
        console.log(`  ${h.scanned_at}  ${h.status}${h.score ? `  score: ${h.score}` : ""}`);
      }
      console.log();
      closeDb();
      return;
    }

    // Default: show stats
    const stats = getDbStats();
    if (opts.json) { console.log(JSON.stringify(stats, null, 2)); closeDb(); return; }
    console.log(`\nDatabase Statistics:`);
    console.log(`  Domains tracked: ${stats.totalDomains}`);
    console.log(`  Total scans: ${stats.totalScans}`);
    console.log(`  Sessions: ${stats.totalSessions}`);
    console.log(`  Portfolio: ${stats.portfolioSize}`);
    console.log(`  WHOIS snapshots: ${stats.whoisSnapshots}`);
    console.log(`  Cache entries: ${stats.cacheEntries}`);
    console.log(`  Database size: ${(stats.dbSizeBytes / 1024).toFixed(1)} KB`);
    console.log();
    closeDb();
  });

program.parse();

// ─── Types ───────────────────────────────────────────────

interface CliOptions {
  file?: string;
  autoRegister: boolean;
  headless: boolean;
  json: boolean;
  concurrency: string;
  recon: boolean;
}

interface JsonOutputResult {
  domain: string;
  status: string;
  available: boolean;
  expired: boolean;
  confidence: string;
  registrar: string | null;
  createdDate: string | null;
  expiryDate: string | null;
  age: string | null;
  dns: { a: string[]; aaaa: string[]; mx: string[]; txt: string[]; cname: string[] } | null;
  http: { status: number | null; server: string | null; parked: boolean; reachable: boolean; redirectUrl: string | null } | null;
  wayback: { hasHistory: boolean; snapshots: number; firstArchived: string | null; lastArchived: string | null } | null;
  price: number | null;
  social: Awaited<ReturnType<typeof checkSocialMedia>> | null;
  techStack: Awaited<ReturnType<typeof detectTechStack>> | null;
  blacklist: Awaited<ReturnType<typeof checkBlacklists>> | null;
  backlinks: Awaited<ReturnType<typeof estimateBacklinks>> | null;
  portScan?: PortScanResult | null;
  reverseIp?: ReverseIpResult | null;
  asn?: AsnResult | null;
  emailSecurity?: EmailSecurityResult | null;
  zoneTransfer?: ZoneTransferResult | null;
  certTransparency?: CertTransparencyResult | null;
  takeover?: TakeoverResult | null;
  securityHeaders?: SecurityHeadersResult | null;
  waf?: WafResult | null;
  pathScan?: PathScanResult | null;
  cors?: CorsResult | null;
}

interface JsonOutput {
  timestamp: string;
  count: number;
  results: JsonOutputResult[];
}

// ─── Headless / non-interactive mode ──────────────────────

async function checkDependencies(): Promise<void> {
  const { execFile } = await import("child_process");
  const { promisify } = await import("util");
  const execFileAsync = promisify(execFile);

  const missing: string[] = [];
  try { await execFileAsync("which", ["whois"]); } catch { missing.push("whois"); }
  try { await execFileAsync("which", ["dig"]); } catch { missing.push("dig"); }

  if (missing.length > 0) {
    console.error(`Missing required tools: ${missing.join(", ")}`);
    console.error("Install them:");
    console.error("  macOS: brew install whois bind (for dig)");
    console.error("  Ubuntu/Debian: apt install whois dnsutils");
    console.error("  Alpine: apk add whois bind-tools");
    process.exit(1);
  }
}

async function runHeadless(domains: string[], options: CliOptions) {
  await checkDependencies();

  const { whoisLookup, verifyAvailability, parseDomainList } = await import("./whois.js");
  const { loadConfigFromEnv, checkAvailabilityViaRegistrar, registerDomain } = await import("./registrar.js");
  const { readFileSync, existsSync } = await import("fs");

  let domainList = [...domains];

  // Load from file if specified
  if (options.file) {
    const filePath = safePath(options.file, [process.cwd()]);
    if (!existsSync(filePath)) {
      console.error(`File not found: ${filePath}`);
      process.exit(1);
    }
    const content = readFileSync(filePath, "utf-8");
    domainList.push(...parseDomainList(content));
  }

  const rawCount = domainList.length;
  domainList = sanitizeDomainList(domainList);

  if (domainList.length === 0) {
    if (rawCount > 0) {
      console.error(`No valid domains found (${rawCount} input(s) rejected). Domains must be like: example.com`);
    } else {
      console.error("No domains specified. Use: domain-sniper example.com or -f domains.txt");
    }
    process.exit(1);
  }

  const config = loadConfigFromEnv();
  const isJsonMode = options.json;

  // JSON mode: collect results
  const jsonResults: JsonOutputResult[] = [];

  if (!isJsonMode) {
    console.log(`\n🔍 Domain Sniper - Checking ${domainList.length} domain(s)...\n`);
  }

  for (let i = 0; i < domainList.length; i++) {
    const domain = domainList[i]!;
    if (!isJsonMode) {
      process.stdout.write(`  Checking ${domain}...`);
    }

    const whois = await whoisLookup(domain);
    const verification = await verifyAvailability(domain);

    let status = "TAKEN";
    let available = false;

    if (whois.available && verification.confidence === "high") {
      status = "AVAILABLE";
      available = true;
    } else if (whois.expired) {
      status = "EXPIRED";
    } else if (whois.available) {
      status = `AVAILABLE (${verification.confidence} confidence)`;
      available = true;
    }

    // DNS details
    let dnsResult: { a: string[]; aaaa: string[]; mx: string[]; txt: string[]; cname: string[] } | null = null;
    try {
      dnsResult = await lookupDns(domain);
    } catch {}

    // HTTP probe
    let httpResult: { status: number | null; server: string | null; parked: boolean; reachable: boolean; redirectUrl: string | null } | null = null;
    try {
      const probe = await httpProbe(domain);
      httpResult = {
        status: probe.status,
        server: probe.server,
        parked: probe.parked,
        reachable: probe.reachable,
        redirectUrl: probe.redirectUrl,
      };
    } catch {}

    // Wayback Machine
    let waybackResult: { hasHistory: boolean; snapshots: number; firstArchived: string | null; lastArchived: string | null } | null = null;
    try {
      waybackResult = await checkWayback(domain);
    } catch {}

    // Domain age
    const age = calculateDomainAge(whois.createdDate);

    // Registrar price check
    let price: number | null = null;
    if (config?.apiKey) {
      const regCheck = await checkAvailabilityViaRegistrar(domain, config);
      if (regCheck.price !== undefined) {
        price = regCheck.price;
      }
    }

    // New feature data collection
    let socialResult: Awaited<ReturnType<typeof checkSocialMedia>> | null = null;
    try { socialResult = await checkSocialMedia(domain); } catch {}

    let techResult: Awaited<ReturnType<typeof detectTechStack>> | null = null;
    try { techResult = await detectTechStack(domain); } catch {}

    let blacklistResult: Awaited<ReturnType<typeof checkBlacklists>> | null = null;
    try { blacklistResult = await checkBlacklists(domain); } catch {}

    let backlinkResult: Awaited<ReturnType<typeof estimateBacklinks>> | null = null;
    try { backlinkResult = await estimateBacklinks(domain); } catch {}

    // Recon features — only when --recon flag is set
    let reconData: {
      portScan: PortScanResult | null;
      reverseIp: ReverseIpResult | null;
      asn: AsnResult | null;
      emailSecurity: EmailSecurityResult | null;
      zoneTransfer: ZoneTransferResult | null;
      certTransparency: CertTransparencyResult | null;
      takeover: TakeoverResult | null;
      securityHeaders: SecurityHeadersResult | null;
      waf: WafResult | null;
      pathScan: PathScanResult | null;
      cors: CorsResult | null;
    } | null = null;

    if (options.recon) {
      const [portsR, reverseIpR, asnR, emailSecR, zoneXferR, certsR, takeoverR, secHeadersR, wafR, pathsR, corsR] = await Promise.all([
        scanPorts(domain).catch(() => null),
        reverseIpLookup(domain).catch(() => null),
        lookupAsn(domain).catch(() => null),
        checkEmailSecurity(domain).catch(() => null),
        checkZoneTransfer(domain).catch(() => null),
        queryCertTransparency(domain).catch(() => null),
        detectTakeover(domain).catch(() => null),
        auditSecurityHeaders(domain).catch(() => null),
        detectWaf(domain).catch(() => null),
        scanPaths(domain).catch(() => null),
        checkCors(domain).catch(() => null),
      ]);
      reconData = {
        portScan: portsR,
        reverseIp: reverseIpR,
        asn: asnR,
        emailSecurity: emailSecR,
        zoneTransfer: zoneXferR,
        certTransparency: certsR,
        takeover: takeoverR,
        securityHeaders: secHeadersR,
        waf: wafR,
        pathScan: pathsR,
        cors: corsR,
      };
    }

    if (isJsonMode) {
      jsonResults.push({
        domain,
        status,
        available,
        expired: whois.expired,
        confidence: verification.confidence,
        registrar: whois.registrar,
        createdDate: whois.createdDate,
        expiryDate: whois.expiryDate,
        age,
        dns: dnsResult,
        http: httpResult,
        wayback: waybackResult,
        price,
        social: socialResult,
        techStack: techResult,
        blacklist: blacklistResult,
        backlinks: backlinkResult,
        ...(reconData || {}),
      });
    } else {
      // Normal text output
      let color = "\x1b[31m"; // red
      if (available) {
        color = "\x1b[32m"; // green
      } else if (whois.expired) {
        color = "\x1b[33m"; // yellow
      }

      console.log(`\r  ${color}${status}\x1b[0m  ${domain}`);

      // Verification details
      for (const check of verification.checks) {
        console.log(`    ${check}`);
      }

      // DNS details
      if (dnsResult) {
        if (dnsResult.a.length) console.log(`    DNS A: ${dnsResult.a.join(", ")}`);
        if (dnsResult.mx.length) console.log(`    DNS MX: ${dnsResult.mx.join(", ")}`);
        if (dnsResult.aaaa.length) console.log(`    DNS AAAA: ${dnsResult.aaaa.join(", ")}`);
      }

      // HTTP probe
      if (httpResult?.reachable) {
        let httpLine = `    HTTP: ${httpResult.status}`;
        if (httpResult.parked) httpLine += " (PARKED)";
        if (httpResult.server) httpLine += ` [${httpResult.server}]`;
        console.log(httpLine);
        if (httpResult.redirectUrl) console.log(`    Redirect: ${httpResult.redirectUrl}`);
      }

      // Wayback Machine
      if (waybackResult?.hasHistory) {
        console.log(`    Wayback: ~${waybackResult.snapshots} snapshots${waybackResult.firstArchived ? ` (${waybackResult.firstArchived}` : ""}${waybackResult.lastArchived ? ` - ${waybackResult.lastArchived})` : waybackResult.firstArchived ? ")" : ""}`);
      }

      // Domain age
      if (age) console.log(`    Age: ${age}`);

      // Social media
      if (socialResult) {
        const avail = socialResult.filter((s) => s.available && !s.error);
        if (avail.length > 0) {
          console.log(`    Social avail: ${avail.map((s) => s.platform).join(", ")}`);
        }
      }

      // Tech stack
      if (techResult) {
        const items: string[] = [];
        if (techResult.cms) items.push(techResult.cms);
        if (techResult.framework) items.push(techResult.framework);
        if (techResult.cdn) items.push(techResult.cdn);
        if (items.length > 0) console.log(`    Tech: ${items.join(", ")}`);
      }

      // Blacklist
      if (blacklistResult) {
        if (blacklistResult.listed) {
          const names = blacklistResult.lists.filter((l) => l.listed).map((l) => l.name).join(", ");
          console.log(`    \x1b[31mBLACKLISTED: ${names}\x1b[0m`);
        } else {
          console.log(`    Reputation: clean (${blacklistResult.cleanCount}/${blacklistResult.lists.length})`);
        }
      }

      // Backlinks
      if (backlinkResult) {
        const parts: string[] = [];
        if (backlinkResult.pageRank !== null) parts.push(`PageRank: ${backlinkResult.pageRank}`);
        if (backlinkResult.commonCrawlPages !== null) parts.push(`CC pages: ~${backlinkResult.commonCrawlPages}`);
        if (parts.length > 0) console.log(`    Authority: ${parts.join(", ")}`);
      }

      // Recon data (if --recon was set)
      if (reconData) {
        if (reconData.asn && !reconData.asn.error) {
          const asnParts: string[] = [];
          if (reconData.asn.asn) asnParts.push(reconData.asn.asn);
          if (reconData.asn.org) asnParts.push(reconData.asn.org);
          if (reconData.asn.country) asnParts.push(reconData.asn.country);
          if (asnParts.length > 0) console.log(`    Network: ${asnParts.join(" | ")}`);
        }
        if (reconData.portScan && reconData.portScan.openPorts.length > 0) {
          console.log(`    \x1b[31mOpen ports: ${reconData.portScan.openPorts.map((p) => `${p.port}/${p.service}`).join(", ")}\x1b[0m`);
        }
        if (reconData.emailSecurity) {
          console.log(`    Email security: ${reconData.emailSecurity.grade} (SPF:${reconData.emailSecurity.spf.found ? "ok" : "missing"} DKIM:${reconData.emailSecurity.dkim.found ? "ok" : "missing"} DMARC:${reconData.emailSecurity.dmarc.found ? "ok" : "missing"})`);
        }
        if (reconData.securityHeaders && !reconData.securityHeaders.error) {
          console.log(`    Security headers: ${reconData.securityHeaders.grade} (${reconData.securityHeaders.score}/100)`);
        }
        if (reconData.waf?.detected) {
          console.log(`    WAF: ${reconData.waf.waf} (${reconData.waf.confidence})`);
        }
        if (reconData.zoneTransfer?.vulnerable) {
          console.log(`    \x1b[31m!! Zone transfer vulnerable: ${reconData.zoneTransfer.vulnerableNs.join(", ")}\x1b[0m`);
        }
        if (reconData.takeover?.vulnerable) {
          const vulnSubs = reconData.takeover.findings.filter((f) => f.status === "vulnerable");
          console.log(`    \x1b[31m!! Subdomain takeover: ${vulnSubs.map((f) => f.subdomain).join(", ")}\x1b[0m`);
        }
        if (reconData.pathScan && reconData.pathScan.findings.length > 0) {
          console.log(`    \x1b[31mExposed paths: ${reconData.pathScan.findings.slice(0, 5).map((f) => f.path).join(", ")}\x1b[0m`);
        }
        if (reconData.cors?.vulnerable) {
          console.log(`    \x1b[31m!! CORS misconfiguration\x1b[0m`);
        }
        if (reconData.certTransparency && reconData.certTransparency.subdomains.length > 0) {
          console.log(`    CT subdomains: ${reconData.certTransparency.subdomains.length} found`);
        }
        if (reconData.reverseIp && reconData.reverseIp.sharedDomains.length > 0) {
          console.log(`    Shared hosting: ${reconData.reverseIp.sharedDomains.length} domains on ${reconData.reverseIp.ip}`);
        }
      }

      // Registrar check
      if (config?.apiKey) {
        const regCheck = await checkAvailabilityViaRegistrar(domain, config);
        if (regCheck.available) {
          console.log(`    ✓ Registrar (${config.provider}): Available${regCheck.price ? ` - $${regCheck.price}` : ""}`);
        }

        // Auto-register
        if (options.autoRegister && (whois.available || whois.expired) && verification.available) {
          console.log(`    ◎ Registering via ${config.provider}...`);
          const result = await registerDomain(domain, config);
          if (result.success) {
            console.log(`    ★ ${result.message}`);
          } else {
            console.log(`    ✗ Registration failed: ${result.error}`);
          }
        }
      }

      console.log();

      // Visual separator between multi-domain results
      if (i < domainList.length - 1) {
        console.log("  ───────────────────────────────────");
      }
    }

    // Rate limit between lookups
    if (i < domainList.length - 1) {
      await new Promise((r) => setTimeout(r, 1500));
    }
  }

  if (isJsonMode) {
    const output: JsonOutput = {
      timestamp: new Date().toISOString(),
      count: jsonResults.length,
      results: jsonResults,
    };
    console.log(JSON.stringify(output, null, 2));
    // Exit with error code if any domain had an error status
    const hasErrors = jsonResults.some((r) => r.status === "error");
    if (hasErrors) process.exitCode = 1;
  } else {
    console.log("Done!\n");
  }

  // Clean up database connection
  try {
    const { closeDb } = await import("./db.js");
    closeDb();
  } catch {}
}
