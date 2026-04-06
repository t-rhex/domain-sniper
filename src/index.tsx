#!/usr/bin/env bun
import { createCliRenderer } from "@opentui/core";
import { createRoot } from "@opentui/react";
import { App } from "./app.js";
import { Command } from "commander";
import { lookupDns } from "./core/features/dns-details.js";
import { httpProbe } from "./core/features/http-probe.js";
import { checkWayback } from "./core/features/wayback.js";
import { calculateDomainAge } from "./core/features/domain-age.js";
import { sanitizeDomainList, safePath, detectTldTypo } from "./core/validate.js";
import { bashCompletions, zshCompletions, fishCompletions } from "./completions.js";
import { checkSocialMedia } from "./core/features/social-check.js";
import { detectTechStack } from "./core/features/tech-stack.js";
import { checkBlacklists } from "./core/features/blacklist-check.js";
import { estimateBacklinks } from "./core/features/backlinks.js";
import { scanPorts } from "./core/features/port-scanner.js";
import { reverseIpLookup } from "./core/features/reverse-ip.js";
import { lookupAsn } from "./core/features/asn-lookup.js";
import { checkEmailSecurity } from "./core/features/email-security.js";
import { checkZoneTransfer } from "./core/features/zone-transfer.js";
import { queryCertTransparency } from "./core/features/cert-transparency.js";
import { detectTakeover } from "./core/features/takeover-detect.js";
import { auditSecurityHeaders } from "./core/features/security-headers.js";
import { detectWaf } from "./core/features/waf-detect.js";
import { scanPaths } from "./core/features/path-scanner.js";
import { checkCors } from "./core/features/cors-check.js";
import { rdapLookup } from "./core/features/rdap.js";
import { checkSsl } from "./core/features/ssl-check.js";
import type { PortScanResult } from "./core/features/port-scanner.js";
import type { ReverseIpResult } from "./core/features/reverse-ip.js";
import type { AsnResult } from "./core/features/asn-lookup.js";
import type { EmailSecurityResult } from "./core/features/email-security.js";
import type { ZoneTransferResult } from "./core/features/zone-transfer.js";
import type { CertTransparencyResult } from "./core/features/cert-transparency.js";
import type { TakeoverResult } from "./core/features/takeover-detect.js";
import type { SecurityHeadersResult } from "./core/features/security-headers.js";
import type { WafResult } from "./core/features/waf-detect.js";
import type { PathScanResult } from "./core/features/path-scanner.js";
import type { CorsResult } from "./core/features/cors-check.js";

const program = new Command();

program
  .name("dsniper")
  .description("All-in-one domain intelligence toolkit — availability checker, security recon, portfolio manager")
  .version("0.1.3")
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
      const { parseDomainList } = await import("./core/whois.js");
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
        useMouse: true,
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
  .option("-t, --tld <tld>", "TLD or 'all' for multi-TLD", "com")
  .option("-n, --count <n>", "Number of suggestions", "20")
  .option("--check", "Check availability of suggestions", false)
  .action(async (keyword: string, opts: { tld: string; count: string; check: boolean }) => {
    const { generateScoredSuggestions } = await import("./core/features/domain-suggest.js");
    const tlds = opts.tld === "all" ? ["com", "io", "dev", "app", "co", "net", "org", "me", "sh", "gg"] : [opts.tld];
    const suggestions = generateScoredSuggestions(keyword, tlds, parseInt(opts.count, 10));

    if (opts.check) {
      const { whoisLookup } = await import("./core/whois.js");
      console.log(`\nChecking ${suggestions.length} suggestions for "${keyword}"...\n`);

      // Concurrent check (5 at a time)
      const CONCURRENCY = 5;
      const results: Array<{ domain: string; strategy: string; available: boolean; score: number; grade: string }> = [];

      for (let i = 0; i < suggestions.length; i += CONCURRENCY) {
        const batch = suggestions.slice(i, i + CONCURRENCY);
        const batchResults = await Promise.all(
          batch.map(async (s) => {
            const whois = await whoisLookup(s.domain);
            return { domain: s.domain, strategy: s.strategy, available: whois.available, score: s.score, grade: s.grade };
          })
        );
        results.push(...batchResults);
      }

      // Sort: available first, then by score
      results.sort((a, b) => {
        if (a.available && !b.available) return -1;
        if (!a.available && b.available) return 1;
        return b.score - a.score;
      });

      for (const r of results) {
        const status = r.available ? "\x1b[32mAVAILABLE\x1b[0m" : "\x1b[31mTAKEN\x1b[0m";
        console.log(`  ${status}  ${r.grade.padEnd(3)} ${r.domain.padEnd(30)} (${r.strategy})`);
      }
      console.log(`\n  ${results.filter(r => r.available).length} available out of ${results.length} checked\n`);
    } else {
      // No check — just list suggestions with scores
      console.log(`\nSuggestions for "${keyword}":\n`);
      for (const s of suggestions) {
        console.log(`  ${s.grade.padEnd(3)} ${s.domain.padEnd(30)} (${s.strategy})`);
      }
      console.log();
    }
  });

// ─── Portfolio subcommand ────────────────────────────────

program
  .command("portfolio")
  .description("Manage your domain portfolio")
  .option("--add <domain>", "Add a domain to portfolio")
  .option("--remove <domain>", "Remove a domain from portfolio")
  .option("--status <domain:status>", "Set domain status (active|parked|for-sale|development|archived)")
  .option("--category <domain:category>", "Set domain category")
  .option("--value <domain:amount>", "Set estimated value")
  .option("--transaction <domain:type:amount>", "Record transaction (purchase|renewal|sale|parking-revenue|affiliate-revenue|expense)")
  .option("--expiring [days]", "Show domains expiring within N days")
  .option("--renewals", "Show renewal calendar")
  .option("--health", "Run health check on all portfolio domains")
  .option("--pnl [domain]", "Show P&L (for specific domain or total)")
  .option("--monthly [months]", "Show monthly financial report")
  .option("--pipeline", "Show acquisition pipeline")
  .option("--pipeline-add <domain>", "Add domain to acquisition pipeline")
  .option("--alerts", "Show unacknowledged alerts")
  .option("--dismiss-alerts", "Dismiss all alerts")
  .option("--categories", "List categories")
  .option("--export-csv <path>", "Export portfolio to CSV")
  .option("--export-tax <year>", "Export tax data for year")
  .option("--export-transactions <path>", "Export transactions to CSV")
  .option("--upload-s3", "Upload latest export to S3/R2")
  .option("--dashboard", "Show portfolio dashboard summary")
  .option("--stats", "Show portfolio statistics")
  .option("--json", "Output as JSON")
  .action(async (opts: {
    add?: string; remove?: string; status?: string; category?: string; value?: string;
    transaction?: string; expiring?: string; renewals?: boolean; health?: boolean;
    pnl?: string | boolean; monthly?: string | boolean; pipeline?: boolean; pipelineAdd?: string;
    alerts?: boolean; dismissAlerts?: boolean; categories?: boolean;
    exportCsv?: string; exportTax?: string; exportTransactions?: string;
    uploadS3?: boolean; dashboard?: boolean; stats?: boolean; json?: boolean;
  }) => {
    if (opts.add) {
      const { addToPortfolio } = await import("./core/features/portfolio.js");
      addToPortfolio(opts.add);
      console.log(`Added ${opts.add} to portfolio`);
      return;
    }

    if (opts.remove) {
      const { removeFromPortfolio } = await import("./core/features/portfolio.js");
      removeFromPortfolio(opts.remove);
      console.log(`Removed ${opts.remove} from portfolio`);
      return;
    }

    if (opts.status) {
      const [domain, status] = opts.status.split(":");
      if (!domain || !status) { console.error("Usage: --status domain.com:active"); process.exit(1); }
      const { updatePortfolioStatus } = await import("./core/db.js");
      updatePortfolioStatus(domain, status as any);
      console.log(`Set ${domain} status to ${status}`);
      return;
    }

    if (opts.category) {
      const [domain, category] = opts.category.split(":");
      if (!domain || !category) { console.error("Usage: --category domain.com:investments"); process.exit(1); }
      const { updatePortfolioCategory } = await import("./core/db.js");
      updatePortfolioCategory(domain, category);
      console.log(`Set ${domain} category to ${category}`);
      return;
    }

    if (opts.value) {
      const [domain, amountStr] = opts.value.split(":");
      if (!domain || !amountStr) { console.error("Usage: --value domain.com:5000"); process.exit(1); }
      const { updatePortfolioValue } = await import("./core/db.js");
      updatePortfolioValue(domain, parseFloat(amountStr));
      console.log(`Set ${domain} estimated value to $${amountStr}`);
      return;
    }

    if (opts.transaction) {
      const parts = opts.transaction.split(":");
      if (parts.length < 3) { console.error("Usage: --transaction domain.com:purchase:9.99"); process.exit(1); }
      const [domain, type, amountStr] = parts;
      const { addTransaction } = await import("./core/db.js");
      addTransaction(domain!, type as any, parseFloat(amountStr!));
      console.log(`Recorded ${type} of $${amountStr} for ${domain}`);
      return;
    }

    if (opts.expiring !== undefined) {
      const { getPortfolioExpiring, closeDb } = await import("./core/db.js");
      const days = parseInt(String(opts.expiring) || "30", 10) || 30;
      const expiring = getPortfolioExpiring(days);
      if (opts.json) { console.log(JSON.stringify(expiring, null, 2)); closeDb(); return; }
      console.log(`\nDomains expiring within ${days} days:\n`);
      if (expiring.length === 0) { console.log("  None"); }
      for (const d of expiring) { console.log(`  ${d.domain}  ${d.expiry_date}  ${d.registrar}`); }
      console.log();
      closeDb();
      return;
    }

    if (opts.renewals) {
      const { generateRenewalCalendar, estimateAnnualRenewalCost } = await import("./core/features/portfolio-monitor.js");
      const calendar = generateRenewalCalendar(12);
      const annualCost = estimateAnnualRenewalCost();
      if (opts.json) { console.log(JSON.stringify({ calendar, annualCost }, null, 2)); return; }
      console.log(`\nRenewal Calendar (est. annual cost: $${annualCost.toFixed(0)}):\n`);
      if (calendar.length === 0) { console.log("  No upcoming renewals."); }
      for (const r of calendar) {
        const urgency = r.daysLeft <= 7 ? "!!" : r.daysLeft <= 30 ? "! " : "  ";
        console.log(`  ${urgency} ${r.domain.padEnd(30)} ${String(r.daysLeft).padStart(4)}d  $${r.renewalPrice}${r.autoRenew ? "  (auto-renew)" : ""}`);
      }
      console.log();
      return;
    }

    if (opts.health) {
      const { runPortfolioHealthCheck } = await import("./core/features/portfolio-monitor.js");
      console.log("\nRunning portfolio health check...\n");
      const report = await runPortfolioHealthCheck((domain, i, total) => {
        process.stdout.write(`\r  Checking ${i + 1}/${total}: ${domain}...`);
      });
      console.log("\r" + " ".repeat(60) + "\r");
      if (opts.json) { console.log(JSON.stringify(report, null, 2)); return; }
      console.log(`Health Check Results:`);
      console.log(`  Checked: ${report.checked}`);
      console.log(`  Healthy: ${report.healthy}`);
      console.log(`  Warnings: ${report.warnings}`);
      console.log(`  Critical: ${report.critical}`);
      if (report.alerts.length > 0) {
        console.log(`\nAlerts:`);
        for (const a of report.alerts) {
          const icon = a.severity === "critical" ? "!!" : a.severity === "warning" ? "! " : "  ";
          console.log(`  ${icon} ${a.domain}: ${a.message}`);
        }
      }
      console.log();
      return;
    }

    if (opts.pnl !== undefined) {
      const { getDomainPnL, getPortfolioPnL } = await import("./core/db.js");
      if (typeof opts.pnl === "string") {
        const pnl = getDomainPnL(opts.pnl);
        if (opts.json) { console.log(JSON.stringify(pnl, null, 2)); return; }
        console.log(`\nP&L for ${opts.pnl}:`);
        console.log(`  Costs:   $${pnl.costs.toFixed(2)}`);
        console.log(`  Revenue: $${pnl.revenue.toFixed(2)}`);
        console.log(`  Profit:  $${pnl.profit.toFixed(2)}\n`);
      } else {
        const pnl = getPortfolioPnL();
        if (opts.json) { console.log(JSON.stringify(pnl, null, 2)); return; }
        console.log(`\nPortfolio P&L:`);
        console.log(`  Total Costs:   $${pnl.totalCosts.toFixed(2)}`);
        console.log(`  Total Revenue: $${pnl.totalRevenue.toFixed(2)}`);
        console.log(`  Total Profit:  $${pnl.totalProfit.toFixed(2)}`);
        console.log(`  Domains:       ${pnl.domainCount}\n`);
      }
      return;
    }

    if (opts.monthly !== undefined) {
      const { getMonthlyReport } = await import("./core/db.js");
      const months = typeof opts.monthly === "string" ? parseInt(opts.monthly, 10) : 12;
      const report = getMonthlyReport(months);
      if (opts.json) { console.log(JSON.stringify(report, null, 2)); return; }
      console.log(`\nMonthly Report (${months} months):\n`);
      console.log(`  ${"Month".padEnd(10)} ${"Costs".padEnd(12)} ${"Revenue".padEnd(12)} ${"Profit".padEnd(12)}`);
      console.log(`  ${"─".repeat(10)} ${"─".repeat(12)} ${"─".repeat(12)} ${"─".repeat(12)}`);
      for (const m of report) {
        console.log(`  ${m.month.padEnd(10)} $${m.costs.toFixed(2).padStart(10)}  $${m.revenue.toFixed(2).padStart(10)}  $${m.profit.toFixed(2).padStart(10)}`);
      }
      console.log();
      return;
    }

    if (opts.pipeline) {
      const { getPipeline } = await import("./core/db.js");
      const pipeline = getPipeline();
      if (opts.json) { console.log(JSON.stringify(pipeline, null, 2)); return; }
      console.log(`\nAcquisition Pipeline (${pipeline.length} domains):\n`);
      if (pipeline.length === 0) { console.log("  Empty. Use --pipeline-add <domain> to add."); }
      for (const p of pipeline) {
        console.log(`  ${p.domain.padEnd(30)} ${p.status.padEnd(14)} ${p.priority}${p.max_bid ? `  max: $${p.max_bid}` : ""}${p.notes ? `  ${p.notes}` : ""}`);
      }
      console.log();
      return;
    }

    if (opts.pipelineAdd) {
      const { addToPipeline } = await import("./core/db.js");
      addToPipeline(opts.pipelineAdd);
      console.log(`Added ${opts.pipelineAdd} to acquisition pipeline`);
      return;
    }

    if (opts.alerts) {
      const { getUnacknowledgedAlerts } = await import("./core/db.js");
      const alerts = getUnacknowledgedAlerts();
      if (opts.json) { console.log(JSON.stringify(alerts, null, 2)); return; }
      console.log(`\nAlerts (${alerts.length} unacknowledged):\n`);
      if (alerts.length === 0) { console.log("  No alerts."); }
      for (const a of alerts) {
        const icon = a.severity === "critical" ? "!!" : a.severity === "warning" ? "! " : "  ";
        console.log(`  ${icon} [${a.severity}] ${a.domain}: ${a.message}  (${a.created_at})`);
      }
      console.log();
      return;
    }

    if (opts.dismissAlerts) {
      const { acknowledgeAllAlerts } = await import("./core/db.js");
      acknowledgeAllAlerts();
      console.log("All alerts dismissed");
      return;
    }

    if (opts.categories) {
      const { getCategories } = await import("./core/db.js");
      const categories = getCategories();
      if (opts.json) { console.log(JSON.stringify(categories, null, 2)); return; }
      console.log(`\nCategories:\n`);
      for (const c of categories) {
        console.log(`  ${c.name.padEnd(20)} ${c.count} domain(s)${c.description ? `  — ${c.description}` : ""}`);
      }
      console.log();
      return;
    }

    if (opts.exportCsv) {
      const { exportPortfolioCSV } = await import("./core/features/portfolio-bulk.js");
      const path = exportPortfolioCSV(opts.exportCsv);
      console.log(`Portfolio exported to ${path}`);
      return;
    }

    if (opts.exportTax) {
      const year = parseInt(opts.exportTax, 10);
      if (isNaN(year)) { console.error("Usage: --export-tax 2025"); process.exit(1); }
      const { exportTaxCSV } = await import("./core/features/portfolio-bulk.js");
      const path = exportTaxCSV(`tax-${year}.csv`, year);
      console.log(`Tax data for ${year} exported to ${path}`);
      return;
    }

    if (opts.exportTransactions) {
      const { exportTransactionsCSV } = await import("./core/features/portfolio-bulk.js");
      const path = exportTransactionsCSV(opts.exportTransactions);
      console.log(`Transactions exported to ${path}`);
      return;
    }

    if (opts.uploadS3) {
      const { isS3Configured, uploadPortfolioExport } = await import("./core/features/s3-export.js");
      if (!isS3Configured()) {
        console.error("S3 not configured. Set S3_BUCKET, S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY in .env");
        process.exit(1);
      }
      const { exportPortfolioCSV } = await import("./core/features/portfolio-bulk.js");
      const csvPath = exportPortfolioCSV("/tmp/ds-portfolio-export.csv");
      const csvContent = await Bun.file(csvPath).text();
      const result = await uploadPortfolioExport(csvContent);
      console.log(`Uploaded to S3: ${result.key}`);
      return;
    }

    if (opts.dashboard) {
      const { getPortfolioDashboard, getTotalPortfolioValue } = await import("./core/db.js");
      const { estimateAnnualRenewalCost } = await import("./core/features/portfolio-monitor.js");
      const dash = getPortfolioDashboard();
      const annualCost = estimateAnnualRenewalCost();
      if (opts.json) { console.log(JSON.stringify(dash, null, 2)); return; }
      console.log(`\n◆ Portfolio Dashboard`);
      console.log(`  Domains: ${dash.totalDomains}  |  Value: $${dash.totalValue.toFixed(0)}  |  Annual cost: ~$${annualCost.toFixed(0)}`);
      console.log(`  P&L: -$${dash.totalCosts.toFixed(0)} costs + $${dash.totalRevenue.toFixed(0)} revenue = $${dash.totalProfit.toFixed(0)} profit`);
      console.log(`  Expiring: ${dash.expiringIn30} in 30d, ${dash.expiringIn90} in 90d`);
      console.log(`  Alerts: ${dash.activeAlerts}  |  Pipeline: ${dash.pipelineCount}`);
      if (Object.keys(dash.byStatus).length > 0) {
        console.log(`  Status: ${Object.entries(dash.byStatus).map(([s, c]) => `${s}(${c})`).join(" ")}`);
      }
      console.log();
      return;
    }

    if (opts.stats) {
      const { getPortfolioStatsDb, closeDb } = await import("./core/db.js");
      const stats = getPortfolioStatsDb();
      if (opts.json) { console.log(JSON.stringify(stats, null, 2)); closeDb(); return; }
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
      closeDb();
      return;
    }

    // Default: list all portfolio domains
    const { getPortfolioDomains, closeDb } = await import("./core/db.js");
    const domains = getPortfolioDomains();
    if (opts.json) { console.log(JSON.stringify(domains, null, 2)); closeDb(); return; }
    console.log(`\nDomain Portfolio (${domains.length} domains):\n`);
    if (domains.length === 0) { console.log("  Empty. Use --add <domain> to add domains."); }
    for (const d of domains) {
      console.log(`  ${d.domain.padEnd(30)} ${(d as any).status?.padEnd(12) || "active".padEnd(12)} ${d.registrar.padEnd(16)} ${d.expiry_date || "no expiry"}  $${d.purchase_price}`);
    }
    console.log();
    closeDb();
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
    const { loadConfig, saveConfig, getConfigPath, resetConfig } = await import("./core/features/config.js");

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
    const { getExpiringFeed } = await import("./core/features/expiring-feed.js");
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
    const { createDropCatcher, formatDropCatchStatus } = await import("./core/features/drop-catch.js");
    const { loadConfigFromEnv } = await import("./core/registrar.js");
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
    const { whoisLookup, verifyAvailability } = await import("./core/whois.js");

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
      const { closeDb: closeReconDb } = await import("./core/db.js");
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
    const { getDbStats, clearCache, importLegacyPortfolio, importLegacySessions, getScanHistory, closeDb } = await import("./core/db.js");
    const { PORTFOLIO_FILE, SESSION_DIR } = await import("./core/paths.js");

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

// ─── Serve subcommand ──────────────────────────────────

program
  .command("serve")
  .description("Start the marketplace server")
  .option("--port <port>", "Port number", "3000")
  .action(async (opts: { port: string }) => {
    process.env.MARKET_PORT = opts.port;
    const marketPath = "../marketplace/index.js";
    try {
      await import(/* @vite-ignore */ marketPath);
    } catch {
      console.error("Marketplace server not found. Clone the private marketplace repo:");
      console.error("  git clone https://github.com/t-rhex/domain-sniper-marketplace marketplace/");
      console.error("  bun run serve");
      process.exit(1);
    }
  });

// ─── Market subcommand ─────────────────────────────────

const market = program
  .command("market")
  .description("Domain marketplace — buy, sell, and trade domains");

market
  .command("signup")
  .description("Create a marketplace account")
  .option("--server <url>", "Marketplace server URL", "http://localhost:3000")
  .option("--email <email>", "Email address")
  .option("--password <password>", "Password (min 8 chars)")
  .option("--name <name>", "Display name")
  .action(async (opts: { server: string; email?: string; password?: string; name?: string }) => {
    const { signUp } = await import("./market-client.js");
    let name = opts.name;
    let email = opts.email;
    let password = opts.password;

    if (!name || !email || !password) {
      const readline = await import("readline");
      const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
      const ask = (q: string): Promise<string> => new Promise((r) => rl.question(q, r));
      if (!name) name = await ask("Name: ");
      if (!email) email = await ask("Email: ");
      if (!password) password = await ask("Password (min 8 chars): ");
      rl.close();
    }

    const result = await signUp(email!, password!, name!, opts.server);
    if (result.success) {
      console.log(`\n✓ Account created. Signed in as ${email}\n`);
    } else {
      console.error(`\n✗ ${result.error}\n`);
      process.exit(1);
    }
  });

market
  .command("login")
  .description("Sign in to the marketplace")
  .option("--server <url>", "Marketplace server URL", "http://localhost:3000")
  .option("--email <email>", "Email address")
  .option("--password <password>", "Password")
  .action(async (opts: { server: string; email?: string; password?: string }) => {
    const { signIn } = await import("./market-client.js");
    let email = opts.email;
    let password = opts.password;

    if (!email || !password) {
      const readline = await import("readline");
      const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
      const ask = (q: string): Promise<string> => new Promise((r) => rl.question(q, r));
      if (!email) email = await ask("Email: ");
      if (!password) password = await ask("Password: ");
      rl.close();
    }

    const result = await signIn(email!, password!, opts.server);
    if (result.success) {
      console.log(`\n✓ Signed in as ${email}\n`);
    } else {
      console.error(`\n✗ ${result.error}\n`);
      process.exit(1);
    }
  });

market
  .command("logout")
  .description("Sign out of the marketplace")
  .action(async () => {
    const { signOut } = await import("./market-client.js");
    signOut();
    console.log("Signed out.");
  });

market
  .command("whoami")
  .description("Show current auth status")
  .action(async () => {
    const { getAuthInfo, getServerUrl } = await import("./market-client.js");
    const info = getAuthInfo();
    if (info) {
      console.log(`\nSigned in as: ${info.name} (${info.email})`);
      console.log(`Server: ${getServerUrl()}\n`);
    } else {
      console.log("\nNot signed in. Use: domain-sniper market login\n");
    }
  });

market
  .command("browse")
  .description("Browse domain listings")
  .option("-q, --query <search>", "Search domains")
  .option("--category <cat>", "Filter by category")
  .option("--min <price>", "Minimum price")
  .option("--max <price>", "Maximum price")
  .option("--verified", "Only verified listings")
  .option("--sort <field>", "Sort: newest, price_asc, price_desc, popular", "newest")
  .option("-n, --limit <n>", "Results per page", "20")
  .option("--json", "Output as JSON")
  .action(async (opts: any) => {
    const { browseListings } = await import("./market-client.js");
    const result = await browseListings({
      search: opts.query, category: opts.category,
      minPrice: opts.min ? parseFloat(opts.min) : undefined,
      maxPrice: opts.max ? parseFloat(opts.max) : undefined,
      verified: opts.verified, sort: opts.sort,
      limit: parseInt(opts.limit, 10),
    });
    if (!result.ok) { console.error("Failed to fetch listings:", result.data?.error); process.exit(1); }
    if (opts.json) { console.log(JSON.stringify(result.data, null, 2)); return; }

    const { listings, total } = result.data;
    console.log(`\n◆ Domain Marketplace (${total} listings)\n`);
    if (listings.length === 0) { console.log("  No listings found.\n"); return; }
    console.log(`  ${"DOMAIN".padEnd(30)} ${"PRICE".padStart(10)} ${"STATUS".padEnd(10)} VERIFIED`);
    console.log(`  ${"─".repeat(30)} ${"─".repeat(10)} ${"─".repeat(10)} ${"─".repeat(8)}`);
    for (const l of listings) {
      console.log(`  ${l.domain.padEnd(30)} ${"$" + l.asking_price.toFixed(2).padStart(9)} ${l.status.padEnd(10)} ${l.verified ? "✓" : " "}`);
    }
    console.log();
  });

market
  .command("list <domain>")
  .description("List a domain for sale")
  .requiredOption("-p, --price <amount>", "Asking price")
  .option("-t, --title <title>", "Listing title")
  .option("-d, --description <desc>", "Description")
  .option("--min-offer <amount>", "Minimum acceptable offer")
  .option("--buy-now", "Enable buy-now at asking price")
  .option("--category <cat>", "Category")
  .action(async (domain: string, opts: any) => {
    const { isLoggedIn, createListingApi } = await import("./market-client.js");
    if (!isLoggedIn()) { console.error("Not signed in. Use: domain-sniper market login"); process.exit(1); }

    const result = await createListingApi(domain, parseFloat(opts.price), {
      title: opts.title, description: opts.description,
      minOffer: opts.minOffer ? parseFloat(opts.minOffer) : undefined,
      buyNow: opts.buyNow, category: opts.category,
    });
    if (!result.ok) { console.error("Failed:", result.data?.error); process.exit(1); }

    const { listing, verification } = result.data;
    console.log(`\n✓ Listing created (#${listing.id}): ${domain} at $${listing.asking_price}`);
    console.log(`\nVerify ownership to activate listing:\n`);
    console.log(`Option 1 — DNS TXT Record:`);
    console.log(`  ${verification.instructions.dns}\n`);
    console.log(`Option 2 — HTTP File:`);
    console.log(`  ${verification.instructions.http}\n`);
    console.log(`Option 3 — Meta Tag:`);
    console.log(`  ${verification.instructions.meta}\n`);
  });

market
  .command("verify <domain>")
  .description("Verify domain ownership for a listing")
  .action(async (domain: string) => {
    const { isLoggedIn, getMyListings, verifyListingApi } = await import("./market-client.js");
    if (!isLoggedIn()) { console.error("Not signed in."); process.exit(1); }

    const myListings = await getMyListings();
    if (!myListings.ok) { console.error("Failed to fetch listings"); process.exit(1); }

    const listing = myListings.data.find((l: any) => l.domain === domain && !l.verified);
    if (!listing) { console.error(`No unverified listing found for ${domain}`); process.exit(1); }

    console.log(`\nVerifying ${domain}...`);
    const result = await verifyListingApi(listing.id);
    if (result.ok && result.data.verified) {
      console.log(`✓ Verified via ${result.data.method}! Listing is now active.\n`);
    } else {
      console.error(`✗ ${result.data.error || "Verification failed"}`);
      console.error(`  Make sure your DNS TXT record, HTTP file, or meta tag is set up.\n`);
      process.exit(1);
    }
  });

market
  .command("offer")
  .description("Make an offer on a listing")
  .requiredOption("-l, --listing <id>", "Listing ID")
  .requiredOption("-a, --amount <price>", "Offer amount")
  .option("-m, --message <msg>", "Message to seller")
  .action(async (opts: any) => {
    const { isLoggedIn, makeOffer } = await import("./market-client.js");
    if (!isLoggedIn()) { console.error("Not signed in."); process.exit(1); }

    const result = await makeOffer(parseInt(opts.listing, 10), parseFloat(opts.amount), opts.message || "");
    if (result.ok) {
      console.log(`\n✓ Offer of $${opts.amount} submitted on listing #${opts.listing}\n`);
    } else {
      console.error(`✗ ${result.data?.error || "Failed"}\n`);
      process.exit(1);
    }
  });

market
  .command("my-listings")
  .description("Show your listings")
  .option("--json", "Output as JSON")
  .action(async (opts: any) => {
    const { isLoggedIn, getMyListings } = await import("./market-client.js");
    if (!isLoggedIn()) { console.error("Not signed in."); process.exit(1); }

    const result = await getMyListings();
    if (!result.ok) { console.error("Failed"); process.exit(1); }
    if (opts.json) { console.log(JSON.stringify(result.data, null, 2)); return; }

    const listings = result.data;
    console.log(`\nYour Listings (${listings.length}):\n`);
    for (const l of listings) {
      console.log(`  #${l.id}  ${l.domain.padEnd(25)} $${l.asking_price}  ${l.status}  ${l.verified ? "✓ verified" : "unverified"}`);
    }
    console.log();
  });

market
  .command("my-offers")
  .description("Show offers you've made or received")
  .option("--role <role>", "buyer or seller", "buyer")
  .option("--json", "Output as JSON")
  .action(async (opts: any) => {
    const { isLoggedIn, getMyOffers } = await import("./market-client.js");
    if (!isLoggedIn()) { console.error("Not signed in."); process.exit(1); }

    const result = await getMyOffers(opts.role);
    if (!result.ok) { console.error("Failed"); process.exit(1); }
    if (opts.json) { console.log(JSON.stringify(result.data, null, 2)); return; }

    const offers = result.data;
    console.log(`\nYour Offers as ${opts.role} (${offers.length}):\n`);
    for (const o of offers) {
      console.log(`  #${o.id}  ${o.domain.padEnd(25)} $${o.amount}  ${o.status}`);
    }
    console.log();
  });

market
  .command("stats")
  .description("Show marketplace statistics")
  .option("--json", "Output as JSON")
  .action(async (opts: any) => {
    const { getMarketStatsApi } = await import("./market-client.js");
    const result = await getMarketStatsApi();
    if (!result.ok) { console.error("Cannot reach marketplace server"); process.exit(1); }
    if (opts.json) { console.log(JSON.stringify(result.data, null, 2)); return; }

    const s = result.data;
    console.log(`\n◆ Marketplace Stats`);
    console.log(`  Total listings: ${s.totalListings}`);
    console.log(`  Active:         ${s.activeListings}`);
    console.log(`  Total offers:   ${s.totalOffers}`);
    console.log(`  Users:          ${s.totalUsers}\n`);
  });

// ─── Proxy commands ──────────────────────────────────────

const proxy = program
  .command("proxy")
  .description("HTTP intercepting proxy — capture and analyze traffic");

proxy
  .command("start")
  .description("Start the intercepting proxy")
  .option("-p, --port <port>", "Proxy port", "8080")
  .option("--https", "Enable HTTPS interception (requires CA cert)", false)
  .option("--filter <hosts>", "Only intercept these hosts (comma-separated)")
  .action(async (opts: { port: string; https: boolean; filter?: string }) => {
    const { startProxy } = await import("./proxy/server.js");
    const filterHosts = opts.filter ? opts.filter.split(",").map((h) => h.trim()) : undefined;

    startProxy({
      port: parseInt(opts.port, 10),
      httpsInterception: opts.https,
      filterHosts,
      onRequest: (entry) => {
        const statusColor = entry.statusCode && entry.statusCode < 400 ? "\x1b[32m" : "\x1b[31m";
        console.log(`  ${entry.method.padEnd(6)} ${statusColor}${entry.statusCode || "ERR"}\x1b[0m ${entry.host}${entry.url.replace(/^https?:\/\/[^/]+/, "")} (${entry.durationMs}ms, ${entry.size}b)`);
      },
    });

    // Keep running
    console.log("Press Ctrl+C to stop\n");
  });

proxy
  .command("history")
  .description("Browse intercepted requests")
  .option("--host <host>", "Filter by host")
  .option("--method <method>", "Filter by method (GET, POST, etc.)")
  .option("--search <query>", "Search in URL/body")
  .option("--flagged", "Show only flagged requests")
  .option("-n, --limit <n>", "Number of results", "30")
  .option("--json", "Output as JSON")
  .action(async (opts: { host?: string; method?: string; search?: string; flagged?: boolean; limit: string; json?: boolean }) => {
    const { getRequests } = await import("./proxy/db.js");
    const result = getRequests({
      host: opts.host, method: opts.method, search: opts.search,
      flagged: opts.flagged, limit: parseInt(opts.limit, 10),
    });
    if (opts.json) { console.log(JSON.stringify(result, null, 2)); return; }

    console.log(`\nIntercepted Requests (${result.total} total):\n`);
    console.log(`  ${"ID".padEnd(6)} ${"METHOD".padEnd(8)} ${"STATUS".padEnd(8)} ${"HOST".padEnd(30)} ${"PATH".padEnd(30)} ${"MS".padEnd(6)}`);
    console.log(`  ${"─".repeat(6)} ${"─".repeat(8)} ${"─".repeat(8)} ${"─".repeat(30)} ${"─".repeat(30)} ${"─".repeat(6)}`);
    for (const r of result.requests) {
      const statusColor = r.status_code && r.status_code < 400 ? "\x1b[32m" : r.status_code && r.status_code < 500 ? "\x1b[33m" : "\x1b[31m";
      console.log(`  ${String(r.id).padEnd(6)} ${r.method.padEnd(8)} ${statusColor}${String(r.status_code || "ERR").padEnd(8)}\x1b[0m ${r.host.slice(0, 30).padEnd(30)} ${r.path.slice(0, 30).padEnd(30)} ${String(r.duration_ms).padEnd(6)}`);
    }
    console.log();
  });

proxy
  .command("inspect <id>")
  .description("View full details of an intercepted request")
  .option("--json", "Output as JSON")
  .action(async (id: string, opts: { json?: boolean }) => {
    const { getRequest } = await import("./proxy/db.js");
    const req = getRequest(parseInt(id, 10));
    if (!req) { console.error("Request not found"); process.exit(1); }

    if (opts.json) { console.log(JSON.stringify(req, null, 2)); return; }

    console.log(`\n── Request #${req.id} ──────────────────────────────`);
    console.log(`${req.method} ${req.url}`);
    console.log(`Host: ${req.host}`);
    console.log(`Time: ${req.intercepted_at} (${req.duration_ms}ms)\n`);

    console.log("── Request Headers ─────────────────────────────");
    try {
      const headers = JSON.parse(req.request_headers) as Record<string, string>;
      for (const [k, v] of Object.entries(headers)) console.log(`  ${k}: ${v}`);
    } catch {}

    if (req.request_body) {
      console.log("\n── Request Body ────────────────────────────────");
      console.log(req.request_body.slice(0, 2000));
    }

    console.log(`\n── Response (${req.status_code}) ───────────────────────────`);
    try {
      const headers = JSON.parse(req.response_headers) as Record<string, string>;
      for (const [k, v] of Object.entries(headers)) console.log(`  ${k}: ${v}`);
    } catch {}

    if (req.response_body) {
      console.log("\n── Response Body ───────────────────────────────");
      console.log(req.response_body.slice(0, 5000));
    }
    console.log();
  });

proxy
  .command("replay <id>")
  .description("Replay an intercepted request")
  .action(async (id: string) => {
    const { getRequest } = await import("./proxy/db.js");
    const req = getRequest(parseInt(id, 10));
    if (!req) { console.error("Request not found"); process.exit(1); }

    console.log(`\nReplaying: ${req.method} ${req.url}`);
    const startTime = Date.now();
    try {
      const headers = JSON.parse(req.request_headers) as Record<string, string>;
      const resp = await fetch(req.url, {
        method: req.method,
        headers,
        body: req.method !== "GET" && req.method !== "HEAD" ? req.request_body : undefined,
      });
      const body = await resp.text();
      const duration = Date.now() - startTime;
      console.log(`Status: ${resp.status} (${duration}ms, ${body.length} bytes)`);
      console.log(body.slice(0, 2000));
    } catch (err: unknown) {
      console.error(`Failed: ${err instanceof Error ? err.message : "unknown"}`);
    }
    console.log();
  });

proxy
  .command("clear")
  .description("Clear intercepted request history")
  .option("--host <host>", "Only clear requests for this host")
  .action(async (opts: { host?: string }) => {
    const { clearRequests } = await import("./proxy/db.js");
    const count = clearRequests(opts.host);
    console.log(`Cleared ${count} requests${opts.host ? ` for ${opts.host}` : ""}`);
  });

proxy
  .command("stats")
  .description("Show proxy statistics")
  .option("--json", "Output as JSON")
  .action(async (opts: { json?: boolean }) => {
    const { getProxyStats, getTopHosts } = await import("./proxy/db.js");
    const stats = getProxyStats();
    const topHosts = getTopHosts(5);
    if (opts.json) { console.log(JSON.stringify({ stats, topHosts }, null, 2)); return; }

    console.log(`\nProxy Statistics:`);
    console.log(`  Total requests: ${stats.totalRequests}`);
    console.log(`  Unique hosts:   ${stats.uniqueHosts}`);
    console.log(`  Flagged:        ${stats.flagged}`);
    console.log(`  Avg latency:    ${stats.avgDuration}ms`);
    if (topHosts.length > 0) {
      console.log(`\n  Top Hosts:`);
      for (const h of topHosts) console.log(`    ${h.host.padEnd(30)} ${h.count} requests`);
    }
    console.log();
  });

proxy
  .command("ca")
  .description("Manage CA certificate for HTTPS interception")
  .option("--generate", "Generate CA certificate")
  .option("--install", "Show installation instructions")
  .option("--path", "Show CA certificate path")
  .action(async (opts: { generate?: boolean; install?: boolean; path?: boolean }) => {
    const { generateCA, getCACertPath, hasCA, getInstallInstructions } = await import("./proxy/ca.js");
    if (opts.generate) {
      generateCA();
      console.log("CA certificate generated.");
      console.log(`Path: ${getCACertPath()}`);
      return;
    }
    if (opts.path) {
      console.log(getCACertPath());
      return;
    }
    // Default: show install instructions
    if (!hasCA()) {
      console.log("No CA certificate found. Generate one first:");
      console.log("  domain-sniper proxy ca --generate\n");
      return;
    }
    console.log(getInstallInstructions());
  });

// ─── Snipe subcommand ──────────────────────────────────

const snipeCmd = program
  .command("snipe")
  .description("Snipe domains — automatically watch, detect expiry, and register");

snipeCmd
  .command("add <domain>")
  .description("Add a domain to snipe list")
  .option("--max-price <price>", "Maximum price to pay")
  .action(async (domain: string, opts: { maxPrice?: string }) => {
    const { snipeDomain } = await import("./core/features/snipe.js");
    const { whoisLookup } = await import("./core/whois.js");

    console.log(`\nChecking ${domain}...`);
    const whois = await whoisLookup(domain);

    snipeDomain(domain, {
      expiryDate: whois.expiryDate || undefined,
      maxPrice: opts.maxPrice ? parseFloat(opts.maxPrice) : undefined,
    });

    if (whois.available) {
      console.log(`  ${domain} is ALREADY AVAILABLE — consider registering now!`);
      console.log(`  Use: domain-sniper snipe run\n`);
    } else if (whois.expired) {
      console.log(`  ${domain} is EXPIRED — snipe engine will monitor and register when it drops`);
      if (whois.expiryDate) console.log(`  Expiry: ${whois.expiryDate}`);
    } else {
      console.log(`  ${domain} is currently registered`);
      if (whois.expiryDate) {
        const daysLeft = Math.floor((new Date(whois.expiryDate).getTime() - Date.now()) / 86400000);
        console.log(`  Expires: ${whois.expiryDate} (${daysLeft} days)`);
      }
      console.log(`  Snipe engine will watch for expiry and auto-register when it drops`);
    }
    console.log(`\nStart the snipe engine: domain-sniper snipe run\n`);
  });

snipeCmd
  .command("remove <domain>")
  .description("Remove a domain from snipe list")
  .action(async (domain: string) => {
    const { cancelSnipe } = await import("./core/features/snipe.js");
    cancelSnipe(domain);
    console.log(`Removed ${domain} from snipe list`);
  });

snipeCmd
  .command("list")
  .description("Show all snipe targets")
  .option("--json", "Output as JSON")
  .action(async (opts: { json?: boolean }) => {
    const { getSnipeTargets } = await import("./core/features/snipe.js");
    const { getSnipeStats } = await import("./core/db.js");
    const targets = getSnipeTargets();
    const stats = getSnipeStats();

    if (opts.json) { console.log(JSON.stringify({ targets, stats }, null, 2)); return; }

    console.log(`\nSnipe Targets (${stats.total} total — ${stats.watching} watching, ${stats.expiring} expiring, ${stats.dropping} dropping, ${stats.registered} registered):\n`);
    if (targets.length === 0) { console.log("  No active snipe targets. Add one: domain-sniper snipe add example.com\n"); return; }

    console.log(`  ${"DOMAIN".padEnd(30)} ${"STATUS".padEnd(12)} ${"PHASE".padEnd(12)} ${"CHECKS".padEnd(8)} LAST CHECK`);
    console.log(`  ${"─".repeat(30)} ${"─".repeat(12)} ${"─".repeat(12)} ${"─".repeat(8)} ${"─".repeat(20)}`);
    for (const t of targets) {
      const statusColor = t.status === "dropping" ? "\x1b[31m" : t.status === "expiring" ? "\x1b[33m" : "\x1b[90m";
      console.log(`  ${t.domain.padEnd(30)} ${statusColor}${t.status.padEnd(12)}\x1b[0m ${t.phase.padEnd(12)} ${String(t.checkCount).padEnd(8)} ${t.lastChecked || "never"}`);
    }
    console.log();
  });

snipeCmd
  .command("run")
  .description("Start the snipe engine (runs in foreground)")
  .action(async () => {
    const { createSnipeEngine, getSnipeTargets } = await import("./core/features/snipe.js");
    const targets = getSnipeTargets();

    if (targets.length === 0) {
      console.error("No snipe targets. Add one first: domain-sniper snipe add example.com");
      process.exit(1);
    }

    console.log(`\n◆ Snipe Engine Starting — ${targets.length} target(s)\n`);
    for (const t of targets) {
      console.log(`  ${t.domain.padEnd(30)} ${t.status.padEnd(12)} ${t.phase}`);
    }
    console.log(`\nPhases: hourly (registered) → frequent/5min (expired) → aggressive/30s (pending delete)`);
    console.log("Press Ctrl+C to stop\n");

    const engine = createSnipeEngine({
      onStatusChange: (domain, status, phase, message) => {
        const ts = new Date().toISOString().slice(11, 19);
        const color = status === "registered" ? "\x1b[32m" : status === "dropping" ? "\x1b[31m" : status === "expiring" ? "\x1b[33m" : "\x1b[90m";
        console.log(`  ${ts} ${color}[${status}/${phase}]\x1b[0m ${message}`);
      },
      onRegistered: (domain) => {
        console.log(`\n  ★ SUCCESS — ${domain} has been REGISTERED!\n`);
      },
      onFailed: (domain, error) => {
        console.log(`\n  ✗ FAILED — ${domain}: ${error}\n`);
      },
    });

    await engine.start();

    // Keep running
    process.on("SIGINT", () => {
      console.log("\nStopping snipe engine...");
      engine.stop();
      process.exit(0);
    });
  });

snipeCmd
  .command("stats")
  .description("Show snipe statistics")
  .option("--json", "Output as JSON")
  .action(async (opts: { json?: boolean }) => {
    const { getSnipeStats, getAllSnipes } = await import("./core/db.js");
    const stats = getSnipeStats();
    const all = getAllSnipes();
    if (opts.json) { console.log(JSON.stringify({ stats, snipes: all }, null, 2)); return; }

    console.log(`\nSnipe Stats:`);
    console.log(`  Watching:    ${stats.watching}`);
    console.log(`  Expiring:    ${stats.expiring}`);
    console.log(`  Dropping:    ${stats.dropping}`);
    console.log(`  Registered:  ${stats.registered}`);
    console.log(`  Failed:      ${stats.failed}`);
    console.log(`  Total:       ${stats.total}\n`);
  });

// ─── Check-update subcommand ────────────────────────────

program
  .command("check-update")
  .description("Check for newer versions")
  .action(async () => {
    const { checkForUpdates, formatUpdateMessage } = await import("./core/features/version-check.js");
    console.log("Checking for updates...");
    const result = await checkForUpdates();
    if (result.updateAvailable && result.latest) {
      console.log(formatUpdateMessage(result.current, result.latest));
    } else {
      console.log(`You're on the latest version (${result.current})`);
    }
  });

// ─── Update subcommand ──────────────────────────────────

program
  .command("update")
  .description("Update domsniper to the latest version")
  .action(async () => {
    const { checkForUpdates } = await import("./core/features/version-check.js");
    const result = await checkForUpdates();

    if (!result.updateAvailable || !result.latest) {
      console.log(`Already on the latest version (${result.current})`);
      return;
    }

    console.log(`Updating: ${result.current} → ${result.latest}`);

    const { execSync } = await import("child_process");
    try {
      // Try bun first, then npm
      try {
        execSync("bun add -g domsniper@latest", { stdio: "inherit" });
      } catch {
        execSync("npm install -g domsniper@latest", { stdio: "inherit" });
      }
      console.log(`\nUpdated to domsniper@${result.latest}`);
    } catch (err: unknown) {
      console.error("Update failed. Try manually:");
      console.error("  bun add -g domsniper@latest");
      console.error("  # or: npm install -g domsniper@latest");
      process.exit(1);
    }
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

  const { whoisLookup, verifyAvailability, parseDomainList } = await import("./core/whois.js");
  const { loadConfigFromEnv, checkAvailabilityViaRegistrar, registerDomain } = await import("./core/registrar.js");
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

  // Auto-detect and correct TLD typos before sanitization
  const rawList = [...domainList];
  domainList = domainList.map((d) => {
    const suggestion = detectTldTypo(d);
    if (suggestion) {
      console.error(`  Typo? "${d}" → auto-corrected to "${suggestion}"`);
      return suggestion;
    }
    return d;
  });

  const rawCount = domainList.length;
  domainList = sanitizeDomainList(domainList);

  // Deduplicate
  const beforeDedup = domainList.length;
  domainList = [...new Set(domainList)];
  if (domainList.length < beforeDedup) {
    console.error(`  Removed ${beforeDedup - domainList.length} duplicate(s)`);
  }

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
    const { closeDb } = await import("./core/db.js");
    closeDb();
  } catch {}
}
