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

const program = new Command();

program
  .name("domain-sniper")
  .description("Check domain availability, detect expired domains, and auto-register them")
  .version("1.0.0")
  .argument("[domains...]", "Domain(s) to check")
  .option("-f, --file <path>", "Path to file with domains (one per line)")
  .option("-a, --auto-register", "Automatically register available domains", false)
  .option("--headless", "Run in non-interactive mode (print results to stdout)", false)
  .option("--json", "Output results as JSON", false)
  .option("-c, --concurrency <n>", "Concurrent lookups (default: 5)", "5")
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

program.parse();

// ─── Types ───────────────────────────────────────────────

interface CliOptions {
  file?: string;
  autoRegister: boolean;
  headless: boolean;
  json: boolean;
  concurrency: string;
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
}

interface JsonOutput {
  timestamp: string;
  count: number;
  results: JsonOutputResult[];
}

// ─── Headless / non-interactive mode ──────────────────────

async function runHeadless(domains: string[], options: CliOptions) {
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

  domainList = sanitizeDomainList(domainList);

  if (domainList.length === 0) {
    console.error("No domains specified. Use: domain-sniper example.com or -f domains.txt");
    process.exit(1);
  }

  const config = loadConfigFromEnv();
  const isJsonMode = options.json;

  // JSON mode: collect results
  const jsonResults: JsonOutputResult[] = [];

  if (!isJsonMode) {
    console.log(`\n🔍 Domain Sniper - Checking ${domainList.length} domain(s)...\n`);
  }

  for (const domain of domainList) {
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
    }

    // Rate limit between lookups
    if (domainList.indexOf(domain) < domainList.length - 1) {
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
  } else {
    console.log("Done!\n");
  }
}
