#!/usr/bin/env bun
import { createCliRenderer } from "@opentui/core";
import { createRoot } from "@opentui/react";
import { App } from "./app.js";
import { Command } from "commander";

const program = new Command();

program
  .name("domain-sniper")
  .description("Check domain availability, detect expired domains, and auto-register them")
  .version("1.0.0")
  .argument("[domains...]", "Domain(s) to check")
  .option("-f, --file <path>", "Path to file with domains (one per line)")
  .option("-a, --auto-register", "Automatically register available domains", false)
  .option("--headless", "Run in non-interactive mode (print results to stdout)", false)
  .action(async (domains: string[], options: any) => {
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

program.parse();

// ─── Headless / non-interactive mode ──────────────────────

async function runHeadless(domains: string[], options: any) {
  const { whoisLookup, verifyAvailability, parseDomainList } = await import("./whois.js");
  const { loadConfigFromEnv, checkAvailabilityViaRegistrar, registerDomain } = await import("./registrar.js");
  const { readFileSync, existsSync } = await import("fs");

  let domainList = [...domains];

  // Load from file if specified
  if (options.file) {
    if (!existsSync(options.file)) {
      console.error(`File not found: ${options.file}`);
      process.exit(1);
    }
    const content = readFileSync(options.file, "utf-8");
    domainList.push(...parseDomainList(content));
  }

  if (domainList.length === 0) {
    console.error("No domains specified. Use: domain-sniper example.com or -f domains.txt");
    process.exit(1);
  }

  const config = loadConfigFromEnv();

  console.log(`\n🔍 Domain Sniper - Checking ${domainList.length} domain(s)...\n`);

  for (const domain of domainList) {
    process.stdout.write(`  Checking ${domain}...`);

    const whois = await whoisLookup(domain);
    const verification = await verifyAvailability(domain);

    let status = "TAKEN";
    let color = "\x1b[31m"; // red

    if (whois.available && verification.confidence === "high") {
      status = "AVAILABLE";
      color = "\x1b[32m"; // green
    } else if (whois.expired) {
      status = "EXPIRED";
      color = "\x1b[33m"; // yellow
    } else if (whois.available) {
      status = `AVAILABLE (${verification.confidence} confidence)`;
      color = "\x1b[32m";
    }

    console.log(`\r  ${color}${status}\x1b[0m  ${domain}`);

    // Verification details
    for (const check of verification.checks) {
      console.log(`    ${check}`);
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

    // Rate limit between lookups
    if (domainList.indexOf(domain) < domainList.length - 1) {
      await new Promise((r) => setTimeout(r, 1500));
    }
  }

  console.log("Done!\n");
}
