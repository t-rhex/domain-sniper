import { useState, useEffect, useCallback, useRef, useMemo } from "react";
import { useKeyboard, useRenderer, useTerminalDimensions } from "@opentui/react";
import { whoisLookup, verifyAvailability, parseDomainList, type WhoisResult } from "./core/whois.js";
import {
  checkAvailabilityViaRegistrar, registerDomain, loadConfigFromEnv,
  type RegistrarConfig, type RegistrationResult,
} from "./core/registrar.js";
import { readFileSync, existsSync } from "fs";
import { theme, borders, statusStyle, type DomainStatus } from "./core/theme.js";
import type { DomainEntry } from "./core/types.js";
import { createEmptyEntry } from "./core/types.js";
import { sanitizeDomainList, safePath } from "./core/validate.js";
import { lookupDns } from "./core/features/dns-details.js";
import { httpProbe } from "./core/features/http-probe.js";
import { checkWayback } from "./core/features/wayback.js";
import { calculateDomainAge, daysUntilExpiry } from "./core/features/domain-age.js";
import { expandTlds, type TldPreset } from "./core/features/tld-expand.js";
import { generateVariations } from "./core/features/variations.js";
import { scoreDomain, scoreGrade } from "./core/features/scoring.js";
import { exportToCSV, exportToJSON } from "./core/features/export.js";
import { DomainWatcher, formatInterval } from "./core/features/watch.js";
import { saveSession, loadSession, listSessions } from "./core/features/session.js";
import { filterDomains, nextStatus, nextSort, DEFAULT_FILTER, type FilterConfig, type FilterStatus, type SortField } from "./core/features/filter.js";
import { rdapLookup } from "./core/features/rdap.js";
import { checkSsl } from "./core/features/ssl-check.js";
import { discoverSubdomains, getActiveSubdomains } from "./core/features/subdomain-discovery.js";
import { checkMarketplaces } from "./core/features/marketplace.js";
import { sendWebhook } from "./core/features/webhooks.js";
import { loadConfig } from "./core/features/config.js";
import { generateSuggestions } from "./core/features/domain-suggest.js";
import { addToPortfolio } from "./core/features/portfolio.js";
import { snipeDomain, getSnipeTargets, cancelSnipe } from "./core/features/snipe.js";
import {
  isLoggedIn, getAuthInfo, browseListings, viewListing,
  createListingApi, makeOffer, getMyListings, getMyOffers,
  getMarketStatsApi, getUnreadApi, getServerUrl,
} from "./market-client.js";
import { checkSocialMedia, getAvailablePlatforms } from "./core/features/social-check.js";
import { detectTechStack } from "./core/features/tech-stack.js";
import { checkBlacklists } from "./core/features/blacklist-check.js";
import { estimateBacklinks } from "./core/features/backlinks.js";
import { saveWhoisSnapshot, getLatestDiff, getHistoryCount } from "./core/features/whois-history.js";
import { createDropCatcher, formatDropCatchStatus, type DropCatchStatus } from "./core/features/drop-catch.js";
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
import { upsertDomain, saveScan, getCached, setCache, clearCache, getScanHistory, getDomainByName, createSession as dbCreateSession, updateSessionCount, getDbStats, getAllDomains, getPortfolioExpiring } from "./core/db.js";
import { getPortfolioDashboard, getUnacknowledgedAlerts, acknowledgeAllAlerts, getMonthlyReport, addTransaction, updatePortfolioStatus, getCategories, getSnipeStats, type PortfolioStatus, type TransactionType } from "./core/db.js";
import { generateRenewalCalendar, estimateAnnualRenewalCost } from "./core/features/portfolio-monitor.js";

// ─── Types ────────────────────────────────────────────────

type Mode = "idle" | "input" | "scanning" | "done" | "watching";
type InputMode = "domain" | "file" | "expand" | "variations" | "export" | "load";

interface AppProps {
  initialDomains?: string[];
  batchFile?: string;
  autoRegister?: boolean;
}

function pad(s: string, len: number): string {
  return s.length >= len ? s.slice(0, len) : s + " ".repeat(len - s.length);
}

function ts(): string {
  const d = new Date();
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
}

// ─── Main App ─────────────────────────────────────────────

type IntelTab = "overview" | "dns" | "security" | "recon";

export function App({ initialDomains, batchFile, autoRegister = false }: AppProps) {
  const [mode, setMode] = useState<Mode>(initialDomains?.length || batchFile ? "scanning" : "idle");
  const [inputMode, setInputMode] = useState<InputMode>("domain");
  const [domains, setDomains] = useState<DomainEntry[]>([]);
  const [inputValue, setInputValue] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [showHelp, setShowHelp] = useState(false);
  const [showPortfolio, setShowPortfolio] = useState(false);
  const [filter, setFilter] = useState<FilterConfig>({ ...DEFAULT_FILTER });
  const [logs, setLogs] = useState<{ id: number; time: string; msg: string; fg: string }[]>([
    { id: 0, time: ts(), msg: "Domain Sniper v2.0 initialized", fg: theme.textMuted },
    { id: 1, time: ts(), msg: "Press ? for all commands", fg: theme.textMuted },
  ]);
  const [registrarConfig] = useState<RegistrarConfig | null>(loadConfigFromEnv());
  const [reconMode, setReconMode] = useState(false);
  const [watcher, setWatcher] = useState<DomainWatcher | null>(null);
  const [watchCycle, setWatchCycle] = useState(0);
  const [intelTab, setIntelTab] = useState<IntelTab>("overview");
  const [scanProgress, setScanProgress] = useState<{ current: number; total: number } | null>(null);
  const [confirmBulkRegister, setConfirmBulkRegister] = useState(false);

  // Marketplace state
  const [showMarket, setShowMarket] = useState(false);
  const [marketListings, setMarketListings] = useState<any[]>([]);
  const [marketTotal, setMarketTotal] = useState(0);
  const [marketSelectedIdx, setMarketSelectedIdx] = useState(0);
  const [marketSearch, setMarketSearch] = useState("");
  const [marketLoading, setMarketLoading] = useState(false);
  const [marketView, setMarketView] = useState<"browse" | "my-listings" | "my-offers" | "detail">("browse");
  const [marketDetail, setMarketDetail] = useState<any | null>(null);
  const [marketUnread, setMarketUnread] = useState(0);
  const [marketInputMode, setMarketInputMode] = useState<"none" | "search" | "list-price" | "offer-amount" | "offer-message">("none");
  const [marketInputValue, setMarketInputValue] = useState("");
  const [marketListDomain, setMarketListDomain] = useState("");

  const { width, height } = useTerminalDimensions();
  const renderer = useRenderer();
  const processingRef = useRef(false);
  const domainsCountRef = useRef(0);
  const logIdRef = useRef(2);
  const appConfig = useRef(loadConfig());

  useEffect(() => { domainsCountRef.current = domains.length; }, [domains.length]);

  // ─── Log ────────────────────────────────────────────────

  const log = useCallback((msg: string, fg: string = theme.textSecondary) => {
    const id = logIdRef.current++;
    setLogs((prev) => [...prev.slice(-80), { id, time: ts(), msg, fg }]);
  }, []);

  // ─── Domain Processing ──────────────────────────────────

  const processDomain = useCallback(async (domain: string): Promise<DomainEntry> => {
    // Check cache first (5-minute TTL for regular, skip for recon)
    if (!reconMode) {
      const cached = getCached(domain, "scan");
      if (cached) {
        try {
          const entry = JSON.parse(cached) as DomainEntry;
          log(`↻ CACHED ${domain}`, theme.textDisabled);
          return entry;
        } catch {}
      }
    }

    const entry: DomainEntry = {
      ...createEmptyEntry(domain),
      status: "checking",
    };
    try {
      const whois = await whoisLookup(domain);
      entry.whois = whois;
      if (whois.error) { entry.status = "error"; entry.error = whois.error; log(`ERR ${domain}: ${whois.error}`, theme.error); return entry; }

      const verification = await verifyAvailability(domain);
      entry.verification = verification;

      if (registrarConfig?.apiKey) {
        try {
          const regCheck = await checkAvailabilityViaRegistrar(domain, registrarConfig);
          entry.registrarCheck = { available: regCheck.available, price: regCheck.price, currency: regCheck.currency };
        } catch (err: unknown) {
          log(`REG check failed: ${err instanceof Error ? err.message : "unknown"}`, theme.warning);
        }
      }

      if (whois.available && verification.confidence === "high") { entry.status = "available"; log(`● AVAIL ${domain} [${verification.confidence}]`, theme.primary); }
      else if (whois.expired) { entry.status = "expired"; log(`◈ EXPRD ${domain}`, theme.pending); }
      else if (whois.available) { entry.status = "available"; log(`● AVAIL ${domain} [${verification.confidence}]`, theme.primary); }
      else { entry.status = "taken"; log(`✕ TAKEN ${domain}`, theme.textDisabled); }

      // New features — run in parallel, don't block on failures
      const [dns, probe, wayback, rdap, ssl, subdomains, marketplace, social, techStack, blacklist, backlinks] = await Promise.all([
        lookupDns(domain).catch(() => null),
        httpProbe(domain).catch(() => null),
        checkWayback(domain).catch(() => null),
        rdapLookup(domain).catch(() => null),
        checkSsl(domain).catch(() => null),
        discoverSubdomains(domain).catch(() => null),
        checkMarketplaces(domain).catch(() => null),
        checkSocialMedia(domain).catch(() => null),
        detectTechStack(domain).catch(() => null),
        checkBlacklists(domain).catch(() => null),
        estimateBacklinks(domain).catch(() => null),
      ]);
      entry.dns = dns;
      entry.httpProbe = probe;
      entry.wayback = wayback;
      entry.rdap = rdap;
      entry.ssl = ssl;
      entry.subdomains = subdomains;
      entry.marketplace = marketplace;
      entry.socialMedia = social;
      entry.techStack = techStack;
      entry.blacklist = blacklist;
      entry.backlinks = backlinks;
      entry.domainAge = calculateDomainAge(entry.whois?.createdDate ?? null);

      // Recon features — only run in recon mode
      if (reconMode) {
        const [ports, reverseIp, asn, emailSec, zoneXfer, certs, takeover, secHeaders, waf, paths, cors] = await Promise.all([
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
        entry.portScan = ports;
        entry.reverseIp = reverseIp;
        entry.asn = asn;
        entry.emailSecurity = emailSec;
        entry.zoneTransfer = zoneXfer;
        entry.certTransparency = certs;
        entry.takeover = takeover;
        entry.securityHeaders = secHeaders;
        entry.waf = waf;
        entry.pathScan = paths;
        entry.cors = cors;
      }

      // Save WHOIS snapshot for history tracking
      if (entry.whois && !entry.whois.error) {
        try { saveWhoisSnapshot(entry.whois); } catch {}
      }

      // Send webhook notification if configured
      if ((entry.status === "available" || entry.status === "expired")) {
        const cfg = appConfig.current;
        if (cfg.notifications.webhookUrl) {
          void sendWebhook(cfg.notifications.webhookUrl, {
            domain: entry.domain,
            status: entry.status,
            timestamp: new Date().toISOString(),
          }).catch(() => {});
        }
      }

      // Save to cache (5 min TTL) and database
      setCache(domain, "scan", JSON.stringify(entry), 5);
      try {
        const domainId = upsertDomain(domain);
        const score = scoreDomain(domain);
        saveScan(domainId, entry.status, entry, undefined, score.total);
      } catch {}

      return entry;
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown error";
      entry.status = "error"; entry.error = message;
      log(`ERR ${domain}: ${message}`, theme.error);
      return entry;
    }
  }, [registrarConfig, reconMode, log]);

  const processAllDomains = useCallback(async (domainList: string[], append = false) => {
    if (processingRef.current) return;
    processingRef.current = true;
    setMode("scanning");

    let sessionId: number | undefined;
    try { sessionId = dbCreateSession(); } catch {}

    const entries: DomainEntry[] = domainList.map((d) => createEmptyEntry(d));

    if (append) {
      setDomains((prev: DomainEntry[]) => [...prev, ...entries]);
    } else {
      setDomains(entries);
    }

    const startIdx = append ? domainsCountRef.current : 0;
    log(`━━━ Scanning ${domainList.length} domain${domainList.length > 1 ? "s" : ""} ━━━`, theme.info);
    setScanProgress({ current: 0, total: domainList.length });

    // Concurrent pool
    const CONCURRENCY = 5;
    let nextIdx = 0;

    async function worker() {
      while (nextIdx < entries.length) {
        const i = nextIdx++;
        const globalIdx = startIdx + i;
        setDomains((prev: DomainEntry[]) => {
          const u = [...prev];
          if (u[globalIdx]) u[globalIdx] = { ...u[globalIdx]!, status: "checking" };
          return u;
        });

        const result = await processDomain(domainList[i]!);
        setDomains((prev: DomainEntry[]) => { const u = [...prev]; u[globalIdx] = result; return u; });
        setScanProgress((prev) => prev ? { ...prev, current: prev.current + 1 } : null);

        if (autoRegister && registrarConfig?.apiKey && (result.status === "available" || result.status === "expired")) {
          setDomains((prev: DomainEntry[]) => {
            const u = [...prev];
            if (u[globalIdx]) u[globalIdx] = { ...u[globalIdx]!, status: "registering" };
            return u;
          });
          try {
            const regResult = await registerDomain(domainList[i]!, registrarConfig);
            setDomains((prev: DomainEntry[]) => {
              const u = [...prev];
              if (u[globalIdx]) u[globalIdx] = { ...u[globalIdx]!, status: regResult.success ? "registered" : u[globalIdx]!.status, registration: regResult };
              return u;
            });
            if (regResult.success) log(`★ REG'd ${domainList[i]}`, theme.secondary);
          } catch (err: unknown) {
            log(`REG failed: ${err instanceof Error ? err.message : "unknown"}`, theme.error);
          }
        }

        // Rate limit per worker
        await new Promise((r) => setTimeout(r, 500));
      }
    }

    const workers = Array.from(
      { length: Math.min(CONCURRENCY, domainList.length) },
      () => worker()
    );
    await Promise.all(workers);

    try { if (sessionId) updateSessionCount(sessionId, domainList.length); } catch {}

    processingRef.current = false;
    setScanProgress(null);
    setMode("done");
    log("━━━ Scan complete ━━━", theme.info);
  }, [autoRegister, registrarConfig, processDomain, log]);

  // ─── Marketplace loaders ────────────────────────────────

  const loadMarketListings = useCallback(async (search?: string) => {
    setMarketLoading(true);
    try {
      const result = await browseListings({ search, limit: 50, sort: "newest" });
      if (result.ok) {
        setMarketListings(result.data.listings);
        setMarketTotal(result.data.total);
      }
    } catch {}
    setMarketLoading(false);
  }, []);

  const loadMyListings = useCallback(async () => {
    setMarketLoading(true);
    try {
      const result = await getMyListings();
      if (result.ok) { setMarketListings(result.data); setMarketTotal(result.data.length); }
    } catch {}
    setMarketLoading(false);
  }, []);

  const loadMyOffers = useCallback(async () => {
    setMarketLoading(true);
    try {
      const result = await getMyOffers("buyer");
      const result2 = await getMyOffers("seller");
      if (result.ok && result2.ok) {
        const all = [...result.data, ...result2.data];
        setMarketListings(all);
        setMarketTotal(all.length);
      }
    } catch {}
    setMarketLoading(false);
  }, []);

  // Check unread count periodically
  useEffect(() => {
    if (!isLoggedIn()) return;
    const checkUnread = async () => {
      try {
        const r = await getUnreadApi();
        if (r.ok) setMarketUnread(r.data.count);
      } catch {}
    };
    checkUnread();
    const interval = setInterval(checkUnread, 60000);
    return () => clearInterval(interval);
  }, []);

  // ─── Init ───────────────────────────────────────────────

  useEffect(() => {
    if (batchFile && existsSync(batchFile)) {
      const content = readFileSync(batchFile, "utf-8");
      const list = parseDomainList(content);
      if (list.length > 0) processAllDomains(list);
    } else if (initialDomains?.length) {
      processAllDomains(initialDomains);
    }
  }, []);

  // ─── Filtered domains ──────────────────────────────────

  const filteredDomains = useMemo(() => filterDomains(domains, filter), [domains, filter]);
  const selected = filteredDomains[selectedIndex] || null;

  // ─── Keyboard ───────────────────────────────────────────

  useKeyboard((e) => {
    const key = e.name;
    const ctrl = e.ctrl;

    if (ctrl && key === "c") { watcher?.stop(); renderer.destroy(); process.exit(0); }
    if (key === "q" && mode !== "input") { watcher?.stop(); renderer.destroy(); process.exit(0); }

    // Toggle help
    if (key === "?" && mode !== "input") { setShowHelp((v) => !v); return; }
    if (showHelp && key === "escape") { setShowHelp(false); return; }
    if (showHelp) return; // Consume all keys while help is shown

    // Toggle portfolio dashboard
    if (key === "P" && mode !== "input") { setShowPortfolio((v) => !v); return; }
    if (showPortfolio && key === "escape") { setShowPortfolio(false); return; }

    // ── Marketplace toggle ──
    if (key === "M" && mode !== "input" && !showPortfolio) {
      if (!showMarket) {
        setShowMarket(true);
        setMarketView("browse");
        setMarketSelectedIdx(0);
        void loadMarketListings();
      } else {
        setShowMarket(false);
        setMarketInputMode("none");
      }
      return;
    }

    // ── Marketplace keyboard controls (when market is open) ──
    if (showMarket) {
      // Close marketplace
      if (key === "escape") {
        if (marketInputMode !== "none") {
          setMarketInputMode("none");
          setMode(domains.length > 0 ? "done" : "idle");
        } else if (marketView === "detail") {
          setMarketView("browse");
          setMarketDetail(null);
        } else {
          setShowMarket(false);
        }
        return;
      }

      // Marketplace input mode
      if (marketInputMode !== "none") {
        return; // Let the input component handle it
      }

      // Navigation
      if (key === "up" || key === "k") { setMarketSelectedIdx((i) => Math.max(0, i - 1)); return; }
      if (key === "down" || key === "j") { setMarketSelectedIdx((i) => Math.min(marketListings.length - 1, i + 1)); return; }

      // View listing detail
      if (key === "return" && marketListings[marketSelectedIdx]) {
        const item = marketListings[marketSelectedIdx];
        if (marketView === "browse" && item.id) {
          setMarketLoading(true);
          viewListing(item.id).then((r) => {
            if (r.ok) { setMarketDetail(r.data); setMarketView("detail"); }
            setMarketLoading(false);
          });
        }
        return;
      }

      // Search
      if (key === "/" && marketView === "browse") {
        setMarketInputMode("search");
        setMarketInputValue(marketSearch);
        setMode("input");
        setInputValue("");
        return;
      }

      // Switch views
      if (key === "1") { setMarketView("browse"); setMarketSelectedIdx(0); void loadMarketListings(marketSearch); return; }
      if (key === "2" && isLoggedIn()) { setMarketView("my-listings"); setMarketSelectedIdx(0); void loadMyListings(); return; }
      if (key === "3" && isLoggedIn()) { setMarketView("my-offers"); setMarketSelectedIdx(0); void loadMyOffers(); return; }

      // List selected domain for sale (from scan results)
      if (key === "l" && selected && isLoggedIn() && marketView !== "detail") {
        setMarketListDomain(selected.domain);
        setMarketInputMode("list-price");
        setMode("input");
        setInputValue("");
        log(`Enter asking price for ${selected.domain}`, theme.info);
        return;
      }

      // Make offer on selected listing
      if (key === "o" && marketView === "detail" && marketDetail && isLoggedIn()) {
        setMarketInputMode("offer-amount");
        setMode("input");
        setInputValue("");
        return;
      }

      // Back from detail
      if (key === "backspace" && marketView === "detail") {
        setMarketView("browse");
        setMarketDetail(null);
        return;
      }

      // Refresh
      if (key === "r") {
        if (marketView === "browse") void loadMarketListings(marketSearch);
        else if (marketView === "my-listings") void loadMyListings();
        else if (marketView === "my-offers") void loadMyOffers();
        return;
      }

      return; // Consume all other keys while market is open
    }

    // ── Tab switching for INTEL panel (Issue 1) ──
    if (key === "tab" && mode !== "input") {
      const tabs: IntelTab[] = ["overview", "dns", "security", "recon"];
      setIntelTab((current) => {
        const idx = tabs.indexOf(current);
        return tabs[(idx + 1) % tabs.length]!;
      });
      return;
    }
    if ((key === "backtick" || (e.shift && key === "tab")) && mode !== "input") {
      const tabs: IntelTab[] = ["overview", "dns", "security", "recon"];
      setIntelTab((current) => {
        const idx = tabs.indexOf(current);
        return tabs[(idx - 1 + tabs.length) % tabs.length]!;
      });
      return;
    }

    // Cancel bulk register on any other key
    if (confirmBulkRegister && key !== "R") {
      setConfirmBulkRegister(false);
    }

    // ── Input triggers ──
    if (mode !== "input" && mode !== "scanning") {
      if (key === "/" || key === "i") { setInputMode("domain"); setMode("input"); setInputValue(""); return; }
      if (key === "f") { setInputMode("file"); setMode("input"); setInputValue(""); log("Enter file path...", theme.textMuted); return; }
      if (key === "e") { setInputMode("expand"); setMode("input"); setInputValue(""); log("Enter base name for TLD expansion...", theme.textMuted); return; }
      if (key === "v" && selected) {
        // Generate variations for selected domain
        const vars = generateVariations(selected.domain);
        log(`Generated ${vars.length} variations of ${selected.domain}`, theme.info);
        if (vars.length > 0) processAllDomains(vars, true);
        return;
      }
      if (key === "x") { setInputMode("export"); setMode("input"); setInputValue(""); log("Enter export path (.csv or .json)...", theme.textMuted); return; }
    }

    // ── Input mode ──
    if (mode === "input") {
      if (key === "escape") { setMode(domains.length > 0 ? "done" : "idle"); return; }
      return;
    }

    // ── Navigation ──
    if (mode === "scanning" || mode === "done" || mode === "watching") {
      if (key === "up" || key === "k" || (ctrl && key === "p")) setSelectedIndex((i: number) => Math.max(0, i - 1));
      else if (key === "down" || key === "j" || (ctrl && key === "n")) setSelectedIndex((i: number) => Math.min(filteredDomains.length - 1, i + 1));
      else if (key === "pageup") setSelectedIndex((i: number) => Math.max(0, i - 10));
      else if (key === "pagedown") setSelectedIndex((i: number) => Math.min(filteredDomains.length - 1, i + 10));
      else if (key === "home" || key === "g") setSelectedIndex(0);
      else if (key === "end") setSelectedIndex(Math.max(0, filteredDomains.length - 1));

      // Register (Issue 5: feedback on all statuses)
      else if (key === "r" && selected) {
        if ((selected.status === "available" || selected.status === "expired") && registrarConfig?.apiKey) {
          void handleRegister(domains.indexOf(selected));
        } else if (!registrarConfig?.apiKey) {
          log("No registrar configured. Set REGISTRAR_PROVIDER and REGISTRAR_API_KEY in .env", theme.warning);
        } else {
          log(`Cannot register ${selected.domain} (status: ${selected.status})`, theme.warning);
        }
      }

      // Bulk register tagged (Issue 7: two-step confirmation)
      else if (key === "R") {
        const tagged = domains.filter((d) => d.tagged && (d.status === "available" || d.status === "expired"));
        if (!registrarConfig?.apiKey) {
          log("No registrar configured", theme.warning);
        } else if (tagged.length === 0) {
          log("Tag domains with SPACE first, then R to bulk register", theme.warning);
        } else if (!confirmBulkRegister) {
          setConfirmBulkRegister(true);
          log(`⚠ CONFIRM: Press R again to register ${tagged.length} domain(s) via ${registrarConfig.provider}`, theme.warning);
          setTimeout(() => setConfirmBulkRegister(false), 5000);
        } else {
          setConfirmBulkRegister(false);
          log(`Bulk registering ${tagged.length} domains...`, theme.info);
          const registerPromises = tagged.map((d) => handleRegister(domains.indexOf(d)));
          void Promise.allSettled(registerPromises);
        }
      }

      // Tag/untag
      else if (key === "space" && selected) {
        setDomains((prev: DomainEntry[]) => {
          const u = [...prev];
          const idx = u.indexOf(selected);
          if (idx >= 0) u[idx] = { ...u[idx]!, tagged: !u[idx]!.tagged };
          return u;
        });
        setSelectedIndex((i: number) => Math.min(filteredDomains.length - 1, i + 1));
      }

      // Filter: cycle status
      else if (key === "s") {
        setFilter((f: FilterConfig) => ({ ...f, status: nextStatus(f.status) }));
        setSelectedIndex(0);
      }

      // Sort: cycle field
      else if (key === "o") {
        setFilter((f: FilterConfig) => ({ ...f, sort: nextSort(f.sort) }));
        setSelectedIndex(0);
      }

      // Sort: toggle order
      else if (key === "O") {
        setFilter((f: FilterConfig) => ({ ...f, order: f.order === "asc" ? "desc" : "asc" }));
      }

      // Watch mode
      else if (key === "w") {
        if (watcher?.running) {
          watcher.stop();
          setMode("done");
          log("Watch stopped", theme.warning);
        } else {
          const watchDomains = domains.filter((d) => d.tagged).map((d) => d.domain);
          if (watchDomains.length === 0) {
            log("Tag domains with SPACE first, then w to watch", theme.warning);
          } else {
            const w = new DomainWatcher({
              domains: watchDomains,
              intervalMs: 3600000,
              notify: true,
              onCheck: (domain, status) => log(`[watch] ${domain}: ${status}`, status === "available" ? theme.primary : theme.textMuted),
              onCycle: (cycle) => { setWatchCycle(cycle); log(`━━━ Watch cycle #${cycle} ━━━`, theme.info); },
              onAvailable: (domain) => log(`🔔 ${domain} is AVAILABLE!`, theme.primary),
            });
            setWatcher(w);
            w.start();
            setMode("watching");
            log(`Watching ${watchDomains.length} domains (1h interval)`, theme.info);
          }
        }
      }

      // Domain suggestions (Issue 6: deduplicate)
      else if (key === "d" && selected) {
        const name = selected.domain.split(".")[0] || "";
        const suggestions = generateSuggestions(name);
        const existingDomains = new Set(domains.map((d) => d.domain));
        const newSuggestions = suggestions.filter((s) => !existingDomains.has(s.domain)).slice(0, 15);
        if (newSuggestions.length > 0) {
          log(`Generated ${newSuggestions.length} new suggestions from "${name}"`, theme.info);
          processAllDomains(newSuggestions.map((s) => s.domain), true);
        } else {
          log(`All suggestions for "${name}" already in list`, theme.textMuted);
        }
      }

      // Drop catch mode
      else if (key === "D" && selected && registrarConfig?.apiKey) {
        if (selected.status === "expired" || selected.whois?.expired) {
          const catcher = createDropCatcher({
            domain: selected.domain,
            registrarConfig: registrarConfig!,
            pollIntervalMs: 30000,
            maxAttempts: 2880,
            onStatus: (status: DropCatchStatus) => log(formatDropCatchStatus(status), status.phase === "success" ? theme.primary : status.phase === "failed" ? theme.error : theme.info),
            onSuccess: (d: string) => log(`DROP CAUGHT: ${d}!`, theme.primary),
            onFailed: (d: string, err: string) => log(`Drop catch failed for ${d}: ${err}`, theme.error),
          });
          catcher.start();
          log(`Drop catch started for ${selected.domain} (polling every 30s)`, theme.info);
        } else {
          log("Drop catch requires an expired domain", theme.warning);
        }
      }

      // Toggle recon mode (Issue 4: fix inverted message)
      else if (key === "n") {
        setReconMode((v) => {
          const newVal = !v;
          log(newVal ? "Recon mode ON (full pentest — rescan to apply)" : "Recon mode OFF (fast scan)", newVal ? theme.warning : theme.textMuted);
          return newVal;
        });
      }

      // Add to portfolio
      else if (key === "p" && selected) {
        try {
          addToPortfolio(selected.domain, {
            registrar: selected.whois?.registrar || selected.rdap?.registrar || "unknown",
            expiryDate: selected.whois?.expiryDate || selected.rdap?.expiryDate || "",
            purchaseDate: new Date().toISOString().split("T")[0],
          });
          log(`Added ${selected.domain} to portfolio`, theme.info);
        } catch (err: unknown) {
          log(`Portfolio: ${err instanceof Error ? err.message : "failed"}`, theme.error);
        }
      }

      // Snipe selected domain
      else if (key === "S" && selected) {
        if (selected.status === "taken" || selected.status === "expired") {
          snipeDomain(selected.domain, {
            expiryDate: selected.whois?.expiryDate || undefined,
          });
          const phase = selected.status === "expired" ? "frequent" : "hourly";
          log(`Sniping ${selected.domain} — ${selected.status === "expired" ? "expired, checking every 5 min" : "watching for expiry"}`, theme.warning);
          log(`Run 'domain-sniper snipe run' to start the engine`, theme.textDisabled);
        } else if (selected.status === "available") {
          log(`${selected.domain} is already available — press r to register now`, theme.primary);
        } else {
          log(`Cannot snipe ${selected.domain} (status: ${selected.status})`, theme.textMuted);
        }
      }

      // Clear cache for selected domain
      else if (key === "c" && selected) {
        const count = clearCache(selected.domain);
        log(`Cleared cache for ${selected.domain} (${count} entries)`, theme.info);
      }

      // Show scan history for selected domain
      else if (key === "h" && selected) {
        const history = getScanHistory(selected.domain, 5);
        if (history.length > 0) {
          log(`─── History for ${selected.domain} ───`, theme.secondary);
          for (const h of history) {
            log(`  ${h.scanned_at} — ${h.status}${h.score ? ` (${h.score})` : ""}`, theme.textSecondary);
          }
        } else {
          log(`No scan history for ${selected.domain}`, theme.textMuted);
        }
      }

      // Save session
      else if (ctrl && key === "s") {
        const path = saveSession(domains);
        log(`Session saved: ${path}`, theme.info);
      }

      // Load session
      else if (ctrl && key === "l") {
        setInputMode("load");
        setMode("input");
        setInputValue("");
        const sessions = listSessions();
        if (sessions.length > 0) {
          log(`${sessions.length} saved session(s). Enter ID or path.`, theme.info);
          sessions.slice(0, 3).forEach((s) => log(`  ${s.id} (${s.count} domains)`, theme.textMuted));
        } else {
          log("No saved sessions found", theme.warning);
        }
      }
    }
  });

  // ─── Register ───────────────────────────────────────────

  const handleRegister = async (index: number) => {
    if (!registrarConfig?.apiKey || index < 0) return;
    const d = domains[index]!;
    log(`Registering ${d.domain}...`, theme.info);
    setDomains((prev: DomainEntry[]) => { const u = [...prev]; u[index] = { ...u[index]!, status: "registering" }; return u; });
    const result = await registerDomain(d.domain, registrarConfig);
    setDomains((prev: DomainEntry[]) => {
      const u = [...prev]; u[index] = { ...u[index]!, status: result.success ? "registered" : "available", registration: result }; return u;
    });
    log(result.success ? `★ REG'd ${d.domain}` : `FAIL ${result.error}`, result.success ? theme.secondary : theme.error);
  };

  // ─── Submit handler ─────────────────────────────────────

  const handleSubmit = (value: string) => {
    const v = value.trim();
    if (!v) return;

    // Marketplace inputs
    if (marketInputMode === "search") {
      setMarketSearch(v);
      setMarketInputMode("none");
      setMarketSelectedIdx(0);
      void loadMarketListings(v);
      setMode(domains.length > 0 ? "done" : "idle");
      return;
    }
    if (marketInputMode === "list-price") {
      const price = parseFloat(v);
      if (isNaN(price) || price <= 0) { log("Invalid price", theme.error); setMarketInputMode("none"); setMode(domains.length > 0 ? "done" : "idle"); return; }
      setMarketInputMode("none");
      setMode(domains.length > 0 ? "done" : "idle");
      createListingApi(marketListDomain, price, { title: marketListDomain }).then((r) => {
        if (r.ok) {
          log(`Listed ${marketListDomain} for $${price} — verify ownership to activate`, theme.primary);
          if (r.data.verification) {
            log(`DNS: Add TXT record domain-sniper-verify=${r.data.verification.token}`, theme.textMuted);
          }
        } else {
          log(`Failed to list: ${r.data?.error || "unknown error"}`, theme.error);
        }
      });
      return;
    }
    if (marketInputMode === "offer-amount") {
      const amount = parseFloat(v);
      if (isNaN(amount) || amount <= 0) { log("Invalid amount", theme.error); setMarketInputMode("none"); setMode(domains.length > 0 ? "done" : "idle"); return; }
      setMarketInputMode("none");
      setMode(domains.length > 0 ? "done" : "idle");
      if (marketDetail?.listing) {
        makeOffer(marketDetail.listing.id, amount).then((r) => {
          if (r.ok) {
            log(`Offer of $${amount} submitted on ${marketDetail.listing.domain}`, theme.primary);
          } else {
            log(`Offer failed: ${r.data?.error || "unknown"}`, theme.error);
          }
        });
      }
      return;
    }

    if (inputMode === "file") {
      try {
        const filePath = safePath(v, [process.cwd()]);
        if (existsSync(filePath)) {
          const content = readFileSync(filePath, "utf-8");
          const list = parseDomainList(content);
          if (list.length > 0) { log(`Loaded ${list.length} domains from ${filePath}`, theme.info); processAllDomains(list); }
          else log("No valid domains in file", theme.warning);
        } else { log("File not found: " + filePath, theme.error); setMode(domains.length > 0 ? "done" : "idle"); }
      } catch (err: unknown) {
        log(`Path error: ${err instanceof Error ? err.message : "invalid path"}`, theme.error);
        setMode(domains.length > 0 ? "done" : "idle");
      }
    } else if (inputMode === "expand") {
      const expanded = expandTlds(v, "popular");
      log(`Expanded "${v}" into ${expanded.length} TLD variants`, theme.info);
      if (expanded.length > 0) processAllDomains(expanded, domains.length > 0);
      else { setMode(domains.length > 0 ? "done" : "idle"); }
    } else if (inputMode === "export") {
      try {
        const path = v.endsWith(".json") ? exportToJSON(domains, v) : exportToCSV(domains, v);
        log(`Exported ${domains.length} domains to ${path}`, theme.primary);
      } catch (err: unknown) { log(`Export failed: ${err instanceof Error ? err.message : "unknown"}`, theme.error); }
      setMode("done");
    } else if (inputMode === "load") {
      const session = loadSession(v);
      if (session) {
        setDomains(session.domains.map((d: any) => ({ ...d, tagged: false })));
        setMode("done");
        log(`Loaded session: ${session.id} (${session.domains.length} domains)`, theme.info);
      } else { log("Session not found", theme.error); setMode(domains.length > 0 ? "done" : "idle"); }
    } else if (inputMode === "domain") {
      if (existsSync(v)) {
        const content = readFileSync(v, "utf-8");
        const list = parseDomainList(content);
        if (list.length > 0) { log(`Loaded ${list.length} from ${v}`, theme.info); processAllDomains(list, domains.length > 0); }
      } else {
        const list = v.split(/[,\s]+/).map((d: string) => d.trim().toLowerCase()).filter(Boolean);
        const validated = sanitizeDomainList(list);
        if (validated.length > 0) processAllDomains(validated, domains.length > 0);
        else log("No valid domains entered", theme.warning);
      }
    }
  };

  // ─── Stats ──────────────────────────────────────────────

  const stats = useMemo(() => {
    const s = { total: domains.length, available: 0, expired: 0, taken: 0, checking: 0, registered: 0, errors: 0, tagged: 0 };
    for (const d of domains) {
      if (d.status === "available") s.available++;
      else if (d.status === "expired") s.expired++;
      else if (d.status === "taken") s.taken++;
      else if (d.status === "checking" || d.status === "pending" || d.status === "registering") s.checking++;
      else if (d.status === "registered") s.registered++;
      else if (d.status === "error") s.errors++;
      if (d.tagged) s.tagged++;
    }
    return s;
  }, [domains]);

  // Memoize scores (Issue 12: avoid recalculating per render)
  const domainScores = useMemo(() => {
    const map = new Map<string, { score: ReturnType<typeof scoreDomain>; grade: ReturnType<typeof scoreGrade> }>();
    for (const d of domains) {
      const s = scoreDomain(d.domain);
      map.set(d.domain, { score: s, grade: scoreGrade(s.total) });
    }
    return map;
  }, [domains]);

  const selectedScoreData = selected ? domainScores.get(selected.domain) : null;
  const score = selectedScoreData?.score ?? null;
  const grade = selectedScoreData?.grade ?? null;

  // ─── Layout ─────────────────────────────────────────────

  const sidebarW = Math.max(32, Math.min(48, Math.floor(width * 0.42)));
  const hLine = (w: number) => "─".repeat(Math.max(1, w - 2));
  const dLine = (w: number) => "═".repeat(Math.max(1, w - 2));
  const logPanelH = Math.max(4, Math.floor((height - 5) * 0.28));

  const inputLabel = marketInputMode === "search" ? "SEARCH" : marketInputMode === "list-price" ? "PRICE" : marketInputMode === "offer-amount" ? "OFFER" : inputMode === "file" ? "FILE" : inputMode === "expand" ? "EXPAND" : inputMode === "export" ? "EXPORT" : inputMode === "load" ? "LOAD" : "SCAN";
  const inputPlaceholder = marketInputMode === "search" ? "Search domains..." : marketInputMode === "list-price" ? `Asking price for ${marketListDomain}` : marketInputMode === "offer-amount" ? "Your offer amount" : inputMode === "file" ? "/path/to/domains.txt" : inputMode === "expand" ? "coolstartup" : inputMode === "export" ? "results.csv or results.json" : inputMode === "load" ? "session-id or path" : "domains or /path/to/file";

  // ─── Render ─────────────────────────────────────────────

  return (
    <box width={width} height={height} backgroundColor={theme.background} flexDirection="column">

      {/* ═══ HEADER ═══ */}
      <box flexShrink={0} flexDirection="column">
        <box flexDirection="row" justifyContent="space-between" paddingLeft={1} paddingRight={1}>
          <box flexDirection="row" gap={1}>
            <box backgroundColor={theme.primary}><text content=" ◆ DOMAIN SNIPER " fg={theme.background} /></box>
            <box backgroundColor={
              mode === "scanning" ? theme.warning : mode === "watching" ? theme.accent : mode === "done" ? theme.primary : mode === "input" ? theme.info : theme.textDisabled
            }><text content={
              mode === "scanning" ? (scanProgress ? ` ${scanProgress.current}/${scanProgress.total} ` : " SCANNING ") : mode === "watching" ? ` WATCH #${watchCycle} ` : mode === "done" ? " READY " : mode === "input" ? ` ${inputLabel} ` : " IDLE "
            } fg={theme.background} /></box>
            {filter.status !== "all" && (
              <box backgroundColor={theme.secondaryDim}><text content={` ${filter.status.toUpperCase()} `} fg={theme.secondary} /></box>
            )}
            {filter.sort !== "domain" && (
              <box backgroundColor={theme.accentDim}><text content={` ↕${filter.sort} `} fg={theme.accent} /></box>
            )}
            {reconMode && (
              <box backgroundColor={theme.errorDim}><text content=" RECON " fg={theme.error} /></box>
            )}
          </box>
          <box flexDirection="row" gap={2}>
            {stats.total > 0 && (
              <box flexDirection="row" gap={1}>
                <text content={`${stats.available}`} fg={theme.primary} />
                <text content="avl" fg={theme.textDisabled} />
                <text content={`${stats.expired}`} fg={theme.pending} />
                <text content="exp" fg={theme.textDisabled} />
                <text content={`${stats.taken}`} fg={theme.error} />
                <text content="tkn" fg={theme.textDisabled} />
                {stats.tagged > 0 && (<><text content={`${stats.tagged}`} fg={theme.info} /><text content="tag" fg={theme.textDisabled} /></>)}
              </box>
            )}
            {registrarConfig?.apiKey ? (
              <text content={`● ${registrarConfig.provider}`} fg={theme.secondary} />
            ) : (
              <text content="○ whois" fg={theme.textDisabled} />
            )}
            {isLoggedIn() && (
              <box flexDirection="row" gap={1}>
                <text content={`◆ market`} fg={theme.secondary} />
                {marketUnread > 0 && <text content={`✉${marketUnread}`} fg={theme.warning} />}
              </box>
            )}
            {(() => {
              try {
                const snipeStats = getSnipeStats();
                return snipeStats.total > 0 ? (
                  <text content={`⊕ ${snipeStats.total} sniping`} fg={theme.warning} />
                ) : null;
              } catch { return null; }
            })()}
          </box>
        </box>
        <text content={dLine(width)} fg={theme.border} paddingLeft={1} />
      </box>

      {/* ═══ BODY ═══ */}
      <box flexGrow={1} flexDirection="row" minHeight={0}>
      {showMarket ? (
        <box flexGrow={1} flexDirection="column" paddingLeft={1} paddingRight={1} minHeight={0}>
          {/* Marketplace header */}
          <box flexDirection="row" gap={2} flexShrink={0} paddingLeft={1}>
            <box backgroundColor={theme.secondary}><text content=" MARKETPLACE " fg={theme.background} /></box>
            {(["browse", "my-listings", "my-offers"] as const).map((v, i) => (
              <box key={v} backgroundColor={marketView === v ? theme.secondaryDim : "transparent"}>
                <text content={` ${i + 1}:${v === "browse" ? "Browse" : v === "my-listings" ? "My Listings" : "My Offers"} `} fg={marketView === v ? theme.secondary : theme.textDisabled} />
              </box>
            ))}
            {isLoggedIn() ? (
              <text content={`● ${getAuthInfo()?.name || "user"}`} fg={theme.primary} />
            ) : (
              <text content="○ not signed in (use CLI: market login)" fg={theme.textDisabled} />
            )}
            {marketUnread > 0 && <text content={`✉ ${marketUnread}`} fg={theme.warning} />}
            <box flexGrow={1} />
            <text content="(M to close)" fg={theme.textDisabled} />
          </box>
          <text content={hLine(width)} fg={theme.borderSubtle} paddingLeft={1} />

          {marketView === "detail" && marketDetail ? (
            /* Detail view */
            <scrollbox flexGrow={1} paddingLeft={2} minHeight={0} scrollbarOptions={{ visible: true }}>
              <box flexDirection="column" gap={0} paddingTop={1}>
                <box flexDirection="row" gap={2}>
                  <text content={marketDetail.listing.domain} fg={theme.text} />
                  <text content={`$${marketDetail.listing.asking_price}`} fg={theme.warning} />
                  <text content={marketDetail.listing.verified ? "✓ verified" : "unverified"} fg={marketDetail.listing.verified ? theme.primary : theme.textDisabled} />
                  <text content={marketDetail.listing.status} fg={theme.textMuted} />
                </box>
                <text content="" />
                {marketDetail.listing.title && <text content={marketDetail.listing.title} fg={theme.textSecondary} />}
                {marketDetail.listing.description && <text content={marketDetail.listing.description} fg={theme.textMuted} />}
                <text content="" />
                <box flexDirection="row" gap={2}>
                  <text content={`Category: ${marketDetail.listing.category}`} fg={theme.textDisabled} />
                  <text content={`Views: ${marketDetail.listing.views}`} fg={theme.textDisabled} />
                  <text content={`Offers: ${marketDetail.offerCount}`} fg={theme.textDisabled} />
                </box>
                {marketDetail.listing.min_offer > 0 && <text content={`Min offer: $${marketDetail.listing.min_offer}`} fg={theme.textMuted} />}
                {marketDetail.listing.buy_now ? <text content="Buy Now enabled" fg={theme.primary} /> : null}
                <text content="" />
                <text content={`Listed: ${marketDetail.listing.created_at}`} fg={theme.textDisabled} />
                <text content="" />
                {isLoggedIn() && <text content="Press 'o' to make an offer, Backspace to go back" fg={theme.textMuted} />}
                {!isLoggedIn() && <text content="Sign in via CLI to make offers: domain-sniper market login" fg={theme.textMuted} />}
              </box>
            </scrollbox>
          ) : (
            /* List view */
            <box flexGrow={1} flexDirection="row" minHeight={0}>
              {/* Listing list */}
              <box flexGrow={1} flexDirection="column" minHeight={0}>
                <box flexDirection="row" justifyContent="space-between" paddingLeft={1} paddingRight={1} flexShrink={0}>
                  <text content={`${marketView === "browse" ? "All Listings" : marketView === "my-listings" ? "My Listings" : "My Offers"} (${marketTotal})`} fg={theme.secondary} />
                  {marketLoading && <text content="loading..." fg={theme.warning} />}
                  {marketSearch && marketView === "browse" && <text content={`search: "${marketSearch}"`} fg={theme.textMuted} />}
                </box>
                <text content={hLine(width)} fg={theme.borderSubtle} paddingLeft={1} />

                {marketListings.length > 0 ? (
                  <scrollbox flexGrow={1} paddingLeft={1} minHeight={0} scrollbarOptions={{ visible: true }}>
                    {marketListings.map((item: any, i: number) => {
                      const active = marketSelectedIdx === i;
                      const domain = item.domain || "—";
                      const price = item.asking_price ?? item.amount ?? 0;
                      const status = item.status || "—";
                      const verified = item.verified ? "✓" : " ";
                      return (
                        <box key={item.id || i} flexDirection="row" backgroundColor={active ? theme.secondaryDim : "transparent"} paddingLeft={1} gap={1}>
                          <text content={verified} fg={theme.primary} />
                          <text content={pad(domain, 28)} fg={active ? theme.text : theme.textSecondary} />
                          <text content={`$${price}`} fg={theme.warning} />
                          <box flexGrow={1} />
                          <text content={status} fg={status === "active" ? theme.primary : status === "pending" ? theme.warning : theme.textDisabled} />
                        </box>
                      );
                    })}
                  </scrollbox>
                ) : (
                  <box flexGrow={1} alignItems="center" justifyContent="center" minHeight={0}>
                    <text content={marketLoading ? "Loading..." : "No listings found"} fg={theme.textDisabled} />
                  </box>
                )}
              </box>
            </box>
          )}

          {/* Marketplace footer hints */}
          <text content={dLine(width)} fg={theme.border} paddingLeft={1} />
          <box flexDirection="row" paddingLeft={1} paddingRight={1} flexShrink={0}>
            <box flexDirection="row" gap={1}>
              <box backgroundColor={theme.textDisabled}><text content=" 1 " fg={theme.background} /></box><text content="browse" fg={theme.textMuted} />
              {isLoggedIn() && (<><box backgroundColor={theme.textDisabled}><text content=" 2 " fg={theme.background} /></box><text content="mine" fg={theme.textMuted} /></>)}
              {isLoggedIn() && (<><box backgroundColor={theme.textDisabled}><text content=" 3 " fg={theme.background} /></box><text content="offers" fg={theme.textMuted} /></>)}
              <box backgroundColor={theme.textDisabled}><text content=" / " fg={theme.background} /></box><text content="search" fg={theme.textMuted} />
              <box backgroundColor={theme.textDisabled}><text content=" ⏎ " fg={theme.background} /></box><text content="view" fg={theme.textMuted} />
              {isLoggedIn() && selected && (<><box backgroundColor={theme.textDisabled}><text content=" l " fg={theme.background} /></box><text content="list domain" fg={theme.textMuted} /></>)}
              <box backgroundColor={theme.textDisabled}><text content=" r " fg={theme.background} /></box><text content="refresh" fg={theme.textMuted} />
              <box backgroundColor={theme.textDisabled}><text content=" M " fg={theme.background} /></box><text content="close" fg={theme.textMuted} />
            </box>
          </box>
        </box>
      ) : showPortfolio ? (
        <box flexGrow={1} flexDirection="column" paddingLeft={2} paddingRight={2} minHeight={0}>
          <scrollbox flexGrow={1} minHeight={0} scrollbarOptions={{ visible: true }}>
            {(() => {
              const dash = getPortfolioDashboard();
              const calendar = generateRenewalCalendar(6);
              const annualCost = estimateAnnualRenewalCost();
              const alerts = getUnacknowledgedAlerts();
              const monthly = getMonthlyReport(6);

              return (
                <box flexDirection="column" gap={0}>
                  {/* Header */}
                  <box flexDirection="row" gap={2} paddingTop={1}>
                    <box backgroundColor={theme.primary}><text content=" PORTFOLIO DASHBOARD " fg={theme.background} /></box>
                    <text content={`${dash.totalDomains} domains`} fg={theme.text} />
                    <text content={`$${dash.totalValue.toFixed(0)} value`} fg={theme.primary} />
                    <text content="(Press P to close)" fg={theme.textDisabled} />
                  </box>

                  <text content="" />

                  {/* Summary cards row */}
                  <box flexDirection="row" gap={3}>
                    <box flexDirection="column">
                      <text content="FINANCIALS" fg={theme.secondary} />
                      <text content={`  Costs:   $${dash.totalCosts.toFixed(2)}`} fg={theme.error} />
                      <text content={`  Revenue: $${dash.totalRevenue.toFixed(2)}`} fg={theme.primary} />
                      <text content={`  Profit:  $${dash.totalProfit.toFixed(2)}`} fg={dash.totalProfit >= 0 ? theme.primary : theme.error} />
                      <text content={`  Annual renewals: ~$${annualCost.toFixed(0)}`} fg={theme.textMuted} />
                    </box>
                    <box flexDirection="column">
                      <text content="STATUS" fg={theme.secondary} />
                      {Object.entries(dash.byStatus).map(([status, count]) => (
                        <text key={status} content={`  ${status}: ${count}`} fg={theme.textSecondary} />
                      ))}
                    </box>
                    <box flexDirection="column">
                      <text content="CATEGORIES" fg={theme.secondary} />
                      {Object.entries(dash.byCategory).map(([cat, count]) => (
                        <text key={cat} content={`  ${cat}: ${count}`} fg={theme.textSecondary} />
                      ))}
                    </box>
                  </box>

                  <text content="" />

                  {/* Alerts */}
                  {alerts.length > 0 && (
                    <box flexDirection="column">
                      <text content={`ALERTS (${alerts.length})`} fg={theme.warning} />
                      {alerts.slice(0, 5).map((a) => (
                        <text key={a.id} content={`  ${a.severity === "critical" ? "!!" : a.severity === "warning" ? "! " : "· "} ${a.domain}: ${a.message}`} fg={a.severity === "critical" ? theme.error : a.severity === "warning" ? theme.warning : theme.textSecondary} />
                      ))}
                      {alerts.length > 5 && <text content={`  +${alerts.length - 5} more`} fg={theme.textDisabled} />}
                    </box>
                  )}

                  <text content="" />

                  {/* Renewal Calendar */}
                  {calendar.length > 0 && (
                    <box flexDirection="column">
                      <text content="UPCOMING RENEWALS" fg={theme.secondary} />
                      {calendar.slice(0, 8).map((r) => (
                        <box key={r.domain} flexDirection="row" gap={2}>
                          <text content={`  ${pad(r.domain, 30)}`} fg={r.daysLeft <= 7 ? theme.error : r.daysLeft <= 30 ? theme.warning : theme.text} />
                          <text content={`${r.daysLeft}d`} fg={r.daysLeft <= 7 ? theme.error : r.daysLeft <= 30 ? theme.warning : theme.textMuted} />
                          <text content={`$${r.renewalPrice}`} fg={theme.textDisabled} />
                          {r.autoRenew && <text content="auto" fg={theme.primary} />}
                        </box>
                      ))}
                    </box>
                  )}

                  <text content="" />

                  {/* Top valued domains */}
                  {dash.topValueDomains.length > 0 && (
                    <box flexDirection="column">
                      <text content="TOP VALUED DOMAINS" fg={theme.secondary} />
                      {dash.topValueDomains.map((d) => (
                        <text key={d.domain} content={`  ${pad(d.domain, 30)} $${d.estimated_value.toFixed(0)}`} fg={theme.text} />
                      ))}
                    </box>
                  )}

                  <text content="" />

                  {/* Monthly P&L */}
                  {monthly.length > 0 && (
                    <box flexDirection="column">
                      <text content="MONTHLY P&L" fg={theme.secondary} />
                      {monthly.map((m) => (
                        <box key={m.month} flexDirection="row" gap={2}>
                          <text content={`  ${m.month}`} fg={theme.textMuted} />
                          <text content={`-$${m.costs.toFixed(0)}`} fg={theme.error} />
                          <text content={`+$${m.revenue.toFixed(0)}`} fg={theme.primary} />
                          <text content={`= $${m.profit.toFixed(0)}`} fg={m.profit >= 0 ? theme.primary : theme.error} />
                        </box>
                      ))}
                    </box>
                  )}

                  <text content="" />

                  {/* Recent transactions */}
                  {dash.recentTransactions.length > 0 && (
                    <box flexDirection="column">
                      <text content="RECENT TRANSACTIONS" fg={theme.secondary} />
                      {dash.recentTransactions.map((t, i) => (
                        <text key={i} content={`  ${t.date}  ${pad(t.type, 18)} ${t.amount >= 0 ? "+" : ""}$${t.amount.toFixed(2)}  ${t.domain}`} fg={theme.textSecondary} />
                      ))}
                    </box>
                  )}

                  {/* Pipeline count */}
                  {dash.pipelineCount > 0 && (
                    <>
                      <text content="" />
                      <text content={`PIPELINE: ${dash.pipelineCount} domain(s) being tracked`} fg={theme.info} />
                    </>
                  )}
                </box>
              );
            })()}
          </scrollbox>
        </box>
      ) : (
        <>
        {/* ─── LEFT PANEL ─── */}
        <box width={sidebarW} flexDirection="column" minHeight={0}>
          <box flexDirection="row" justifyContent="space-between" paddingLeft={1} paddingRight={1} flexShrink={0}>
            <text content={` TARGETS ${filteredDomains.length !== stats.total ? `(${filteredDomains.length}/${stats.total})` : stats.total > 0 ? `(${stats.total})` : ""}`} fg={theme.primary} />
            {stats.checking > 0 && <text content={`◆ ${stats.checking}`} fg={theme.warning} />}
          </box>
          <text content={hLine(sidebarW)} fg={theme.borderSubtle} paddingLeft={1} />

          {filteredDomains.length > 0 ? (
            <scrollbox flexGrow={1} paddingLeft={1} minHeight={0} scrollbarOptions={{ visible: true }}>
              {filteredDomains.map((entry: DomainEntry, i: number) => {
                const active = selectedIndex === i;
                const ss = statusStyle(entry.status);
                const cached = domainScores.get(entry.domain);
                const gr = cached?.grade ?? scoreGrade(0);
                return (
                  <box key={entry.domain} flexDirection="row" backgroundColor={active ? theme.primaryDim : "transparent"} paddingLeft={1} gap={1}>
                    <text content={entry.tagged ? "◉" : " "} fg={entry.tagged ? theme.info : "transparent"} />
                    <text content={ss.icon} fg={ss.fg} />
                    <text content={entry.domain} fg={active ? theme.text : theme.textSecondary} />
                    <box flexGrow={1} />
                    <text content={gr.grade} fg={gr.color} />
                    {entry.status === "checking" && <text content="···" fg={theme.warning} />}
                  </box>
                );
              })}
            </scrollbox>
          ) : (
            <box flexGrow={1} alignItems="center" justifyContent="center" minHeight={0}>
              <text content={domains.length > 0 ? "No matches" : "No targets"} fg={theme.textDisabled} />
            </box>
          )}

          {/* LOG */}
          <text content={hLine(sidebarW)} fg={theme.borderSubtle} paddingLeft={1} />
          <box flexDirection="row" paddingLeft={1} flexShrink={0}>
            <text content=" LOG" fg={theme.textMuted} />
          </box>
          <scrollbox height={logPanelH} paddingLeft={1} minHeight={0} scrollbarOptions={{ visible: false }}>
            {logs.map((l) => (
              <box key={l.id} flexDirection="row" gap={1}>
                <text content={l.time} fg={theme.textDisabled} />
                <text content={l.msg} fg={l.fg} />
              </box>
            ))}
          </scrollbox>
        </box>

        {/* ─── DIVIDER ─── */}
        <box width={1}><text content={"┃\n".repeat(Math.max(1, height - 5))} fg={theme.border} /></box>

        {/* ─── RIGHT PANEL: INTEL ─── */}
        <box flexGrow={1} flexDirection="column" minHeight={0}>
          <box flexDirection="row" justifyContent="space-between" paddingLeft={1} paddingRight={1} flexShrink={0}>
            <text content=" INTEL" fg={theme.primary} />
            {selected && <text content={selected.domain} fg={theme.text} />}
          </box>
          {/* Tab bar (Issue 1) */}
          {selected && !showHelp && (
            <box flexDirection="row" paddingLeft={1} gap={1} flexShrink={0}>
              {(["overview", "dns", "security", "recon"] as IntelTab[]).map((tab) => (
                <box key={tab} backgroundColor={intelTab === tab ? theme.primaryDim : "transparent"}>
                  <text content={` ${tab.toUpperCase()} `} fg={intelTab === tab ? theme.primary : theme.textDisabled} />
                </box>
              ))}
            </box>
          )}
          <text content={hLine(width - sidebarW)} fg={theme.borderSubtle} paddingLeft={1} />

          {/* ─── Help overlay ─── */}
          {showHelp ? (
            <scrollbox flexGrow={1} paddingLeft={2} paddingRight={2} minHeight={0} scrollbarOptions={{ visible: false }}>
              <box flexDirection="column" gap={0} paddingTop={1}>
                <text content="COMMANDS" fg={theme.primary} />
                <text content="" />
                <text content="Navigation" fg={theme.secondary} />
                <text content="  ↑/k  ↓/j     Move selection" fg={theme.textSecondary} />
                <text content="  PgUp PgDn     Jump 10" fg={theme.textSecondary} />
                <text content="  g / Home      First" fg={theme.textSecondary} />
                <text content="  End           Last" fg={theme.textSecondary} />
                <text content="  Tab / `       Cycle INTEL tabs" fg={theme.textSecondary} />
                <text content="" />
                <text content="Scanning" fg={theme.secondary} />
                <text content="  /  i          Enter domains" fg={theme.textSecondary} />
                <text content="  f             Load from file" fg={theme.textSecondary} />
                <text content="  e             TLD expansion" fg={theme.textSecondary} />
                <text content="  v             Variations of selected" fg={theme.textSecondary} />
                <text content="" />
                <text content="Actions" fg={theme.secondary} />
                <text content="  SPACE         Tag / untag domain" fg={theme.textSecondary} />
                <text content="  r             Register selected" fg={theme.textSecondary} />
                <text content="  R             Bulk register tagged (2x)" fg={theme.textSecondary} />
                <text content="  d             Suggest similar domains" fg={theme.textSecondary} />
                <text content="  p             Add to portfolio" fg={theme.textSecondary} />
                <text content="  S             Snipe domain (auto-register when it drops)" fg={theme.textSecondary} />
                <text content="  D             Drop catch (expired only)" fg={theme.textSecondary} />
                <text content="  c             Clear cache for selected" fg={theme.textSecondary} />
                <text content="  h             Show scan history" fg={theme.textSecondary} />
                <text content="  w             Watch tagged (1h)" fg={theme.textSecondary} />
                <text content="" />
                <text content="Filter & Sort" fg={theme.secondary} />
                <text content="  s             Cycle status filter" fg={theme.textSecondary} />
                <text content="  o             Cycle sort field" fg={theme.textSecondary} />
                <text content="  O             Toggle sort order" fg={theme.textSecondary} />
                <text content="" />
                <text content="Recon" fg={theme.secondary} />
                <text content="  n             Toggle recon mode" fg={theme.textSecondary} />
                <text content="                Enables port scan, WAF, headers," fg={theme.textDisabled} />
                <text content="                CORS, zone transfer, takeover detect" fg={theme.textDisabled} />
                <text content="                (rescan required after toggling)" fg={theme.textDisabled} />
                <text content="" />
                <text content="Marketplace" fg={theme.secondary} />
                <text content="  M             Open/close marketplace" fg={theme.textSecondary} />
                <text content="  /             Search listings (in marketplace)" fg={theme.textSecondary} />
                <text content="  1 2 3         Switch: Browse / My Listings / My Offers" fg={theme.textSecondary} />
                <text content="  Enter         View listing details" fg={theme.textSecondary} />
                <text content="  l             List selected domain for sale" fg={theme.textSecondary} />
                <text content="  o             Make offer (in detail view)" fg={theme.textSecondary} />
                <text content="  r             Refresh listings" fg={theme.textSecondary} />
                <text content="" />
                <text content="Portfolio" fg={theme.secondary} />
                <text content="  P             Portfolio dashboard" fg={theme.textSecondary} />
                <text content="  p             Add selected to portfolio" fg={theme.textSecondary} />
                <text content="" />
                <text content="Session" fg={theme.secondary} />
                <text content="  Ctrl+S        Save session" fg={theme.textSecondary} />
                <text content="  Ctrl+L        Load session" fg={theme.textSecondary} />
                <text content="  x             Export CSV/JSON" fg={theme.textSecondary} />
                <text content="" />
                <text content="  ?             Toggle this help" fg={theme.textSecondary} />
                <text content="  q / Ctrl+C    Quit" fg={theme.textSecondary} />
              </box>
            </scrollbox>
          ) : selected ? (
            <scrollbox flexGrow={1} paddingLeft={1} paddingRight={1} minHeight={0} scrollbarOptions={{ visible: true }}>
              <box flexDirection="column" gap={0} paddingRight={1}>

                {/* ══ OVERVIEW TAB ══ */}
                {intelTab === "overview" && (
                  <>
                    {/* Status + Score banner */}
                    <box flexDirection="row" gap={2} paddingLeft={1} paddingTop={1}>
                      {(() => { const ss = statusStyle(selected.status); return (<box flexDirection="row" gap={1}><text content={ss.icon} fg={ss.fg} /><text content={ss.label} fg={ss.fg} /></box>); })()}
                      {score && grade && (
                        <box flexDirection="row" gap={1}>
                          <text content={`${grade.grade}`} fg={grade.color} />
                          <text content={`${score.total}/100`} fg={theme.textMuted} />
                        </box>
                      )}
                      {selected.verification && (
                        <text content={`conf: ${selected.verification.confidence}`} fg={selected.verification.confidence === "high" ? theme.primary : theme.warning} />
                      )}
                      {selected.tagged && <text content="TAGGED" fg={theme.info} />}
                      {selected.domainAge && (
                        <text content={`age: ${selected.domainAge}`} fg={theme.textMuted} />
                      )}
                      {(() => {
                        try {
                          const dbDomain = getDomainByName(selected.domain);
                          return dbDomain && dbDomain.scan_count > 1 ? <text content={`scanned ${dbDomain.scan_count}x`} fg={theme.textDisabled} /> : null;
                        } catch { return null; }
                      })()}
                    </box>

                    {/* Score breakdown */}
                    {score && (
                      <box flexDirection="row" paddingLeft={2} paddingTop={1} gap={1}>
                        <text content={`len:${score.length}`} fg={theme.textDisabled} />
                        <text content={`tld:${score.tld}`} fg={theme.textDisabled} />
                        <text content={`read:${score.readability}`} fg={theme.textDisabled} />
                        <text content={`brand:${score.brandable}`} fg={theme.textDisabled} />
                        <text content={`seo:${score.seo}`} fg={theme.textDisabled} />
                      </box>
                    )}

                    {/* Contextual action hint */}
                    {selected && selected.status !== "checking" && selected.status !== "pending" && (
                      <box paddingLeft={2} paddingTop={0} flexShrink={0}>
                        <text content={
                          selected.status === "available" && registrarConfig?.apiKey
                            ? "\u2192 Press r to register  |  p to add to portfolio  |  M then l to list for sale"
                            : selected.status === "available"
                            ? "\u2192 Press p to add to portfolio  |  M then l to list for sale"
                            : selected.status === "expired"
                            ? "\u2192 Press D for drop catch  |  w to watch for availability"
                            : selected.status === "taken"
                            ? "\u2192 Press d for alternatives  |  v for variations  |  Tab for more intel"
                            : selected.status === "registered"
                            ? "\u2192 Press p to add to portfolio  |  M then l to list for sale"
                            : selected.status === "error"
                            ? "\u2192 Press c to clear cache and rescan"
                            : ""
                        } fg={theme.textDisabled} />
                      </box>
                    )}

                    {/* One-line summary */}
                    {selected && selected.status !== "checking" && selected.status !== "pending" && (
                      <box paddingLeft={1} paddingTop={1} paddingBottom={1} flexShrink={0} flexDirection="row" gap={1} flexWrap="wrap">
                        {selected.status === "available" && <text content="AVAILABLE" fg={theme.primary} />}
                        {selected.status === "taken" && <text content="TAKEN" fg={theme.error} />}
                        {selected.status === "expired" && <text content="EXPIRED" fg={theme.warning} />}
                        {selected.httpProbe?.parked && <text content="| Parked" fg={theme.warning} />}
                        {selected.httpProbe?.reachable && !selected.httpProbe?.parked && <text content="| Live" fg={theme.primary} />}
                        {selected.ssl && !selected.ssl.error && selected.ssl.valid && <text content="| SSL OK" fg={theme.primary} />}
                        {selected.ssl && !selected.ssl.error && !selected.ssl.valid && <text content="| SSL Bad" fg={theme.error} />}
                        {selected.blacklist?.listed && <text content="| BLACKLISTED" fg={theme.error} />}
                        {selected.blacklist && !selected.blacklist.listed && <text content="| Clean" fg={theme.textDisabled} />}
                        {selected.waf?.detected && <text content={`| WAF: ${selected.waf.waf}`} fg={theme.textDisabled} />}
                        {selected.techStack?.cms && <text content={`| ${selected.techStack.cms}`} fg={theme.textDisabled} />}
                        {selected.domainAge && <text content={`| ${selected.domainAge} old`} fg={theme.textDisabled} />}
                      </box>
                    )}

                    {/* WHOIS */}
                    {selected.whois && !selected.whois.available && (
                      <box flexDirection="column" paddingLeft={1}>
                        <box flexDirection="row" gap={1}><text content="┃" fg={theme.secondary} /><text content="WHOIS" fg={theme.secondary} /></box>
                        {selected.whois.registrar && (<box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("Registrar", 12)} fg={theme.textMuted} /><text content={selected.whois.registrar} fg={theme.text} /></box>)}
                        {selected.whois.createdDate && (<box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("Created", 12)} fg={theme.textMuted} /><text content={selected.whois.createdDate} fg={theme.text} /></box>)}
                        {selected.whois.expiryDate && (<box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("Expires", 12)} fg={theme.textMuted} /><text content={selected.whois.expiryDate} fg={selected.whois.expired ? theme.error : theme.text} /></box>)}
                        {selected.whois.expiryDate && (() => {
                          const daysLeft = daysUntilExpiry(selected.whois!.expiryDate);
                          return daysLeft !== null ? (
                            <box flexDirection="row" gap={1}>
                              <text content="┃" fg={theme.borderSubtle} />
                              <text content={pad("Expires in", 12)} fg={theme.textMuted} />
                              <text content={`${daysLeft}d`} fg={daysLeft < 30 ? theme.error : daysLeft < 90 ? theme.warning : theme.textSecondary} />
                            </box>
                          ) : null;
                        })()}
                        {selected.whois.nameServers.length > 0 && (<box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("NS", 12)} fg={theme.textMuted} /><text content={selected.whois.nameServers.slice(0, 2).join(", ")} fg={theme.textSecondary} /></box>)}
                        <text content="" />
                      </box>
                    )}

                    {/* Verification */}
                    {selected.verification && (
                      <box flexDirection="column" paddingLeft={1}>
                        <box flexDirection="row" gap={1}><text content="┃" fg={theme.primary} /><text content="VERIFICATION" fg={theme.primary} /></box>
                        {selected.verification.checks.map((c: string, i: number) => (
                          <box key={i} flexDirection="row" gap={1}>
                            <text content="┃" fg={theme.borderSubtle} />
                            <text content={c} fg={c.startsWith("✓") ? theme.primary : c.startsWith("✗") ? theme.error : theme.warning} />
                          </box>
                        ))}
                        <text content="" />
                      </box>
                    )}

                    {/* Registrar */}
                    {selected.registrarCheck && (
                      <box flexDirection="column" paddingLeft={1}>
                        <box flexDirection="row" gap={1}><text content="┃" fg={theme.accent} /><text content="REGISTRAR" fg={theme.accent} /></box>
                        <box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("Available", 12)} fg={theme.textMuted} /><text content={selected.registrarCheck.available ? "Yes" : "No"} fg={selected.registrarCheck.available ? theme.primary : theme.error} /></box>
                        {selected.registrarCheck.price && (<box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("Price", 12)} fg={theme.textMuted} /><text content={`$${selected.registrarCheck.price}`} fg={theme.warning} /></box>)}
                        <text content="" />
                      </box>
                    )}

                    {/* Marketplace */}
                    {selected.marketplace && selected.marketplace.length > 0 && (
                      <box flexDirection="column" paddingLeft={1}>
                        <box flexDirection="row" gap={1}><text content="┃" fg={theme.warning} /><text content="MARKETPLACE" fg={theme.warning} /></box>
                        {selected.marketplace.map((m) => (
                          <box key={m.source} flexDirection="row" gap={1}>
                            <text content="┃" fg={theme.borderSubtle} />
                            <text content={pad(m.source, 12)} fg={theme.textMuted} />
                            <text content={m.price ? `$${m.price}` : m.listed ? "Listed" : "—"} fg={m.price ? theme.warning : theme.textDisabled} />
                          </box>
                        ))}
                        <text content="" />
                      </box>
                    )}

                    {/* Social Media */}
                    {selected.socialMedia && selected.socialMedia.length > 0 && (() => {
                      const avail = selected.socialMedia!.filter((s) => s.available && !s.error);
                      const taken = selected.socialMedia!.filter((s) => !s.available && !s.error);
                      return (
                        <box flexDirection="column" paddingLeft={1}>
                          <box flexDirection="row" gap={1}><text content="┃" fg={theme.info} /><text content={`SOCIAL MEDIA (${avail.length} avail / ${taken.length} taken)`} fg={theme.info} /></box>
                          {avail.slice(0, 5).map((s) => (
                            <box key={s.platform} flexDirection="row" gap={1}>
                              <text content="┃" fg={theme.borderSubtle} />
                              <text content="●" fg={theme.primary} />
                              <text content={s.platform} fg={theme.primary} />
                            </box>
                          ))}
                          {taken.slice(0, 4).map((s) => (
                            <box key={s.platform} flexDirection="row" gap={1}>
                              <text content="┃" fg={theme.borderSubtle} />
                              <text content="✕" fg={theme.textDisabled} />
                              <text content={s.platform} fg={theme.textDisabled} />
                            </box>
                          ))}
                          <text content="" />
                        </box>
                      );
                    })()}

                    {/* WHOIS History */}
                    {(() => {
                      const histCount = getHistoryCount(selected.domain);
                      return histCount > 1 ? <text content={`${histCount} snapshots`} fg={theme.textDisabled} /> : null;
                    })()}

                    {/* Registration */}
                    {selected.registration && (
                      <box flexDirection="column" paddingLeft={1}>
                        <box flexDirection="row" gap={1}><text content="┃" fg={selected.registration.success ? theme.secondary : theme.error} /><text content="REGISTRATION" fg={selected.registration.success ? theme.secondary : theme.error} /></box>
                        <box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={selected.registration.message} fg={theme.text} /></box>
                      </box>
                    )}

                    {/* Score details */}
                    {score && score.breakdown.length > 0 && (
                      <box flexDirection="column" paddingLeft={1}>
                        <box flexDirection="row" gap={1}><text content="┃" fg={theme.warning} /><text content="SCORE FACTORS" fg={theme.warning} /></box>
                        {score.breakdown.map((b: string, i: number) => (
                          <box key={i} flexDirection="row" gap={1}>
                            <text content="┃" fg={theme.borderSubtle} />
                            <text content={`· ${b}`} fg={theme.textSecondary} />
                          </box>
                        ))}
                      </box>
                    )}

                    {selected.error && (
                      <box flexDirection="column" paddingLeft={1}>
                        <box flexDirection="row" gap={1}><text content="┃" fg={theme.error} /><text content="ERROR" fg={theme.error} /></box>
                        <box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={selected.error} fg={theme.error} /></box>
                      </box>
                    )}
                  </>
                )}

                {/* ══ DNS TAB ══ */}
                {intelTab === "dns" && (
                  <>
                    {/* DNS Details */}
                    {selected.dns && (selected.dns.a.length > 0 || selected.dns.mx.length > 0 || selected.dns.txt.length > 0 || selected.dns.cname.length > 0) && (
                      <box flexDirection="column" paddingLeft={1}>
                        <box flexDirection="row" gap={1}><text content="┃" fg={theme.info} /><text content="DNS RECORDS" fg={theme.info} /></box>
                        {selected.dns.a.length > 0 && (<box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("A", 12)} fg={theme.textMuted} /><text content={selected.dns.a.join(", ")} fg={theme.text} /></box>)}
                        {selected.dns.aaaa.length > 0 && (<box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("AAAA", 12)} fg={theme.textMuted} /><text content={selected.dns.aaaa.join(", ")} fg={theme.text} /></box>)}
                        {selected.dns.mx.length > 0 && (<box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("MX", 12)} fg={theme.textMuted} /><text content={selected.dns.mx.slice(0, 3).join(", ")} fg={theme.text} /></box>)}
                        {selected.dns.txt.length > 0 && (<box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("TXT", 12)} fg={theme.textMuted} /><text content={selected.dns.txt.slice(0, 2).join(", ")} fg={theme.textSecondary} /></box>)}
                        {selected.dns.cname.length > 0 && (<box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("CNAME", 12)} fg={theme.textMuted} /><text content={selected.dns.cname.join(", ")} fg={theme.text} /></box>)}
                        <text content="" />
                      </box>
                    )}

                    {/* RDAP */}
                    {selected.rdap && !selected.rdap.error && (
                      <box flexDirection="column" paddingLeft={1}>
                        <box flexDirection="row" gap={1}><text content="┃" fg={theme.info} /><text content="RDAP" fg={theme.info} /></box>
                        {selected.rdap.registrar && (<box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("Registrar", 12)} fg={theme.textMuted} /><text content={selected.rdap.registrar} fg={theme.text} /></box>)}
                        {selected.rdap.status.length > 0 && (<box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("Status", 12)} fg={theme.textMuted} /><text content={selected.rdap.status.slice(0, 3).join(", ")} fg={theme.textSecondary} /></box>)}
                        <text content="" />
                      </box>
                    )}

                    {/* Subdomains */}
                    {selected.subdomains && (() => {
                      const active = selected.subdomains!.filter((s) => s.resolved);
                      return active.length > 0 ? (
                        <box flexDirection="column" paddingLeft={1}>
                          <box flexDirection="row" gap={1}><text content="┃" fg={theme.secondary} /><text content={`SUBDOMAINS (${active.length} found)`} fg={theme.secondary} /></box>
                          {active.slice(0, 8).map((s) => (
                            <box key={s.subdomain} flexDirection="row" gap={1}>
                              <text content="┃" fg={theme.borderSubtle} />
                              <text content={pad(s.subdomain, 12)} fg={theme.textMuted} />
                              <text content={s.ip || ""} fg={theme.textSecondary} />
                            </box>
                          ))}
                          {active.length > 8 && (<box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={`  +${active.length - 8} more`} fg={theme.textDisabled} /></box>)}
                          <text content="" />
                        </box>
                      ) : null;
                    })()}

                    {/* Cert Transparency (recon) */}
                    {selected.certTransparency && selected.certTransparency.subdomains.length > 0 && (
                      <box flexDirection="column" paddingLeft={1}>
                        <box flexDirection="row" gap={1}><text content="┃" fg={theme.secondary} /><text content={`CERT TRANSPARENCY (${selected.certTransparency.subdomains.length} subdomains, ${selected.certTransparency.totalCerts} certs)`} fg={theme.secondary} /></box>
                        {selected.certTransparency.subdomains.slice(0, 8).map((s) => (
                          <box key={s} flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={s} fg={theme.textSecondary} /></box>
                        ))}
                        {selected.certTransparency.subdomains.length > 8 && <box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={`  +${selected.certTransparency.subdomains.length - 8} more`} fg={theme.textDisabled} /></box>}
                        <text content="" />
                      </box>
                    )}

                    {/* Email Security (recon) */}
                    {selected.emailSecurity && (
                      <box flexDirection="column" paddingLeft={1}>
                        <box flexDirection="row" gap={1}><text content="┃" fg={selected.emailSecurity.grade <= "B" ? theme.primary : theme.error} /><text content={`EMAIL SECURITY (${selected.emailSecurity.grade})`} fg={selected.emailSecurity.grade <= "B" ? theme.primary : theme.error} /></box>
                        <box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("SPF", 12)} fg={theme.textMuted} /><text content={selected.emailSecurity.spf.found ? "Found" : "Missing"} fg={selected.emailSecurity.spf.found ? theme.primary : theme.error} /></box>
                        <box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("DKIM", 12)} fg={theme.textMuted} /><text content={selected.emailSecurity.dkim.found ? `Found (${selected.emailSecurity.dkim.selector})` : "Missing"} fg={selected.emailSecurity.dkim.found ? theme.primary : theme.error} /></box>
                        <box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("DMARC", 12)} fg={theme.textMuted} /><text content={selected.emailSecurity.dmarc.found ? `p=${selected.emailSecurity.dmarc.policy || "?"}` : "Missing"} fg={selected.emailSecurity.dmarc.found ? theme.primary : theme.error} /></box>
                        {selected.emailSecurity.issues.slice(0, 3).map((issue, i) => (
                          <box key={i} flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={`! ${issue}`} fg={theme.warning} /></box>
                        ))}
                        <text content="" />
                      </box>
                    )}

                    {!selected.dns && !selected.rdap && !selected.subdomains && !selected.certTransparency && !selected.emailSecurity && (
                      <box paddingLeft={2} paddingTop={2}><text content="No DNS data available" fg={theme.textDisabled} /></box>
                    )}
                  </>
                )}

                {/* ══ SECURITY TAB ══ */}
                {intelTab === "security" && (
                  <>
                    {/* SSL Certificate */}
                    {selected.ssl && !selected.ssl.error && (
                      <box flexDirection="column" paddingLeft={1}>
                        <box flexDirection="row" gap={1}><text content="┃" fg={theme.primary} /><text content="SSL CERTIFICATE" fg={theme.primary} /></box>
                        <box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("Valid", 12)} fg={theme.textMuted} /><text content={selected.ssl.valid ? "Yes" : "No"} fg={selected.ssl.valid ? theme.primary : theme.error} /></box>
                        {selected.ssl.issuer && (<box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("Issuer", 12)} fg={theme.textMuted} /><text content={selected.ssl.issuer} fg={theme.text} /></box>)}
                        {selected.ssl.daysUntilExpiry !== null && (<box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("Cert Expiry", 12)} fg={theme.textMuted} /><text content={`${selected.ssl.daysUntilExpiry}d`} fg={selected.ssl.daysUntilExpiry < 30 ? theme.error : theme.textSecondary} /></box>)}
                        {selected.ssl.protocol && (<box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("Protocol", 12)} fg={theme.textMuted} /><text content={selected.ssl.protocol} fg={theme.textSecondary} /></box>)}
                        {selected.ssl.sans.length > 0 && (<box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("SANs", 12)} fg={theme.textMuted} /><text content={selected.ssl.sans.slice(0, 3).join(", ")} fg={theme.textSecondary} /></box>)}
                        <text content="" />
                      </box>
                    )}

                    {/* Blacklist */}
                    {selected.blacklist && (
                      <box flexDirection="column" paddingLeft={1}>
                        <box flexDirection="row" gap={1}>
                          <text content="┃" fg={selected.blacklist.listed ? theme.error : theme.primary} />
                          <text content={selected.blacklist.listed ? `BLACKLISTED (${selected.blacklist.listedCount})` : `REPUTATION (${selected.blacklist.cleanCount}/${selected.blacklist.lists.length} clean)`} fg={selected.blacklist.listed ? theme.error : theme.primary} />
                        </box>
                        {selected.blacklist.listed && selected.blacklist.lists.filter((l) => l.listed).map((l) => (
                          <box key={l.name} flexDirection="row" gap={1}>
                            <text content="┃" fg={theme.borderSubtle} />
                            <text content="⚠" fg={theme.error} />
                            <text content={l.name} fg={theme.error} />
                            {l.detail && <text content={l.detail} fg={theme.textDisabled} />}
                          </box>
                        ))}
                        <text content="" />
                      </box>
                    )}

                    {/* Tech Stack */}
                    {selected.techStack && selected.techStack.technologies.length > 0 && (
                      <box flexDirection="column" paddingLeft={1}>
                        <box flexDirection="row" gap={1}><text content="┃" fg={theme.accent} /><text content={`TECH STACK (${selected.techStack.technologies.length})`} fg={theme.accent} /></box>
                        {selected.techStack.cms && (<box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("CMS", 12)} fg={theme.textMuted} /><text content={selected.techStack.cms} fg={theme.text} /></box>)}
                        {selected.techStack.framework && (<box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("Framework", 12)} fg={theme.textMuted} /><text content={selected.techStack.framework} fg={theme.text} /></box>)}
                        {selected.techStack.cdn && (<box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("CDN", 12)} fg={theme.textMuted} /><text content={selected.techStack.cdn} fg={theme.text} /></box>)}
                        {selected.techStack.analytics.length > 0 && (<box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("Analytics", 12)} fg={theme.textMuted} /><text content={selected.techStack.analytics.join(", ")} fg={theme.textSecondary} /></box>)}
                        {selected.techStack.technologies.filter((t) => !["CMS", "Framework", "CDN", "Analytics"].includes(t.category)).slice(0, 4).map((t) => (
                          <box key={t.name} flexDirection="row" gap={1}>
                            <text content="┃" fg={theme.borderSubtle} />
                            <text content={pad(t.category, 12)} fg={theme.textMuted} />
                            <text content={t.name} fg={theme.textSecondary} />
                          </box>
                        ))}
                        <text content="" />
                      </box>
                    )}

                    {/* Backlinks / Authority */}
                    {selected.backlinks && (selected.backlinks.pageRank !== null || selected.backlinks.commonCrawlPages !== null) && (
                      <box flexDirection="column" paddingLeft={1}>
                        <box flexDirection="row" gap={1}><text content="┃" fg={theme.secondary} /><text content="AUTHORITY" fg={theme.secondary} /></box>
                        {selected.backlinks.pageRank !== null && (<box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("PageRank", 12)} fg={theme.textMuted} /><text content={`${selected.backlinks.pageRank}`} fg={selected.backlinks.pageRank >= 5 ? theme.primary : theme.text} /></box>)}
                        {selected.backlinks.commonCrawlPages !== null && (<box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("CC Pages", 12)} fg={theme.textMuted} /><text content={`~${selected.backlinks.commonCrawlPages}`} fg={theme.textSecondary} /></box>)}
                        <text content="" />
                      </box>
                    )}

                    {/* Security Headers (recon) */}
                    {selected.securityHeaders && !selected.securityHeaders.error && (
                      <box flexDirection="column" paddingLeft={1}>
                        <box flexDirection="row" gap={1}><text content="┃" fg={selected.securityHeaders.grade <= "B" ? theme.primary : theme.error} /><text content={`SECURITY HEADERS (${selected.securityHeaders.grade} — ${selected.securityHeaders.score}/100)`} fg={selected.securityHeaders.grade <= "B" ? theme.primary : theme.error} /></box>
                        {selected.securityHeaders.missing.slice(0, 4).map((h) => (
                          <box key={h} flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={`x ${h}`} fg={theme.error} /></box>
                        ))}
                        {selected.securityHeaders.headers.filter((h) => h.status === "good").slice(0, 3).map((h) => (
                          <box key={h.name} flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={`+ ${h.name}`} fg={theme.primary} /></box>
                        ))}
                        <text content="" />
                      </box>
                    )}

                    {/* WAF (recon) */}
                    {selected.waf && (
                      <box flexDirection="column" paddingLeft={1}>
                        <box flexDirection="row" gap={1}><text content="┃" fg={theme.accent} /><text content={selected.waf.detected ? `WAF: ${selected.waf.waf} (${selected.waf.confidence})` : "WAF: None detected"} fg={selected.waf.detected ? theme.accent : theme.textDisabled} /></box>
                        <text content="" />
                      </box>
                    )}

                    {/* CORS (recon) */}
                    {selected.cors && selected.cors.vulnerable && (
                      <box flexDirection="column" paddingLeft={1}>
                        <box flexDirection="row" gap={1}><text content="┃" fg={theme.error} /><text content="!! CORS MISCONFIGURATION" fg={theme.error} /></box>
                        {selected.cors.findings.filter((f) => f.allowed).slice(0, 3).map((f, i) => (
                          <box key={i} flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={f.detail} fg={theme.error} /></box>
                        ))}
                        <text content="" />
                      </box>
                    )}

                    {/* Zone Transfer (recon) */}
                    {selected.zoneTransfer && selected.zoneTransfer.vulnerable && (
                      <box flexDirection="column" paddingLeft={1}>
                        <box flexDirection="row" gap={1}><text content="┃" fg={theme.error} /><text content="!! ZONE TRANSFER VULNERABLE" fg={theme.error} /></box>
                        {selected.zoneTransfer.vulnerableNs.map((ns) => (
                          <box key={ns} flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={ns} fg={theme.error} /></box>
                        ))}
                        <text content="" />
                      </box>
                    )}

                    {/* Takeover Detection (recon) */}
                    {selected.takeover && selected.takeover.vulnerable && (
                      <box flexDirection="column" paddingLeft={1}>
                        <box flexDirection="row" gap={1}><text content="┃" fg={theme.error} /><text content="!! SUBDOMAIN TAKEOVER" fg={theme.error} /></box>
                        {selected.takeover.findings.filter((f) => f.status === "vulnerable").map((f) => (
                          <box key={f.subdomain} flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={`${f.subdomain} -> ${f.service}`} fg={theme.error} /></box>
                        ))}
                        <text content="" />
                      </box>
                    )}

                    {/* Path Scanner (recon) */}
                    {selected.pathScan && selected.pathScan.findings.length > 0 && (
                      <box flexDirection="column" paddingLeft={1}>
                        <box flexDirection="row" gap={1}><text content="┃" fg={theme.error} /><text content={`EXPOSED PATHS (${selected.pathScan.findings.length})`} fg={theme.error} /></box>
                        {selected.pathScan.findings.slice(0, 8).map((f) => (
                          <box key={f.path} flexDirection="row" gap={1}>
                            <text content="┃" fg={theme.borderSubtle} />
                            <text content={f.severity === "critical" ? "!!" : f.severity === "high" ? "! " : ". "} fg={f.severity === "critical" ? theme.error : f.severity === "high" ? theme.warning : theme.textMuted} />
                            <text content={f.path} fg={f.severity === "critical" ? theme.error : theme.text} />
                            <text content={`${f.status}`} fg={theme.textDisabled} />
                          </box>
                        ))}
                        <text content="" />
                      </box>
                    )}

                    {!selected.ssl && !selected.blacklist && !selected.techStack && !selected.backlinks && !selected.securityHeaders && !selected.waf && !selected.cors && !selected.zoneTransfer && !selected.takeover && !selected.pathScan && (
                      <box paddingLeft={2} paddingTop={2}><text content="No security data available" fg={theme.textDisabled} /></box>
                    )}
                  </>
                )}

                {/* ══ RECON TAB ══ */}
                {intelTab === "recon" && (
                  <>
                    {/* Port Scan */}
                    {selected.portScan && selected.portScan.openPorts.length > 0 && (
                      <box flexDirection="column" paddingLeft={1}>
                        <box flexDirection="row" gap={1}><text content="┃" fg={theme.error} /><text content={`OPEN PORTS (${selected.portScan.openPorts.length})`} fg={theme.error} /></box>
                        {selected.portScan.openPorts.slice(0, 10).map((p) => (
                          <box key={p.port} flexDirection="row" gap={1}>
                            <text content="┃" fg={theme.borderSubtle} />
                            <text content={pad(String(p.port), 6)} fg={theme.warning} />
                            <text content={pad(p.service, 12)} fg={theme.text} />
                            {p.banner && <text content={p.banner.slice(0, 40)} fg={theme.textDisabled} />}
                          </box>
                        ))}
                        {selected.portScan.ip && <box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={`IP: ${selected.portScan.ip} (${selected.portScan.scanTime}ms)`} fg={theme.textDisabled} /></box>}
                        <text content="" />
                      </box>
                    )}

                    {/* ASN / Network */}
                    {selected.asn && !selected.asn.error && (
                      <box flexDirection="column" paddingLeft={1}>
                        <box flexDirection="row" gap={1}><text content="┃" fg={theme.info} /><text content="NETWORK" fg={theme.info} /></box>
                        {selected.asn.asn && <box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("ASN", 12)} fg={theme.textMuted} /><text content={`${selected.asn.asn}${selected.asn.asnName ? ` (${selected.asn.asnName})` : ""}`} fg={theme.text} /></box>}
                        {selected.asn.org && <box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("Org", 12)} fg={theme.textMuted} /><text content={selected.asn.org} fg={theme.text} /></box>}
                        {selected.asn.country && <box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("Location", 12)} fg={theme.textMuted} /><text content={`${selected.asn.city || ""}${selected.asn.city && selected.asn.country ? ", " : ""}${selected.asn.country}`} fg={theme.textSecondary} /></box>}
                        <text content="" />
                      </box>
                    )}

                    {/* Reverse IP */}
                    {selected.reverseIp && selected.reverseIp.sharedDomains.length > 0 && (
                      <box flexDirection="column" paddingLeft={1}>
                        <box flexDirection="row" gap={1}><text content="┃" fg={theme.warning} /><text content={`SHARED HOSTING (${selected.reverseIp.sharedDomains.length} domains on ${selected.reverseIp.ip})`} fg={theme.warning} /></box>
                        {selected.reverseIp.sharedDomains.slice(0, 6).map((d) => (
                          <box key={d} flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={d} fg={theme.textSecondary} /></box>
                        ))}
                        {selected.reverseIp.sharedDomains.length > 6 && <box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={`  +${selected.reverseIp.sharedDomains.length - 6} more`} fg={theme.textDisabled} /></box>}
                        <text content="" />
                      </box>
                    )}

                    {/* HTTP Probe */}
                    {selected.httpProbe && (
                      <box flexDirection="column" paddingLeft={1}>
                        <box flexDirection="row" gap={1}><text content="┃" fg={theme.pending} /><text content="HTTP PROBE" fg={theme.pending} /></box>
                        {selected.httpProbe.reachable ? (
                          <>
                            <box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("Status", 12)} fg={theme.textMuted} /><text content={`${selected.httpProbe.status}`} fg={selected.httpProbe.status === 200 ? theme.primary : theme.warning} /></box>
                            {selected.httpProbe.server && (<box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("Server", 12)} fg={theme.textMuted} /><text content={selected.httpProbe.server} fg={theme.textSecondary} /></box>)}
                            {selected.httpProbe.redirectUrl && (<box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("Redirect", 12)} fg={theme.textMuted} /><text content={selected.httpProbe.redirectUrl} fg={theme.warning} /></box>)}
                            {selected.httpProbe.parked && (<box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content="⚠ PARKED DOMAIN" fg={theme.error} /></box>)}
                          </>
                        ) : (
                          <box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content="Unreachable" fg={theme.textDisabled} /></box>
                        )}
                        <text content="" />
                      </box>
                    )}

                    {/* Wayback Machine */}
                    {selected.wayback && selected.wayback.hasHistory && (
                      <box flexDirection="column" paddingLeft={1}>
                        <box flexDirection="row" gap={1}><text content="┃" fg={theme.accent} /><text content="WAYBACK MACHINE" fg={theme.accent} /></box>
                        <box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("Snapshots", 12)} fg={theme.textMuted} /><text content={`~${selected.wayback.snapshots} pages`} fg={theme.text} /></box>
                        {selected.wayback.firstArchived && (<box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("First", 12)} fg={theme.textMuted} /><text content={selected.wayback.firstArchived} fg={theme.textSecondary} /></box>)}
                        {selected.wayback.lastArchived && (<box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("Last", 12)} fg={theme.textMuted} /><text content={selected.wayback.lastArchived} fg={theme.textSecondary} /></box>)}
                        <text content="" />
                      </box>
                    )}

                    {!selected.portScan && !selected.asn && !selected.reverseIp && !selected.httpProbe && !selected.wayback && (
                      <box paddingLeft={2} paddingTop={2}><text content={reconMode ? "No recon data yet — rescan to collect" : "Enable recon mode (n) and rescan"} fg={theme.textDisabled} /></box>
                    )}
                  </>
                )}

                {(selected.status === "pending") && <box paddingLeft={2} paddingTop={2}><text content="Queued..." fg={theme.textDisabled} /></box>}
                {(selected.status === "checking") && <box paddingLeft={2} paddingTop={2}><text content="Scanning..." fg={theme.warning} /></box>}
              </box>
            </scrollbox>
          ) : (
            <box flexGrow={1} alignItems="center" justifyContent="center" minHeight={0}>
              {(() => {
                const dbStats = (() => { try { return getDbStats(); } catch { return null; } })();
                const portfolio = (() => { try { return getPortfolioDashboard(); } catch { return null; } })();
                const expiring = (() => { try { return getPortfolioExpiring(30); } catch { return []; } })();
                const recentDomains = (() => { try { return getAllDomains(5, 0); } catch { return []; } })();
                const alerts = (() => { try { return getUnacknowledgedAlerts(); } catch { return []; } })();
                const hasData = dbStats && dbStats.totalScans > 0;
                const cw = Math.min(56, width - 10);
                const sep = `  ${" ".repeat(2)}${"─".repeat(cw)}`;

                return (
                  <box flexDirection="column" alignItems="center">
                    {/* Logo */}
                    <text content="" />
                    <box flexDirection="row" gap={1} justifyContent="center">
                      <text content="◆" fg={theme.primary} />
                      <text content="DOMAIN SNIPER" fg={theme.primary} />
                    </box>
                    <box justifyContent="center">
                      <text content="Domain Intelligence & Security Recon" fg={theme.textDisabled} />
                    </box>
                    <text content="" />

                    {/* Stats */}
                    {hasData && (
                      <>
                        <text content={sep} fg={theme.borderSubtle} />
                        <text content="" />
                        <box flexDirection="row" justifyContent="center" gap={4}>
                          <box flexDirection="column" alignItems="center">
                            <text content={`${dbStats.totalDomains}`} fg={theme.primary} />
                            <text content="domains" fg={theme.textDisabled} />
                          </box>
                          <box flexDirection="column" alignItems="center">
                            <text content={`${dbStats.totalScans}`} fg={theme.primary} />
                            <text content="scans" fg={theme.textDisabled} />
                          </box>
                          {portfolio && portfolio.totalDomains > 0 ? (
                            <box flexDirection="column" alignItems="center">
                              <text content={`$${portfolio.totalValue.toFixed(0)}`} fg={theme.warning} />
                              <text content="portfolio" fg={theme.textDisabled} />
                            </box>
                          ) : (
                            <box flexDirection="column" alignItems="center">
                              <text content={`${dbStats.totalSessions}`} fg={theme.info} />
                              <text content="sessions" fg={theme.textDisabled} />
                            </box>
                          )}
                        </box>
                        <text content="" />
                      </>
                    )}

                    {/* Alerts / Expiring */}
                    {alerts.length > 0 && (
                      <>
                        {alerts.slice(0, 2).map((a: any) => (
                          <box key={a.id} justifyContent="center">
                            <text content={`${a.severity === "critical" ? "!!" : " !"} ${a.domain}: ${a.message}`} fg={a.severity === "critical" ? theme.error : theme.warning} />
                          </box>
                        ))}
                        <text content="" />
                      </>
                    )}
                    {expiring.length > 0 && !alerts.length && (
                      <>
                        <box justifyContent="center">
                          <text content={`⚠ ${expiring.length} domain${expiring.length > 1 ? "s" : ""} expiring within 30 days`} fg={theme.warning} />
                        </box>
                        <text content="" />
                      </>
                    )}

                    {/* Recent scans */}
                    {recentDomains.length > 0 && (
                      <>
                        <text content={sep} fg={theme.borderSubtle} />
                        <text content="" />
                        <box justifyContent="center">
                          <text content="RECENT" fg={theme.textMuted} />
                        </box>
                        {recentDomains.slice(0, 3).map((d: any) => (
                          <box key={d.domain} justifyContent="center" flexDirection="row" gap={1}>
                            <text content={d.domain} fg={theme.textSecondary} />
                            {d.scan_count > 0 && <text content={`${d.scan_count}x`} fg={theme.textDisabled} />}
                          </box>
                        ))}
                        <text content="" />
                      </>
                    )}

                    {/* First run */}
                    {!hasData && (
                      <>
                        <text content={sep} fg={theme.borderSubtle} />
                        <text content="" />
                        <box justifyContent="center">
                          <text content="Press / to scan your first domain" fg={theme.textSecondary} />
                        </box>
                        <text content="" />
                      </>
                    )}

                    {/* Shortcuts */}
                    <text content={sep} fg={theme.borderSubtle} />
                    <text content="" />
                    <box flexDirection="row" justifyContent="center" gap={3}>
                      <box flexDirection="row" gap={1}><box backgroundColor={theme.primaryDim}><text content=" / " fg={theme.primary} /></box><text content="scan" fg={theme.textSecondary} /></box>
                      <box flexDirection="row" gap={1}><box backgroundColor={theme.primaryDim}><text content=" e " fg={theme.primary} /></box><text content="expand" fg={theme.textSecondary} /></box>
                      <box flexDirection="row" gap={1}><box backgroundColor={theme.primaryDim}><text content=" f " fg={theme.primary} /></box><text content="file" fg={theme.textSecondary} /></box>
                      <box flexDirection="row" gap={1}><box backgroundColor={theme.primaryDim}><text content=" ? " fg={theme.primary} /></box><text content="help" fg={theme.textSecondary} /></box>
                    </box>
                    <box flexDirection="row" justifyContent="center" gap={3}>
                      <box flexDirection="row" gap={1}><box backgroundColor={theme.secondaryDim}><text content=" M " fg={theme.secondary} /></box><text content="market" fg={theme.textSecondary} /></box>
                      <box flexDirection="row" gap={1}><box backgroundColor={theme.secondaryDim}><text content=" P " fg={theme.secondary} /></box><text content="portfolio" fg={theme.textSecondary} /></box>
                      <box flexDirection="row" gap={1}><box backgroundColor={theme.accentDim}><text content=" n " fg={theme.accent} /></box><text content="recon" fg={theme.textSecondary} /></box>
                      <box flexDirection="row" gap={1}><box backgroundColor={theme.errorDim}><text content=" q " fg={theme.error} /></box><text content="quit" fg={theme.textSecondary} /></box>
                    </box>
                    <text content="" />

                    {/* Mode indicators */}
                    <box flexDirection="row" justifyContent="center" gap={2}>
                      <text content={reconMode ? "● recon" : "○ recon"} fg={reconMode ? theme.warning : theme.textDisabled} />
                      <text content={registrarConfig?.apiKey ? `● ${registrarConfig.provider}` : "○ registrar"} fg={registrarConfig?.apiKey ? theme.secondary : theme.textDisabled} />
                      <text content={isLoggedIn() ? `● ${getAuthInfo()?.name}` : "○ market"} fg={isLoggedIn() ? theme.primary : theme.textDisabled} />
                    </box>
                  </box>
                );
              })()}
            </box>
          )}
        </box>
        </>
      )}
      </box>

      {/* ═══ INPUT BAR ═══ */}
      {(mode === "input" || marketInputMode !== "none") && (
        <box flexShrink={0} flexDirection="row" paddingLeft={1} paddingRight={1} backgroundColor={theme.backgroundPanel} gap={1}>
          <box backgroundColor={theme.info}><text content={` ${inputLabel} `} fg={theme.background} /></box>
          <input
            focused value={inputValue}
            placeholder={inputPlaceholder}
            placeholderColor={theme.textPlaceholder} cursorColor={theme.primary}
            focusedTextColor={theme.text} focusedBackgroundColor={theme.backgroundPanel}
            width={width - inputLabel.length - 6}
            onChange={(v: string) => setInputValue(v)}
            // opentui input onSubmit type workaround
            onSubmit={((v: any) => handleSubmit(String(v))) as any}
          />
        </box>
      )}

      {/* ═══ FOOTER ═══ */}
      <box flexShrink={0} flexDirection="column">
        <text content={dLine(width)} fg={theme.border} paddingLeft={1} />
        <box flexDirection="row" justifyContent="space-between" paddingLeft={1} paddingRight={1}>
          <box flexDirection="row" gap={1}>
            {mode !== "input" ? (
              (() => {
                const footerHints: { key: string; label: string; priority: number }[] = [
                  { key: "/", label: "scan", priority: 1 },
                  { key: "␣", label: "tag", priority: 2 },
                  { key: "?", label: "help", priority: 3 },
                  { key: "n", label: reconMode ? "recon:ON" : "recon", priority: 4 },
                  { key: "M", label: "market", priority: 5 },
                  { key: "S", label: "snipe", priority: 6 },
                  { key: "e", label: "expand", priority: 7 },
                  { key: "Tab", label: "tabs", priority: 8 },
                  ...(registrarConfig?.apiKey ? [{ key: "r", label: "reg", priority: 9 }] : []),
                  { key: "d", label: "suggest", priority: 10 },
                  { key: "P", label: showPortfolio ? "close" : "dash", priority: 11 },
                  { key: "p", label: "portfolio", priority: 12 },
                ];
                const maxHints = Math.floor((width - 20) / 10);
                const visibleHints = footerHints.slice(0, maxHints);
                return (
                  <>
                    {visibleHints.map((h) => (
                      <box key={h.key} flexDirection="row" gap={0}>
                        <box backgroundColor={theme.textDisabled}><text content={` ${h.key} `} fg={theme.background} /></box>
                        <text content={h.label} fg={h.key === "n" && reconMode ? theme.error : h.key === "P" && showPortfolio ? theme.primary : h.key === "M" && showMarket ? theme.secondary : theme.textMuted} />
                      </box>
                    ))}
                  </>
                );
              })()
            ) : (
              <>
                <box backgroundColor={theme.textDisabled}><text content=" ⏎ " fg={theme.background} /></box><text content="submit" fg={theme.textMuted} />
                <box backgroundColor={theme.textDisabled}><text content=" esc " fg={theme.background} /></box><text content="cancel" fg={theme.textMuted} />
              </>
            )}
          </box>
          <text content={stats.total > 0 ? `${stats.available + stats.expired}/${stats.total} actionable` : "v2.0"} fg={theme.textDisabled} />
        </box>
      </box>
    </box>
  );
}
