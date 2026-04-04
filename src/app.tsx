import { useState, useEffect, useCallback, useRef, useMemo } from "react";
import { useKeyboard, useRenderer, useTerminalDimensions } from "@opentui/react";
import { whoisLookup, verifyAvailability, parseDomainList, type WhoisResult } from "./whois.js";
import {
  checkAvailabilityViaRegistrar, registerDomain, loadConfigFromEnv,
  type RegistrarConfig, type RegistrationResult,
} from "./registrar.js";
import { readFileSync, existsSync } from "fs";
import { theme, borders, statusStyle, type DomainStatus } from "./theme.js";
import type { DomainEntry } from "./types.js";
import { expandTlds, type TldPreset } from "./features/tld-expand.js";
import { generateVariations } from "./features/variations.js";
import { scoreDomain, scoreGrade } from "./features/scoring.js";
import { exportToCSV, exportToJSON } from "./features/export.js";
import { DomainWatcher, formatInterval } from "./features/watch.js";
import { saveSession, loadSession, listSessions } from "./features/session.js";
import { filterDomains, nextStatus, nextSort, DEFAULT_FILTER, type FilterConfig, type FilterStatus, type SortField } from "./features/filter.js";

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

export function App({ initialDomains, batchFile, autoRegister = false }: AppProps) {
  const [mode, setMode] = useState<Mode>(initialDomains?.length || batchFile ? "scanning" : "idle");
  const [inputMode, setInputMode] = useState<InputMode>("domain");
  const [domains, setDomains] = useState<DomainEntry[]>([]);
  const [inputValue, setInputValue] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [showHelp, setShowHelp] = useState(false);
  const [filter, setFilter] = useState<FilterConfig>({ ...DEFAULT_FILTER });
  const [logs, setLogs] = useState<{ time: string; msg: string; fg: string }[]>([
    { time: ts(), msg: "Domain Sniper v2.0 initialized", fg: theme.textMuted },
    { time: ts(), msg: "Press ? for all commands", fg: theme.textMuted },
  ]);
  const [registrarConfig] = useState<RegistrarConfig | null>(loadConfigFromEnv());
  const [watcher, setWatcher] = useState<DomainWatcher | null>(null);
  const [watchCycle, setWatchCycle] = useState(0);
  const { width, height } = useTerminalDimensions();
  const renderer = useRenderer();
  const processingRef = useRef(false);

  // ─── Log ────────────────────────────────────────────────

  const log = useCallback((msg: string, fg: string = theme.textSecondary) => {
    setLogs((prev: { time: string; msg: string; fg: string }[]) => [...prev.slice(-80), { time: ts(), msg, fg }]);
  }, []);

  // ─── Domain Processing ──────────────────────────────────

  const processDomain = useCallback(async (domain: string): Promise<DomainEntry> => {
    const entry: DomainEntry = {
      domain, status: "checking", whois: null, verification: null,
      registrarCheck: null, registration: null, error: null, tagged: false,
      dns: null, httpProbe: null, wayback: null, domainAge: null,
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
        } catch {}
      }

      if (whois.available && verification.confidence === "high") { entry.status = "available"; log(`● AVAIL ${domain} [${verification.confidence}]`, theme.primary); }
      else if (whois.expired) { entry.status = "expired"; log(`◈ EXPRD ${domain}`, theme.pending); }
      else if (whois.available) { entry.status = "available"; log(`● AVAIL ${domain} [${verification.confidence}]`, theme.primary); }
      else { entry.status = "taken"; log(`✕ TAKEN ${domain}`, theme.textDisabled); }

      return entry;
    } catch (err: any) {
      entry.status = "error"; entry.error = err.message;
      log(`ERR ${domain}: ${err.message}`, theme.error);
      return entry;
    }
  }, [registrarConfig, log]);

  const processAllDomains = useCallback(async (domainList: string[], append = false) => {
    if (processingRef.current) return;
    processingRef.current = true;
    setMode("scanning");

    const entries: DomainEntry[] = domainList.map((d) => ({
      domain: d, status: "pending" as DomainStatus, whois: null,
      verification: null, registrarCheck: null, registration: null, error: null, tagged: false,
      dns: null, httpProbe: null, wayback: null, domainAge: null,
    }));

    if (append) {
      setDomains((prev: DomainEntry[]) => [...prev, ...entries]);
    } else {
      setDomains(entries);
    }

    const startIdx = append ? domains.length : 0;
    log(`━━━ Scanning ${domainList.length} domain${domainList.length > 1 ? "s" : ""} ━━━`, theme.info);

    for (let i = 0; i < entries.length; i++) {
      const globalIdx = startIdx + i;
      setDomains((prev: DomainEntry[]) => { const u = [...prev]; if (u[globalIdx]) u[globalIdx] = { ...u[globalIdx]!, status: "checking" }; return u; });
      if (!append) setSelectedIndex(i);
      const result = await processDomain(domainList[i]!);
      setDomains((prev: DomainEntry[]) => { const u = [...prev]; u[globalIdx] = result; return u; });

      if (autoRegister && registrarConfig?.apiKey && (result.status === "available" || result.status === "expired")) {
        setDomains((prev: DomainEntry[]) => { const u = [...prev]; if (u[globalIdx]) u[globalIdx] = { ...u[globalIdx]!, status: "registering" }; return u; });
        try {
          const regResult = await registerDomain(domainList[i]!, registrarConfig);
          setDomains((prev: DomainEntry[]) => {
            const u = [...prev];
            if (u[globalIdx]) u[globalIdx] = { ...u[globalIdx]!, status: regResult.success ? "registered" : u[globalIdx]!.status, registration: regResult };
            return u;
          });
          if (regResult.success) log(`★ REG'd ${domainList[i]}`, theme.secondary);
        } catch {}
      }

      if (i < entries.length - 1) await new Promise((r) => setTimeout(r, 1500));
    }

    processingRef.current = false;
    setMode("done");
    log("━━━ Scan complete ━━━", theme.info);
  }, [autoRegister, registrarConfig, processDomain, log, domains.length]);

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

      // Register
      else if (key === "r" && selected) {
        if ((selected.status === "available" || selected.status === "expired") && registrarConfig?.apiKey) {
          handleRegister(domains.indexOf(selected));
        } else if (!registrarConfig?.apiKey) log("No registrar configured", theme.warning);
      }

      // Bulk register tagged
      else if (key === "R") {
        const tagged = domains.filter((d) => d.tagged && (d.status === "available" || d.status === "expired"));
        if (tagged.length > 0 && registrarConfig?.apiKey) {
          log(`Bulk registering ${tagged.length} domains...`, theme.info);
          for (const d of tagged) handleRegister(domains.indexOf(d));
        } else {
          log("Tag domains with SPACE first, then R to bulk register", theme.warning);
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

    if (inputMode === "file") {
      if (existsSync(v)) {
        const content = readFileSync(v, "utf-8");
        const list = parseDomainList(content);
        if (list.length > 0) { log(`Loaded ${list.length} domains from ${v}`, theme.info); processAllDomains(list); }
        else log("No valid domains in file", theme.warning);
      } else { log("File not found: " + v, theme.error); setMode(domains.length > 0 ? "done" : "idle"); }
    } else if (inputMode === "expand") {
      const expanded = expandTlds(v, "popular");
      log(`Expanded "${v}" into ${expanded.length} TLD variants`, theme.info);
      if (expanded.length > 0) processAllDomains(expanded, domains.length > 0);
      else { setMode(domains.length > 0 ? "done" : "idle"); }
    } else if (inputMode === "export") {
      try {
        const path = v.endsWith(".json") ? exportToJSON(domains, v) : exportToCSV(domains, v);
        log(`Exported ${domains.length} domains to ${path}`, theme.primary);
      } catch (err: any) { log(`Export failed: ${err.message}`, theme.error); }
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
        if (list.length > 0) processAllDomains(list, domains.length > 0);
        else log("No valid domains", theme.warning);
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

  const score = selected ? scoreDomain(selected.domain) : null;
  const grade = score ? scoreGrade(score.total) : null;

  // ─── Layout ─────────────────────────────────────────────

  const sidebarW = Math.max(32, Math.min(48, Math.floor(width * 0.42)));
  const hLine = (w: number) => "─".repeat(Math.max(1, w - 2));
  const dLine = (w: number) => "═".repeat(Math.max(1, w - 2));
  const logPanelH = Math.max(4, Math.floor((height - 5) * 0.28));

  const inputLabel = inputMode === "file" ? "FILE" : inputMode === "expand" ? "EXPAND" : inputMode === "export" ? "EXPORT" : inputMode === "load" ? "LOAD" : "SCAN";
  const inputPlaceholder = inputMode === "file" ? "/path/to/domains.txt" : inputMode === "expand" ? "coolstartup" : inputMode === "export" ? "results.csv or results.json" : inputMode === "load" ? "session-id or path" : "domains or /path/to/file";

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
              mode === "scanning" ? " SCANNING " : mode === "watching" ? ` WATCH #${watchCycle} ` : mode === "done" ? " READY " : mode === "input" ? ` ${inputLabel} ` : " IDLE "
            } fg={theme.background} /></box>
            {filter.status !== "all" && (
              <box backgroundColor={theme.secondaryDim}><text content={` ${filter.status.toUpperCase()} `} fg={theme.secondary} /></box>
            )}
            {filter.sort !== "domain" && (
              <box backgroundColor={theme.accentDim}><text content={` ↕${filter.sort} `} fg={theme.accent} /></box>
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
          </box>
        </box>
        <text content={dLine(width)} fg={theme.border} paddingLeft={1} />
      </box>

      {/* ═══ BODY ═══ */}
      <box flexGrow={1} flexDirection="row" minHeight={0}>

        {/* ─── LEFT PANEL ─── */}
        <box width={sidebarW} flexDirection="column" minHeight={0}>
          <box flexDirection="row" justifyContent="space-between" paddingLeft={1} paddingRight={1} flexShrink={0}>
            <text content={` TARGETS ${filteredDomains.length !== stats.total ? `(${filteredDomains.length}/${stats.total})` : stats.total > 0 ? `(${stats.total})` : ""}`} fg={theme.primary} />
            {stats.checking > 0 && <text content={`◆ ${stats.checking}`} fg={theme.warning} />}
          </box>
          <text content={hLine(sidebarW)} fg={theme.borderSubtle} paddingLeft={1} />

          {filteredDomains.length > 0 ? (
            <scrollbox flexGrow={1} paddingLeft={1} minHeight={0} scrollbarOptions={{ visible: false }}>
              {filteredDomains.map((entry: DomainEntry, i: number) => {
                const active = selectedIndex === i;
                const ss = statusStyle(entry.status);
                const sc = scoreDomain(entry.domain);
                const gr = scoreGrade(sc.total);
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
            {logs.map((l: { time: string; msg: string; fg: string }, i: number) => (
              <box key={i} flexDirection="row" gap={1}>
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
                <text content="  Home End      First / last" fg={theme.textSecondary} />
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
                <text content="  R             Bulk register tagged" fg={theme.textSecondary} />
                <text content="  w             Watch tagged (1h)" fg={theme.textSecondary} />
                <text content="" />
                <text content="Filter & Sort" fg={theme.secondary} />
                <text content="  s             Cycle status filter" fg={theme.textSecondary} />
                <text content="  o             Cycle sort field" fg={theme.textSecondary} />
                <text content="  O             Toggle sort order" fg={theme.textSecondary} />
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
            <scrollbox flexGrow={1} paddingLeft={1} paddingRight={1} minHeight={0} scrollbarOptions={{ visible: false }}>
              <box flexDirection="column" gap={0} paddingRight={1}>

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

                <text content="" />

                {/* WHOIS */}
                {selected.whois && !selected.whois.available && (
                  <box flexDirection="column" paddingLeft={1}>
                    <box flexDirection="row" gap={1}><text content="┃" fg={theme.secondary} /><text content="WHOIS" fg={theme.secondary} /></box>
                    {selected.whois.registrar && (<box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("Registrar", 12)} fg={theme.textMuted} /><text content={selected.whois.registrar} fg={theme.text} /></box>)}
                    {selected.whois.createdDate && (<box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("Created", 12)} fg={theme.textMuted} /><text content={selected.whois.createdDate} fg={theme.text} /></box>)}
                    {selected.whois.expiryDate && (<box flexDirection="row" gap={1}><text content="┃" fg={theme.borderSubtle} /><text content={pad("Expires", 12)} fg={theme.textMuted} /><text content={selected.whois.expiryDate} fg={selected.whois.expired ? theme.error : theme.text} /></box>)}
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

                {(selected.status === "pending") && <box paddingLeft={2} paddingTop={2}><text content="Queued..." fg={theme.textDisabled} /></box>}
                {(selected.status === "checking") && <box paddingLeft={2} paddingTop={2}><text content="Scanning..." fg={theme.warning} /></box>}
              </box>
            </scrollbox>
          ) : (
            <box flexGrow={1} alignItems="center" justifyContent="center" minHeight={0} flexDirection="column">
              <text content="┌────────────────────────────┐" fg={theme.borderSubtle} />
              <text content="│  /  scan domains           │" fg={theme.textMuted} />
              <text content="│  f  load from file         │" fg={theme.textMuted} />
              <text content="│  e  TLD expansion          │" fg={theme.textMuted} />
              <text content="│  ?  all commands            │" fg={theme.textMuted} />
              <text content="└────────────────────────────┘" fg={theme.borderSubtle} />
            </box>
          )}
        </box>
      </box>

      {/* ═══ INPUT BAR ═══ */}
      {mode === "input" && (
        <box flexShrink={0} flexDirection="row" paddingLeft={1} paddingRight={1} backgroundColor={theme.backgroundPanel} gap={1}>
          <box backgroundColor={theme.info}><text content={` ${inputLabel} `} fg={theme.background} /></box>
          <input
            focused value={inputValue}
            placeholder={inputPlaceholder}
            placeholderColor={theme.textPlaceholder} cursorColor={theme.primary}
            focusedTextColor={theme.text} focusedBackgroundColor={theme.backgroundPanel}
            width={width - inputLabel.length - 6}
            onChange={(v: string) => setInputValue(v)}
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
              <>
                <box backgroundColor={theme.textDisabled}><text content=" / " fg={theme.background} /></box><text content="scan" fg={theme.textMuted} />
                <box backgroundColor={theme.textDisabled}><text content=" e " fg={theme.background} /></box><text content="expand" fg={theme.textMuted} />
                <box backgroundColor={theme.textDisabled}><text content=" v " fg={theme.background} /></box><text content="vars" fg={theme.textMuted} />
                <box backgroundColor={theme.textDisabled}><text content=" ␣ " fg={theme.background} /></box><text content="tag" fg={theme.textMuted} />
                {registrarConfig?.apiKey && (<><box backgroundColor={theme.textDisabled}><text content=" r " fg={theme.background} /></box><text content="reg" fg={theme.textMuted} /></>)}
                <box backgroundColor={theme.textDisabled}><text content=" ? " fg={theme.background} /></box><text content="help" fg={theme.textMuted} />
              </>
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
