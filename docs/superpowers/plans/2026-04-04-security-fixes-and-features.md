# Domain Sniper: Security Fixes + New Features Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all critical security vulnerabilities (command injection, path traversal, type safety) and add 7 new features (concurrent scanning, DNS details, HTTP probe, domain age, Wayback Machine, bulk paste, price comparison).

**Architecture:** Security fixes create a validation layer (`src/validate.ts`) that all user input passes through before reaching shell commands or filesystem. New features are added as independent modules in `src/features/` that plug into the existing `processDomain` pipeline. The TUI INTEL panel is extended to display new data.

**Tech Stack:** Bun, TypeScript (strict), @opentui/react, child_process (execFile only), fetch API

---

## File Structure

### New files to create:
- `src/validate.ts` — Domain regex validation, path confinement, input sanitization
- `src/features/dns-details.ts` — Full DNS record lookup (A, AAAA, MX, TXT, CNAME)
- `src/features/http-probe.ts` — HTTP status, redirect detection, server headers, parked page detection
- `src/features/wayback.ts` — Wayback Machine API check for archived history
- `src/features/domain-age.ts` — Human-readable age calculation from WHOIS dates
- `src/features/price-compare.ts` — Multi-registrar price comparison

### Files to modify:
- `src/whois.ts` — Replace `exec` with `execFile`, add domain validation
- `src/features/watch.ts` — Fix osascript injection
- `src/features/session.ts` — Restrict to bare session IDs, fix mixed imports, type `any`
- `src/features/export.ts` — Path confinement, fix empty guard, type `any`
- `src/features/filter.ts` — Replace `any` with `DomainEntry` type
- `src/registrar.ts` — Fix Cloudflare logic, type API responses, validate config
- `src/app.tsx` — Integrate new features, fix floating promises, fix race condition, add concurrent scanning, extend INTEL panel
- `src/index.tsx` — Add concurrency option, validate inputs
- `src/types.ts` — Extract shared `DomainEntry` type for cross-module use

---

## Phase 1: Security Fixes

### Task 1: Create validation module

**Files:**
- Create: `src/validate.ts`

- [ ] **Step 1: Create `src/validate.ts` with domain regex, path confinement, session ID validation**

```typescript
import { resolve, normalize } from "path";

const DOMAIN_RE = /^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$/;
const SESSION_ID_RE = /^[a-z0-9\-]+$/;

export function isValidDomain(domain: string): boolean {
  return DOMAIN_RE.test(domain) && domain.length <= 253;
}

export function assertValidDomain(domain: string): void {
  if (!isValidDomain(domain)) {
    throw new Error(`Invalid domain: ${domain}`);
  }
}

export function sanitizeDomainList(domains: string[]): string[] {
  return domains.filter(isValidDomain);
}

export function isValidSessionId(id: string): boolean {
  return SESSION_ID_RE.test(id) && id.length <= 100;
}

export function safePath(input: string, allowedRoots: string[]): string {
  const resolved = resolve(normalize(input));
  const allowed = allowedRoots.some(
    (root) => resolved.startsWith(root + "/") || resolved === root
  );
  if (!allowed) {
    throw new Error(`Access denied: path outside allowed directories`);
  }
  return resolved;
}
```

- [ ] **Step 2: Verify file compiles**

Run: `bunx tsc --noEmit`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
git add src/validate.ts
git commit -m "feat: add input validation module for domain, path, and session ID safety"
```

---

### Task 2: Fix command injection in whois.ts

**Files:**
- Modify: `src/whois.ts`

- [ ] **Step 1: Replace `exec` with `execFile` and add validation**

In `src/whois.ts`, replace the imports and `execAsync`:

```typescript
// OLD
import { exec } from "child_process";
import { promisify } from "util";
const execAsync = promisify(exec);

// NEW
import { execFile } from "child_process";
import { promisify } from "util";
import { assertValidDomain, isValidDomain } from "./validate.js";
const execFileAsync = promisify(execFile);
```

- [ ] **Step 2: Fix `whoisLookup` to use `execFileAsync`**

Replace line 158:
```typescript
// OLD
const { stdout, stderr } = await execAsync(`whois ${domain}`, { timeout: 15000 });

// NEW
assertValidDomain(domain);
const { stdout, stderr } = await execFileAsync("whois", [domain], { timeout: 15000 });
```

- [ ] **Step 3: Fix `verifyAvailability` DNS checks**

Replace lines 210 and 226:
```typescript
// OLD
const { stdout } = await execAsync(`dig +short ${domain} A`, { timeout: 10000 });
// ...
const { stdout } = await execAsync(`dig +short ${domain} NS`, { timeout: 10000 });

// NEW
assertValidDomain(domain);
const { stdout } = await execFileAsync("dig", ["+short", domain, "A"], { timeout: 10000 });
// ...
const { stdout } = await execFileAsync("dig", ["+short", domain, "NS"], { timeout: 10000 });
```

- [ ] **Step 4: Fix `parseDomainList` to validate domains**

```typescript
export function parseDomainList(content: string): string[] {
  return content
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#") && !line.startsWith("//"))
    .map((line) => line.toLowerCase())
    .filter(isValidDomain);
}
```

- [ ] **Step 5: Verify compiles and test with a domain**

Run: `bunx tsc --noEmit`

- [ ] **Step 6: Commit**

```bash
git add src/whois.ts
git commit -m "fix: replace exec with execFile to prevent command injection in WHOIS/DNS lookups"
```

---

### Task 3: Fix osascript injection in watch.ts

**Files:**
- Modify: `src/features/watch.ts`

- [ ] **Step 1: Replace `exec` with `execFile` in `sendDesktopNotification`**

```typescript
// OLD
import { exec } from "child_process";
// ...
function sendDesktopNotification(domain: string, status: string) {
  const title = "Domain Sniper";
  const msg = status === "available"
    ? `${domain} is AVAILABLE!`
    : `${domain} has EXPIRED and may be available soon`;
  try {
    exec(`osascript -e 'display notification "${msg}" with title "${title}" sound name "Glass"'`);
  } catch {}
}

// NEW
import { execFile } from "child_process";
// ...
function sendDesktopNotification(domain: string, status: string) {
  const msg = status === "available"
    ? `${domain} is AVAILABLE!`
    : `${domain} has EXPIRED and may be available soon`;
  const script = `display notification "${msg.replace(/["\\]/g, "")}" with title "Domain Sniper" sound name "Glass"`;
  execFile("osascript", ["-e", script], () => {});
}
```

- [ ] **Step 2: Also await `runCycle` promise in `setInterval`**

```typescript
// In start():
this.timer = setInterval(() => { void this.runCycle(); }, this.config.intervalMs);

// Initial call:
void this.runCycle();
```

- [ ] **Step 3: Commit**

```bash
git add src/features/watch.ts
git commit -m "fix: prevent osascript injection and handle async watch cycles"
```

---

### Task 4: Fix session.ts — path traversal, mixed imports, types

**Files:**
- Modify: `src/features/session.ts`

- [ ] **Step 1: Replace `require` with proper imports, restrict session loading to IDs only**

Full rewrite of `src/features/session.ts`:

```typescript
import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync, unlinkSync } from "fs";
import { join } from "path";
import { homedir } from "os";
import { isValidSessionId } from "../validate.js";
import type { DomainEntry } from "../types.js";

const SESSION_DIR = join(homedir(), ".domain-sniper", "sessions");

export interface SavedSession {
  id: string;
  timestamp: string;
  domains: DomainEntry[];
  watchlist: string[];
  tags: Record<string, string[]>;
  notes: Record<string, string>;
}

function ensureDir() {
  if (!existsSync(SESSION_DIR)) {
    mkdirSync(SESSION_DIR, { recursive: true });
  }
}

export function saveSession(
  domains: DomainEntry[],
  watchlist: string[] = [],
  tags: Record<string, string[]> = {},
  notes: Record<string, string> = {}
): string {
  ensureDir();
  const id = `scan-${Date.now()}`;
  const session: SavedSession = { id, timestamp: new Date().toISOString(), domains, watchlist, tags, notes };
  const path = join(SESSION_DIR, `${id}.json`);
  writeFileSync(path, JSON.stringify(session, null, 2), "utf-8");
  return path;
}

export function loadSession(id: string): SavedSession | null {
  if (!isValidSessionId(id)) return null;
  const path = join(SESSION_DIR, `${id}.json`);
  if (!existsSync(path)) return null;
  try {
    const content = readFileSync(path, "utf-8");
    const parsed = JSON.parse(content);
    if (!parsed || !Array.isArray(parsed.domains)) return null;
    return parsed as SavedSession;
  } catch {
    return null;
  }
}

export function listSessions(): { id: string; timestamp: string; count: number; path: string }[] {
  ensureDir();
  try {
    const files = readdirSync(SESSION_DIR);
    return files
      .filter((f) => f.endsWith(".json"))
      .map((f) => {
        try {
          const content = readFileSync(join(SESSION_DIR, f), "utf-8");
          const session = JSON.parse(content);
          if (!session || !Array.isArray(session.domains)) return null;
          return {
            id: session.id as string,
            timestamp: session.timestamp as string,
            count: (session.domains as unknown[]).length,
            path: join(SESSION_DIR, f),
          };
        } catch {
          return null;
        }
      })
      .filter((s): s is NonNullable<typeof s> => s !== null)
      .sort((a, b) => b.timestamp.localeCompare(a.timestamp));
  } catch {
    return [];
  }
}

export function deleteSession(id: string): boolean {
  if (!isValidSessionId(id)) return false;
  const path = join(SESSION_DIR, `${id}.json`);
  try {
    if (existsSync(path)) {
      unlinkSync(path);
      return true;
    }
  } catch {}
  return false;
}
```

- [ ] **Step 2: Commit**

```bash
git add src/features/session.ts
git commit -m "fix: restrict session load to IDs, remove path traversal, fix imports and types"
```

---

### Task 5: Extract shared DomainEntry type

**Files:**
- Create: `src/types.ts`

- [ ] **Step 1: Create `src/types.ts` with shared types**

```typescript
import type { WhoisResult } from "./whois.js";
import type { RegistrationResult } from "./registrar.js";
import type { DomainStatus } from "./theme.js";

export interface DnsDetails {
  a: string[];
  aaaa: string[];
  mx: string[];
  txt: string[];
  cname: string[];
}

export interface HttpProbeResult {
  status: number | null;
  redirectUrl: string | null;
  server: string | null;
  parked: boolean;
  reachable: boolean;
  error: string | null;
}

export interface WaybackResult {
  hasHistory: boolean;
  firstArchived: string | null;
  lastArchived: string | null;
  snapshots: number;
}

export interface DomainEntry {
  domain: string;
  status: DomainStatus;
  whois: WhoisResult | null;
  verification: { available: boolean; confidence: string; checks: string[] } | null;
  registrarCheck: { available: boolean; price?: number; currency?: string } | null;
  registration: RegistrationResult | null;
  dns: DnsDetails | null;
  httpProbe: HttpProbeResult | null;
  wayback: WaybackResult | null;
  domainAge: string | null;
  error: string | null;
  tagged: boolean;
}

export function createEmptyEntry(domain: string): DomainEntry {
  return {
    domain, status: "pending", whois: null, verification: null,
    registrarCheck: null, registration: null, dns: null,
    httpProbe: null, wayback: null, domainAge: null,
    error: null, tagged: false,
  };
}
```

- [ ] **Step 2: Commit**

```bash
git add src/types.ts
git commit -m "feat: extract shared DomainEntry type with new feature fields"
```

---

### Task 6: Fix registrar.ts — Cloudflare logic, type safety, config validation

**Files:**
- Modify: `src/registrar.ts`

- [ ] **Step 1: Fix Cloudflare availability check (inverted logic)**

```typescript
// OLD (line 241-248)
if (!data.success || data.result?.available) {
  return { domain, available: true, provider: "cloudflare" };
}

// NEW
if (data.success && data.result?.available) {
  return { domain, available: true, provider: "cloudflare" };
}
if (!data.success) {
  return { domain, available: false, provider: "cloudflare", error: data.errors?.[0]?.message || "API request failed" };
}
```

- [ ] **Step 2: Add typed API response interfaces to replace `any`**

Add at top of file:
```typescript
interface GodaddyAvailabilityResponse {
  available: boolean;
  price?: number;
  currency?: string;
}

interface GodaddyPurchaseResponse {
  orderId?: number;
  message?: string;
}

interface CloudflareResponse<T> {
  success: boolean;
  result?: T;
  errors?: { message: string }[];
}
```

Replace all `const data: any = await resp.json()` with typed versions.

- [ ] **Step 3: Validate config before returning in `loadConfigFromEnv`**

```typescript
export function loadConfigFromEnv(): RegistrarConfig | null {
  const provider = (process.env.REGISTRAR_PROVIDER || "").toLowerCase() as RegistrarProvider;
  if (!provider || !["godaddy", "namecheap", "cloudflare"].includes(provider)) return null;

  const apiKey = process.env.REGISTRAR_API_KEY || "";
  if (!apiKey) return null; // Don't return config with empty API key

  return {
    provider,
    apiKey,
    apiSecret: process.env.REGISTRAR_API_SECRET || "",
    accountId: process.env.CLOUDFLARE_ACCOUNT_ID || "",
    username: process.env.NAMECHEAP_USERNAME || "",
    clientIp: process.env.CLIENT_IP || "127.0.0.1",
  };
}
```

- [ ] **Step 4: Commit**

```bash
git add src/registrar.ts
git commit -m "fix: correct Cloudflare availability logic, add typed API responses, validate config"
```

---

### Task 7: Fix export.ts — path confinement, types, empty guard

**Files:**
- Modify: `src/features/export.ts`

- [ ] **Step 1: Add path confinement, replace `any` with `DomainEntry`, guard empty list**

```typescript
import { writeFileSync } from "fs";
import { scoreDomain } from "./scoring.js";
import { safePath } from "../validate.js";
import type { DomainEntry } from "../types.js";

// ... keep ExportEntry interface ...

function toExportEntry(d: DomainEntry): ExportEntry {
  // same logic but now typed
}

export function exportToCSV(domains: DomainEntry[], filePath: string): string {
  if (domains.length === 0) throw new Error("No domains to export");
  const safe = safePath(filePath, [process.cwd()]);
  const entries = domains.map(toExportEntry);
  // ... rest same ...
  writeFileSync(safe, csv, "utf-8");
  return safe;
}

export function exportToJSON(domains: DomainEntry[], filePath: string): string {
  if (domains.length === 0) throw new Error("No domains to export");
  const safe = safePath(filePath, [process.cwd()]);
  // ... rest same ...
  writeFileSync(safe, json, "utf-8");
  return safe;
}
```

- [ ] **Step 2: Commit**

```bash
git add src/features/export.ts
git commit -m "fix: add path confinement, typed params, and empty list guard to exports"
```

---

### Task 8: Fix filter.ts — replace `any`

**Files:**
- Modify: `src/features/filter.ts`

- [ ] **Step 1: Replace `any[]` with `DomainEntry[]`**

```typescript
import type { DomainEntry } from "../types.js";
// ...
export function filterDomains(domains: DomainEntry[], config: FilterConfig): DomainEntry[] {
  // same logic, no any
}
```

- [ ] **Step 2: Commit**

```bash
git add src/features/filter.ts
git commit -m "fix: replace any with DomainEntry type in filter module"
```

---

## Phase 2: New Features

### Task 9: DNS details module

**Files:**
- Create: `src/features/dns-details.ts`

- [ ] **Step 1: Create DNS lookup module using `execFile` for dig queries**

```typescript
import { execFile } from "child_process";
import { promisify } from "util";
import { assertValidDomain } from "../validate.js";
import type { DnsDetails } from "../types.js";

const execFileAsync = promisify(execFile);

async function digQuery(domain: string, type: string): Promise<string[]> {
  try {
    const { stdout } = await execFileAsync("dig", ["+short", domain, type], { timeout: 10000 });
    return stdout.trim().split("\n").filter(Boolean);
  } catch {
    return [];
  }
}

export async function lookupDns(domain: string): Promise<DnsDetails> {
  assertValidDomain(domain);
  const [a, aaaa, mx, txt, cname] = await Promise.all([
    digQuery(domain, "A"),
    digQuery(domain, "AAAA"),
    digQuery(domain, "MX"),
    digQuery(domain, "TXT"),
    digQuery(domain, "CNAME"),
  ]);
  return { a, aaaa, mx, txt, cname };
}
```

- [ ] **Step 2: Commit**

```bash
git add src/features/dns-details.ts
git commit -m "feat: add DNS details module (A, AAAA, MX, TXT, CNAME lookups)"
```

---

### Task 10: HTTP probe module

**Files:**
- Create: `src/features/http-probe.ts`

- [ ] **Step 1: Create HTTP probe with redirect/parked detection**

```typescript
import { assertValidDomain } from "../validate.js";
import type { HttpProbeResult } from "../types.js";

const PARKED_INDICATORS = [
  "parked", "for sale", "buy this domain", "domain parking",
  "godaddy", "sedo", "afternic", "hugedomains", "dan.com",
  "this domain is for sale", "under construction",
];

export async function httpProbe(domain: string): Promise<HttpProbeResult> {
  assertValidDomain(domain);

  for (const scheme of ["https", "http"] as const) {
    try {
      const resp = await fetch(`${scheme}://${domain}`, {
        redirect: "manual",
        signal: AbortSignal.timeout(8000),
        headers: { "User-Agent": "DomainSniper/2.0" },
      });

      const redirectUrl = resp.status >= 300 && resp.status < 400
        ? resp.headers.get("location")
        : null;

      let parked = false;
      try {
        const body = await resp.text();
        const lower = body.toLowerCase();
        parked = PARKED_INDICATORS.some((ind) => lower.includes(ind));
      } catch {}

      return {
        status: resp.status,
        redirectUrl,
        server: resp.headers.get("server"),
        parked,
        reachable: true,
        error: null,
      };
    } catch {
      continue;
    }
  }

  return { status: null, redirectUrl: null, server: null, parked: false, reachable: false, error: "Unreachable" };
}
```

- [ ] **Step 2: Commit**

```bash
git add src/features/http-probe.ts
git commit -m "feat: add HTTP probe with parked page and redirect detection"
```

---

### Task 11: Wayback Machine module

**Files:**
- Create: `src/features/wayback.ts`

- [ ] **Step 1: Create Wayback Machine availability check**

```typescript
import { assertValidDomain } from "../validate.js";
import type { WaybackResult } from "../types.js";

export async function checkWayback(domain: string): Promise<WaybackResult> {
  assertValidDomain(domain);

  try {
    const resp = await fetch(
      `https://web.archive.org/wayback/available?url=${encodeURIComponent(domain)}&timestamp=20000101`,
      { signal: AbortSignal.timeout(8000) }
    );
    const data = await resp.json() as {
      archived_snapshots?: {
        closest?: { available: boolean; timestamp: string; url: string };
      };
    };

    const closest = data.archived_snapshots?.closest;

    // Also get CDX count for snapshot estimate
    let snapshots = 0;
    let firstArchived: string | null = null;
    let lastArchived: string | null = null;

    try {
      const cdxResp = await fetch(
        `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(domain)}&output=json&limit=1&fl=timestamp&sort=asc`,
        { signal: AbortSignal.timeout(8000) }
      );
      const cdxFirst = await cdxResp.json() as string[][];
      if (cdxFirst.length > 1 && cdxFirst[1]) {
        firstArchived = formatWaybackTs(cdxFirst[1][0]!);
      }

      const cdxLastResp = await fetch(
        `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(domain)}&output=json&limit=1&fl=timestamp&sort=desc`,
        { signal: AbortSignal.timeout(8000) }
      );
      const cdxLast = await cdxLastResp.json() as string[][];
      if (cdxLast.length > 1 && cdxLast[1]) {
        lastArchived = formatWaybackTs(cdxLast[1][0]!);
      }

      // Rough count
      const countResp = await fetch(
        `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(domain)}&output=json&limit=0&showNumPages=true`,
        { signal: AbortSignal.timeout(8000) }
      );
      const countText = await countResp.text();
      snapshots = parseInt(countText, 10) || 0;
    } catch {}

    return {
      hasHistory: !!closest?.available || snapshots > 0,
      firstArchived,
      lastArchived,
      snapshots,
    };
  } catch {
    return { hasHistory: false, firstArchived: null, lastArchived: null, snapshots: 0 };
  }
}

function formatWaybackTs(ts: string): string {
  if (ts.length < 8) return ts;
  return `${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)}`;
}
```

- [ ] **Step 2: Commit**

```bash
git add src/features/wayback.ts
git commit -m "feat: add Wayback Machine history checker"
```

---

### Task 12: Domain age module

**Files:**
- Create: `src/features/domain-age.ts`

- [ ] **Step 1: Create domain age calculator**

```typescript
export function calculateDomainAge(createdDate: string | null): string | null {
  if (!createdDate) return null;

  try {
    const created = new Date(createdDate);
    if (isNaN(created.getTime())) return null;

    const now = new Date();
    const diffMs = now.getTime() - created.getTime();
    if (diffMs < 0) return "Not yet created";

    const days = Math.floor(diffMs / 86400000);
    if (days < 1) return "< 1 day";
    if (days < 30) return `${days}d`;
    if (days < 365) {
      const months = Math.floor(days / 30);
      return `${months}mo`;
    }

    const years = Math.floor(days / 365);
    const remainingMonths = Math.floor((days % 365) / 30);
    return remainingMonths > 0 ? `${years}y ${remainingMonths}mo` : `${years}y`;
  } catch {
    return null;
  }
}

export function daysUntilExpiry(expiryDate: string | null): number | null {
  if (!expiryDate) return null;
  try {
    const expiry = new Date(expiryDate);
    if (isNaN(expiry.getTime())) return null;
    return Math.floor((expiry.getTime() - Date.now()) / 86400000);
  } catch {
    return null;
  }
}
```

- [ ] **Step 2: Commit**

```bash
git add src/features/domain-age.ts
git commit -m "feat: add domain age and expiry countdown calculator"
```

---

### Task 13: Price comparison module

**Files:**
- Create: `src/features/price-compare.ts`

- [ ] **Step 1: Create multi-registrar price comparison**

```typescript
import {
  checkAvailabilityViaRegistrar,
  loadConfigFromEnv,
  type RegistrarConfig,
  type RegistrarProvider,
  type AvailabilityCheckResult,
} from "../registrar.js";

export interface PriceQuote {
  provider: RegistrarProvider;
  available: boolean;
  price?: number;
  currency?: string;
  error?: string;
}

export async function comparePrices(
  domain: string,
  configs: RegistrarConfig[]
): Promise<PriceQuote[]> {
  const results = await Promise.allSettled(
    configs.map((config) => checkAvailabilityViaRegistrar(domain, config))
  );

  return results.map((r, i) => {
    if (r.status === "fulfilled") {
      return {
        provider: r.value.provider,
        available: r.value.available,
        price: r.value.price,
        currency: r.value.currency,
        error: r.value.error,
      };
    }
    return {
      provider: configs[i]!.provider,
      available: false,
      error: r.reason?.message || "Failed",
    };
  });
}
```

- [ ] **Step 2: Commit**

```bash
git add src/features/price-compare.ts
git commit -m "feat: add multi-registrar price comparison"
```

---

## Phase 3: Integration into App

### Task 14: Rewrite app.tsx — concurrent scanning, new features, fix all remaining issues

**Files:**
- Modify: `src/app.tsx`
- Modify: `src/index.tsx`

This is the largest task. Key changes:

- [ ] **Step 1: Update imports and use `DomainEntry` from `src/types.ts`**

Remove the local `DomainEntry` interface from `app.tsx`. Import from `types.ts` instead. Import all new feature modules.

- [ ] **Step 2: Add concurrent domain scanning**

Replace the sequential `for` loop in `processAllDomains` with a concurrent pool:

```typescript
const CONCURRENCY = 5;

async function processPool(
  domainList: string[],
  processFn: (domain: string) => Promise<DomainEntry>,
  onResult: (index: number, result: DomainEntry) => void
): Promise<void> {
  let nextIndex = 0;

  async function worker() {
    while (nextIndex < domainList.length) {
      const i = nextIndex++;
      const domain = domainList[i]!;
      const result = await processFn(domain);
      onResult(i, result);
      // Rate limit per worker
      await new Promise((r) => setTimeout(r, 500));
    }
  }

  const workers = Array.from({ length: Math.min(CONCURRENCY, domainList.length) }, () => worker());
  await Promise.all(workers);
}
```

- [ ] **Step 3: Extend `processDomain` to call new feature modules**

After WHOIS + verification, add parallel calls:

```typescript
// After whois and verification...
const [dns, probe, wayback] = await Promise.all([
  lookupDns(domain).catch(() => null),
  httpProbe(domain).catch(() => null),
  checkWayback(domain).catch(() => null),
]);

entry.dns = dns;
entry.httpProbe = probe;
entry.wayback = wayback;
entry.domainAge = calculateDomainAge(entry.whois?.createdDate ?? null);
```

- [ ] **Step 4: Fix floating promises — await `handleRegister` in bulk mode**

```typescript
// OLD
for (const d of tagged) handleRegister(domains.indexOf(d));

// NEW
const registerPromises = tagged.map((d) => handleRegister(domains.indexOf(d)));
void Promise.allSettled(registerPromises);
```

- [ ] **Step 5: Fix race condition — use ref for domain count**

```typescript
const domainsCountRef = useRef(0);
// Update ref whenever domains change
useEffect(() => { domainsCountRef.current = domains.length; }, [domains.length]);

// In processAllDomains:
const startIdx = append ? domainsCountRef.current : 0;
```

Remove `domains.length` from `useCallback` dependency array.

- [ ] **Step 6: Fix swallowed errors — add logging to all catch blocks**

Replace all empty `catch {}` with `catch (err) { log(...) }`.

- [ ] **Step 7: Extend INTEL panel with new sections**

Add DNS Details, HTTP Probe, Wayback Machine, and Domain Age sections to the right panel, following the existing pattern of `┃` prefixed rows.

- [ ] **Step 8: Add `--concurrency` CLI option to `index.tsx`**

```typescript
.option("-c, --concurrency <n>", "Concurrent lookups (default 5)", "5")
```

Also fix `options: any` → proper typed interface.

- [ ] **Step 9: Verify everything compiles**

Run: `bunx tsc --noEmit`

- [ ] **Step 10: Manual test**

Run: `bun run src/index.tsx example.com google.com --headless`
Verify output shows DNS details, HTTP probe results, domain age.

- [ ] **Step 11: Commit**

```bash
git add src/app.tsx src/index.tsx
git commit -m "feat: concurrent scanning, DNS details, HTTP probe, Wayback, domain age integration

- Replace sequential scanning with 5-worker concurrent pool
- Add DNS details panel (A, AAAA, MX, TXT, CNAME)
- Add HTTP probe (status, redirects, parked page detection)
- Add Wayback Machine history check
- Add domain age display
- Fix floating promises in bulk register
- Fix race condition in append mode
- Log all previously swallowed errors"
```

---

### Task 15: Update headless mode in index.tsx

**Files:**
- Modify: `src/index.tsx`

- [ ] **Step 1: Add new feature output to headless mode**

After the existing WHOIS/verification output, add:

```typescript
// DNS
const dns = await lookupDns(domain);
if (dns.a.length) console.log(`    DNS A: ${dns.a.join(", ")}`);
if (dns.mx.length) console.log(`    DNS MX: ${dns.mx.join(", ")}`);

// HTTP probe
const probe = await httpProbe(domain);
if (probe.reachable) {
  console.log(`    HTTP: ${probe.status}${probe.parked ? " (PARKED)" : ""}${probe.server ? ` [${probe.server}]` : ""}`);
  if (probe.redirectUrl) console.log(`    Redirect: ${probe.redirectUrl}`);
}

// Wayback
const wb = await checkWayback(domain);
if (wb.hasHistory) {
  console.log(`    Wayback: ${wb.snapshots} snapshots (${wb.firstArchived} - ${wb.lastArchived})`);
}

// Age
const age = calculateDomainAge(whois.createdDate);
if (age) console.log(`    Age: ${age}`);
```

- [ ] **Step 2: Validate domain inputs before processing**

```typescript
import { sanitizeDomainList, isValidDomain } from "./validate.js";

// Validate CLI domain args
domainList = sanitizeDomainList(domainList);
if (domainList.length === 0) {
  console.error("No valid domains specified.");
  process.exit(1);
}
```

- [ ] **Step 3: Add file path validation**

```typescript
import { safePath } from "./validate.js";

if (options.file) {
  const filePath = safePath(options.file, [process.cwd()]);
  // ... use filePath instead of options.file
}
```

- [ ] **Step 4: Commit**

```bash
git add src/index.tsx
git commit -m "feat: add new feature output to headless mode, validate all inputs"
```

---

### Task 16: Final verification

- [ ] **Step 1: Type check**

Run: `bunx tsc --noEmit`

- [ ] **Step 2: Test TUI mode**

Run: `bun run src/index.tsx`
Verify: TUI launches, can enter domains, new panels show data

- [ ] **Step 3: Test headless mode**

Run: `bun run src/index.tsx example.com github.com --headless`
Verify: All sections display (WHOIS, DNS, HTTP, Wayback, Age)

- [ ] **Step 4: Test batch file**

Run: `bun run src/index.tsx -f domains.example.txt --headless`
Verify: Processes valid domains, rejects invalid ones

- [ ] **Step 5: Final commit if any remaining changes**
