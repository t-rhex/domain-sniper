import { execFile } from "child_process";
import { promisify } from "util";
import { whoisLookup } from "../whois.js";
import { registerDomain, loadConfigFromEnv, type RegistrarConfig } from "../registrar.js";
import { assertValidDomain } from "../validate.js";
import {
  addSnipe, getSnipe, getActiveSnipes, updateSnipeStatus, updateSnipeCheck,
  markSnipeRegistered, type SnipeStatus, type SnipePhase,
} from "../db.js";
import { sendWebhook, type WebhookPayload } from "./webhooks.js";
import { loadConfig } from "./config.js";

const execFileAsync = promisify(execFile);

export interface SnipeConfig {
  registrarConfig: RegistrarConfig | null;
  webhookUrl?: string;
  maxPrice?: number;
  onStatusChange?: (domain: string, status: SnipeStatus, phase: SnipePhase, message: string) => void;
  onRegistered?: (domain: string) => void;
  onFailed?: (domain: string, error: string) => void;
}

export interface SnipeTarget {
  domain: string;
  expiryDate: string | null;
  status: SnipeStatus;
  phase: SnipePhase;
  checkCount: number;
  lastChecked: string | null;
  lastStatus: string | null;
}

// Phase intervals
const PHASE_INTERVALS: Record<SnipePhase, number> = {
  hourly: 3600000,      // 1 hour — domain is registered, just watching
  frequent: 300000,     // 5 minutes — domain expired, checking often
  aggressive: 30000,    // 30 seconds — domain in pending delete, sniping
};

export class SnipeEngine {
  private config: SnipeConfig;
  private timer: ReturnType<typeof setInterval> | null = null;
  private _running = false;

  constructor(config: SnipeConfig) {
    this.config = config;
  }

  get running() { return this._running; }

  async start(): Promise<void> {
    if (this._running) return;
    this._running = true;

    this.emit("engine", "watching", "hourly", "Snipe engine started");

    // Run immediately
    await this.tick();

    // Main loop — check every 30s, but only act on domains whose interval has elapsed
    this.timer = setInterval(() => { void this.tick(); }, 30000);
  }

  stop(): void {
    this._running = false;
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  private emit(domain: string, status: SnipeStatus, phase: SnipePhase, message: string) {
    this.config.onStatusChange?.(domain, status, phase, message);
  }

  private async tick(): Promise<void> {
    if (!this._running) return;
    const snipes = getActiveSnipes();

    for (const snipe of snipes) {
      // Check if enough time has elapsed since last check
      const interval = PHASE_INTERVALS[snipe.phase as SnipePhase] || PHASE_INTERVALS.hourly;
      if (snipe.last_checked) {
        const elapsed = Date.now() - new Date(snipe.last_checked + "Z").getTime();
        if (elapsed < interval) continue;
      }

      await this.checkDomain(snipe);

      // Small delay between domains to avoid rate limiting
      await new Promise((r) => setTimeout(r, 2000));
    }
  }

  private async checkDomain(snipe: any): Promise<void> {
    const domain = snipe.domain;

    try {
      // Quick DNS check first (fastest)
      const _hasNs = await this.hasNameservers(domain);

      // Full WHOIS check
      const whois = await whoisLookup(domain);

      if (whois.available) {
        // DOMAIN IS AVAILABLE — attempt registration!
        this.emit(domain, "registering", "aggressive", `${domain} is AVAILABLE — registering!`);
        updateSnipeStatus(domain, "registering", "aggressive");

        await this.attemptRegistration(domain, snipe);
        return;
      }

      if (whois.expired) {
        // Domain is expired — ramp up checking
        const currentPhase = snipe.phase as SnipePhase;

        // Check for pending delete indicators
        const isPendingDelete = whois.status.some((s: string) =>
          s.toLowerCase().includes("pendingdelete") || s.toLowerCase().includes("pending delete")
        );

        if (isPendingDelete) {
          // About to drop — go aggressive
          if (currentPhase !== "aggressive") {
            updateSnipeStatus(domain, "dropping", "aggressive");
            this.emit(domain, "dropping", "aggressive", `${domain} is PENDING DELETE — checking every 30s!`);
            await this.notify(domain, "dropping", `${domain} is in pending delete — sniping aggressively!`);
          }
        } else {
          // Expired but not yet pending delete
          if (currentPhase === "hourly") {
            updateSnipeStatus(domain, "expiring", "frequent");
            this.emit(domain, "expiring", "frequent", `${domain} has EXPIRED — checking every 5 min`);
            await this.notify(domain, "expiring", `${domain} has expired — monitoring closely`);
          }
        }

        updateSnipeCheck(domain, whois.expired ? "expired" : "taken");
      } else {
        // Still registered and active
        updateSnipeCheck(domain, "taken");

        // Check if expiry date is approaching
        if (whois.expiryDate) {
          const daysLeft = Math.floor((new Date(whois.expiryDate).getTime() - Date.now()) / 86400000);
          if (daysLeft <= 30 && snipe.phase === "hourly") {
            this.emit(domain, "watching", "hourly", `${domain} expires in ${daysLeft} days`);
          }
        }
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Check failed";
      updateSnipeCheck(domain, `error: ${msg}`);
    }
  }

  private async attemptRegistration(domain: string, snipe: any): Promise<void> {
    const config = this.config.registrarConfig || loadConfigFromEnv();
    if (!config?.apiKey) {
      updateSnipeStatus(domain, "failed");
      this.emit(domain, "failed", "aggressive", "No registrar configured — cannot register");
      this.config.onFailed?.(domain, "No registrar configured");
      await this.notify(domain, "failed", `${domain} is available but no registrar configured!`);
      return;
    }

    // Check price constraint
    if (snipe.max_price) {
      // We don't have real-time pricing here, so just attempt registration
    }

    try {
      const result = await registerDomain(domain, config);

      if (result.success) {
        markSnipeRegistered(domain);
        this.emit(domain, "registered", "aggressive", `SUCCESS — ${domain} registered!`);
        this.config.onRegistered?.(domain);
        await this.notify(domain, "registered", `${domain} has been REGISTERED successfully!`);
      } else {
        // Registration failed — keep trying
        updateSnipeCheck(domain, `reg-failed: ${result.error}`);
        this.emit(domain, "dropping", "aggressive", `Registration attempt failed: ${result.error} — retrying...`);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Registration error";
      updateSnipeCheck(domain, `reg-error: ${msg}`);
      this.emit(domain, "dropping", "aggressive", `Registration error: ${msg} — retrying...`);
    }
  }

  private async hasNameservers(domain: string): Promise<boolean> {
    try {
      assertValidDomain(domain);
      const { stdout } = await execFileAsync("dig", ["+short", domain, "NS"], { timeout: 5000 });
      return !!stdout.trim();
    } catch {
      return false;
    }
  }

  private async notify(domain: string, status: string, message: string): Promise<void> {
    // Desktop notification
    try {
      const script = `display notification "${message.replace(/["\\]/g, "")}" with title "Domain Sniper" sound name "Glass"`;
      execFileAsync("osascript", ["-e", script]).catch(() => {});
    } catch {}

    // Webhook
    const webhookUrl = this.config.webhookUrl || loadConfig().notifications.webhookUrl;
    if (webhookUrl) {
      const payload: WebhookPayload = {
        domain,
        status,
        timestamp: new Date().toISOString(),
        details: { message },
      };
      await sendWebhook(webhookUrl, payload).catch(() => {});
    }
  }
}

// ─── Convenience functions ───────────────────────────────

export function snipeDomain(domain: string, options: {
  expiryDate?: string;
  maxPrice?: number;
} = {}): number {
  assertValidDomain(domain);
  return addSnipe(domain, {
    expiryDate: options.expiryDate,
    maxPrice: options.maxPrice,
  });
}

export function cancelSnipe(domain: string): void {
  updateSnipeStatus(domain, "cancelled");
}

export function getSnipeTargets(): SnipeTarget[] {
  const snipes = getActiveSnipes();
  return snipes.map((s: any) => ({
    domain: s.domain,
    expiryDate: s.expiry_date,
    status: s.status,
    phase: s.phase,
    checkCount: s.check_count,
    lastChecked: s.last_checked,
    lastStatus: s.last_status,
  }));
}

export function createSnipeEngine(config: Partial<SnipeConfig> = {}): SnipeEngine {
  return new SnipeEngine({
    registrarConfig: config.registrarConfig || loadConfigFromEnv(),
    webhookUrl: config.webhookUrl,
    maxPrice: config.maxPrice,
    onStatusChange: config.onStatusChange,
    onRegistered: config.onRegistered,
    onFailed: config.onFailed,
  });
}
