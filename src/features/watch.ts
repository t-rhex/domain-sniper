/**
 * Watch mode — monitor domains at an interval
 */

import { whoisLookup, verifyAvailability } from "../whois.js";
import { exec } from "child_process";

export interface WatchConfig {
  domains: string[];
  intervalMs: number;       // default 3600000 (1 hour)
  notify: boolean;          // desktop notifications
  onAvailable?: (domain: string) => void;
  onCheck?: (domain: string, status: string) => void;
  onCycle?: (cycle: number) => void;
}

export class DomainWatcher {
  private config: WatchConfig;
  private timer: ReturnType<typeof setInterval> | null = null;
  private cycle = 0;
  private _running = false;

  constructor(config: WatchConfig) {
    this.config = {
      ...{ intervalMs: 3600000, notify: true },
      ...config,
    };
  }

  get running() { return this._running; }

  async checkOnce(): Promise<Map<string, string>> {
    const results = new Map<string, string>();

    for (const domain of this.config.domains) {
      this.config.onCheck?.(domain, "checking");

      const whois = await whoisLookup(domain);
      const verify = await verifyAvailability(domain);

      let status = "taken";
      if (whois.available && verify.confidence === "high") status = "available";
      else if (whois.expired) status = "expired";
      else if (whois.available) status = "available";

      results.set(domain, status);
      this.config.onCheck?.(domain, status);

      if ((status === "available" || status === "expired") && this.config.notify) {
        this.config.onAvailable?.(domain);
        sendDesktopNotification(domain, status);
      }

      // Rate limit
      await new Promise((r) => setTimeout(r, 2000));
    }

    return results;
  }

  start() {
    if (this._running) return;
    this._running = true;
    this.cycle = 0;

    // Run immediately
    this.runCycle();

    // Set interval
    this.timer = setInterval(() => this.runCycle(), this.config.intervalMs);
  }

  stop() {
    this._running = false;
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  addDomain(domain: string) {
    if (!this.config.domains.includes(domain)) {
      this.config.domains.push(domain);
    }
  }

  removeDomain(domain: string) {
    this.config.domains = this.config.domains.filter((d) => d !== domain);
  }

  private async runCycle() {
    this.cycle++;
    this.config.onCycle?.(this.cycle);
    await this.checkOnce();
  }
}

function sendDesktopNotification(domain: string, status: string) {
  const title = "Domain Sniper";
  const msg = status === "available"
    ? `${domain} is AVAILABLE!`
    : `${domain} has EXPIRED and may be available soon`;

  // macOS notification
  try {
    exec(`osascript -e 'display notification "${msg}" with title "${title}" sound name "Glass"'`);
  } catch {
    // Notification failed silently
  }
}

export function formatInterval(ms: number): string {
  if (ms < 60000) return `${Math.round(ms / 1000)}s`;
  if (ms < 3600000) return `${Math.round(ms / 60000)}m`;
  return `${(ms / 3600000).toFixed(1)}h`;
}
