import { whoisLookup } from "../whois.js";
import { registerDomain, type RegistrarConfig } from "../registrar.js";
import { assertValidDomain } from "../validate.js";
import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);

export interface DropCatchConfig {
  domain: string;
  registrarConfig: RegistrarConfig;
  pollIntervalMs?: number;       // how often to check (default: 30000 = 30s)
  maxAttempts?: number;           // max polling cycles (default: 2880 = 24h at 30s)
  onStatus?: (status: DropCatchStatus) => void;
  onSuccess?: (domain: string) => void;
  onFailed?: (domain: string, error: string) => void;
}

export interface DropCatchStatus {
  domain: string;
  attempt: number;
  maxAttempts: number;
  phase: "watching" | "detected" | "registering" | "success" | "failed" | "expired_timeout";
  message: string;
  timestamp: string;
}

type ResolvedDropCatchConfig = DropCatchConfig & Required<Pick<DropCatchConfig, "pollIntervalMs" | "maxAttempts">>;

export class DropCatcher {
  private config: ResolvedDropCatchConfig;
  private timer: ReturnType<typeof setInterval> | null = null;
  private attempt = 0;
  private _running = false;
  private _succeeded = false;

  constructor(config: DropCatchConfig) {
    assertValidDomain(config.domain);
    this.config = {
      pollIntervalMs: 30000,
      maxAttempts: 2880,
      ...config,
    };
  }

  get running() { return this._running; }
  get succeeded() { return this._succeeded; }

  private emit(phase: DropCatchStatus["phase"], message: string) {
    this.config.onStatus?.({
      domain: this.config.domain,
      attempt: this.attempt,
      maxAttempts: this.config.maxAttempts,
      phase,
      message,
      timestamp: new Date().toISOString(),
    });
  }

  async start(): Promise<void> {
    if (this._running) return;
    this._running = true;
    this.attempt = 0;

    this.emit("watching", `Monitoring ${this.config.domain} for drop...`);

    // Initial check
    await this.poll();

    // Set up polling
    this.timer = setInterval(() => {
      void this.poll();
    }, this.config.pollIntervalMs);
  }

  stop(): void {
    this._running = false;
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  private async poll(): Promise<void> {
    if (!this._running) return;
    this.attempt++;

    if (this.attempt > this.config.maxAttempts) {
      this.emit("expired_timeout", "Max attempts reached, stopping.");
      this.stop();
      this.config.onFailed?.(this.config.domain, "Max attempts reached");
      return;
    }

    try {
      // Quick DNS check first (faster than full WHOIS)
      const dnsAvailable = await this.quickDnsCheck();

      if (dnsAvailable) {
        this.emit("detected", "Domain may be available! Verifying...");

        // Verify with WHOIS
        const whois = await whoisLookup(this.config.domain);

        if (whois.available) {
          this.emit("registering", "Domain is available! Attempting registration...");

          // Attempt registration immediately
          const result = await registerDomain(this.config.domain, this.config.registrarConfig);

          if (result.success) {
            this._succeeded = true;
            this.emit("success", `Successfully registered ${this.config.domain}!`);
            this.config.onSuccess?.(this.config.domain);
            this.stop();
          } else {
            this.emit("failed", `Registration failed: ${result.error || "Unknown error"}`);
            // Don't stop — keep trying in case of transient failure
          }
        } else {
          this.emit("watching", `Attempt ${this.attempt}/${this.config.maxAttempts} — DNS empty but WHOIS still registered`);
        }
      } else {
        if (this.attempt % 10 === 0) {
          this.emit("watching", `Attempt ${this.attempt}/${this.config.maxAttempts} — still registered`);
        }
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      this.emit("watching", `Check error: ${msg} (will retry)`);
    }
  }

  private async quickDnsCheck(): Promise<boolean> {
    try {
      const { stdout } = await execFileAsync("dig", ["+short", this.config.domain, "NS"], { timeout: 5000 });
      // Empty response = no nameservers = possibly available
      return !stdout.trim();
    } catch {
      return false;
    }
  }
}

export function createDropCatcher(config: DropCatchConfig): DropCatcher {
  return new DropCatcher(config);
}

export function formatDropCatchStatus(status: DropCatchStatus): string {
  const progress = `[${status.attempt}/${status.maxAttempts}]`;
  switch (status.phase) {
    case "watching": return `${progress} Watching ${status.domain}...`;
    case "detected": return `${progress} DETECTED — ${status.domain} may be dropping!`;
    case "registering": return `${progress} REGISTERING ${status.domain}...`;
    case "success": return `${progress} SUCCESS — ${status.domain} registered!`;
    case "failed": return `${progress} FAILED — ${status.message}`;
    case "expired_timeout": return `${progress} TIMEOUT — stopped monitoring`;
  }
}
