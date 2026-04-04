import { readFileSync, writeFileSync, existsSync, mkdirSync } from "fs";
import { join } from "path";
import { homedir } from "os";
import type { RegistrarProvider } from "../registrar.js";

const CONFIG_DIR = join(homedir(), ".domain-sniper");
const CONFIG_FILE = join(CONFIG_DIR, "config.json");

export interface DomainSniperConfig {
  concurrency: number;
  rateLimitMs: number;
  defaultTldPreset: "popular" | "premium" | "startup" | "all";
  registrar: {
    provider: RegistrarProvider;
    apiKey: string;
    apiSecret: string;
    accountId: string;
    username: string;
    clientIp: string;
  } | null;
  notifications: {
    webhookUrl: string | null;
    emailTo: string | null;
    smtpHost: string | null;
    smtpPort: number;
    smtpUser: string | null;
    smtpPass: string | null;
  };
  watch: {
    intervalMs: number;
    desktopNotify: boolean;
  };
}

const DEFAULT_CONFIG: DomainSniperConfig = {
  concurrency: 5,
  rateLimitMs: 500,
  defaultTldPreset: "popular",
  registrar: null,
  notifications: {
    webhookUrl: null,
    emailTo: null,
    smtpHost: null,
    smtpPort: 587,
    smtpUser: null,
    smtpPass: null,
  },
  watch: {
    intervalMs: 3600000,
    desktopNotify: true,
  },
};

function ensureDir(): void {
  if (!existsSync(CONFIG_DIR)) {
    mkdirSync(CONFIG_DIR, { recursive: true });
  }
}

export function loadConfig(): DomainSniperConfig {
  ensureDir();
  if (!existsSync(CONFIG_FILE)) return { ...DEFAULT_CONFIG };
  try {
    const content = readFileSync(CONFIG_FILE, "utf-8");
    const parsed = JSON.parse(content);
    return { ...DEFAULT_CONFIG, ...parsed };
  } catch {
    return { ...DEFAULT_CONFIG };
  }
}

export function saveConfig(config: DomainSniperConfig): void {
  ensureDir();
  writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2), "utf-8");
}

export function getConfigPath(): string {
  return CONFIG_FILE;
}

export function resetConfig(): void {
  saveConfig(DEFAULT_CONFIG);
}
