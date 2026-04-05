import { join } from "path";
import { homedir } from "os";

export const APP_DIR = join(homedir(), ".domain-sniper");
export const CONFIG_FILE = join(APP_DIR, "config.json");
export const PORTFOLIO_FILE = join(APP_DIR, "portfolio.json");
export const SESSION_DIR = join(APP_DIR, "sessions");
export const WHOIS_HISTORY_DIR = join(APP_DIR, "whois-history");
export const DB_FILE = join(APP_DIR, "domain-sniper.db");
