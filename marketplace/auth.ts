import { betterAuth } from "better-auth";
import { Database } from "bun:sqlite";
import { join } from "path";
import { homedir } from "os";
import { mkdirSync, existsSync } from "fs";

const APP_DIR = process.env.DATA_DIR || join(homedir(), ".domain-sniper");
const AUTH_DB_FILE = join(APP_DIR, "auth.db");

if (!existsSync(APP_DIR)) mkdirSync(APP_DIR, { recursive: true });

const authSecret = process.env.BETTER_AUTH_SECRET;
if (!authSecret || authSecret.length < 32) {
  console.error("FATAL: BETTER_AUTH_SECRET must be set and at least 32 characters");
  process.exit(1);
}

export const auth = betterAuth({
  baseURL: process.env.BETTER_AUTH_URL || "http://localhost:3000",
  database: new Database(AUTH_DB_FILE),
  emailAndPassword: {
    enabled: true,
    minPasswordLength: 8,
  },
  session: {
    expiresIn: 60 * 60 * 24 * 7, // 7 days
    updateAge: 60 * 60 * 24, // 1 day
  },
  trustedOrigins: [
    "http://localhost:3000",
    "http://localhost:5173",
    process.env.BETTER_AUTH_URL || "",
  ].filter(Boolean),
});

export type Session = typeof auth.$Infer.Session;

// Run migrations programmatically on import
export async function migrateAuth(): Promise<void> {
  const { getMigrations } = await import("better-auth/db/migration");
  const { runMigrations } = await getMigrations(auth.options);
  await runMigrations();
}
