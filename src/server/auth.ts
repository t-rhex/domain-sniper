import { betterAuth } from "better-auth";
import { Database } from "bun:sqlite";
import { join } from "path";
import { homedir } from "os";
import { mkdirSync, existsSync } from "fs";

const APP_DIR = join(homedir(), ".domain-sniper");
const AUTH_DB_FILE = join(APP_DIR, "auth.db");

if (!existsSync(APP_DIR)) mkdirSync(APP_DIR, { recursive: true });

export const auth = betterAuth({
  database: new Database(AUTH_DB_FILE),
  emailAndPassword: {
    enabled: true,
    minPasswordLength: 8,
  },
  session: {
    expiresIn: 60 * 60 * 24 * 7, // 7 days
    updateAge: 60 * 60 * 24, // 1 day
  },
  trustedOrigins: ["http://localhost:3000", "http://localhost:5173"],
});

export type Session = typeof auth.$Infer.Session;
