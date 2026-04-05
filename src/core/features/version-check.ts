/**
 * Check if a newer version of domain-sniper is available.
 * Uses Bun.semver for version comparison.
 */

import { join } from "path";
import { readFileSync } from "fs";

export function getCurrentVersion(): string {
  try {
    const raw = readFileSync(join(import.meta.dir, "../../../package.json"), "utf-8");
    const pkg = JSON.parse(raw) as { version?: string };
    return pkg.version || "0.0.0";
  } catch {
    return "2.0.0";
  }
}

export async function checkForUpdates(): Promise<{
  current: string;
  latest: string | null;
  updateAvailable: boolean;
  error: string | null;
}> {
  const current = getCurrentVersion();

  try {
    const resp = await fetch("https://registry.npmjs.org/domain-sniper/latest", {
      signal: AbortSignal.timeout(5000),
    });

    if (!resp.ok) {
      return { current, latest: null, updateAvailable: false, error: null };
    }

    const data = (await resp.json()) as { version?: string };
    const latest = data.version || null;

    if (!latest) {
      return { current, latest: null, updateAvailable: false, error: null };
    }

    const updateAvailable = Bun.semver.order(current, latest) < 0;

    return { current, latest, updateAvailable, error: null };
  } catch (err: unknown) {
    return {
      current,
      latest: null,
      updateAvailable: false,
      error: err instanceof Error ? err.message : "Check failed",
    };
  }
}

export function formatUpdateMessage(current: string, latest: string): string {
  return `Update available: ${current} -> ${latest}\nRun: bun update -g domain-sniper`;
}
