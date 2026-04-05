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
