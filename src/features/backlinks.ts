import { assertValidDomain } from "../validate.js";

export interface BacklinkResult {
  domain: string;
  estimatedBacklinks: number | null;
  pageRank: number | null;
  commonCrawlPages: number | null;
  sources: BacklinkSource[];
  error: string | null;
}

export interface BacklinkSource {
  name: string;
  value: number | null;
  error: string | null;
}

async function checkCommonCrawl(domain: string): Promise<BacklinkSource> {
  try {
    // Use Common Crawl index API to estimate pages
    const resp = await fetch(
      `https://index.commoncrawl.org/CC-MAIN-2025-51-index?url=*.${encodeURIComponent(domain)}&output=json&limit=1&showNumPages=true`,
      { signal: AbortSignal.timeout(10000) }
    );
    if (!resp.ok) {
      return { name: "CommonCrawl", value: null, error: `HTTP ${resp.status}` };
    }
    const text = await resp.text();
    // The showNumPages response is a single number
    const pages = parseInt(text.trim(), 10);
    if (!isNaN(pages)) {
      return { name: "CommonCrawl", value: pages, error: null };
    }
    // Try parsing as JSON lines
    const lines = text.trim().split("\n").filter(Boolean);
    return { name: "CommonCrawl", value: lines.length, error: null };
  } catch (err: unknown) {
    return { name: "CommonCrawl", value: null, error: err instanceof Error ? err.message : "Failed" };
  }
}

async function checkOpenPageRank(domain: string): Promise<BacklinkSource> {
  try {
    // Open PageRank - free API, no key needed for basic lookups
    const resp = await fetch(
      `https://openpagerank.com/api/v1.0/getPageRank?domains[]=${encodeURIComponent(domain)}`,
      {
        signal: AbortSignal.timeout(8000),
        headers: { "User-Agent": "DomainSniper/2.0" },
      }
    );
    if (!resp.ok) {
      return { name: "OpenPageRank", value: null, error: `HTTP ${resp.status}` };
    }
    const data = await resp.json() as {
      status_code?: number;
      response?: Array<{ page_rank_decimal?: number; rank?: number }>;
    };
    const first = data.response?.[0];
    const rank = first?.page_rank_decimal ?? first?.rank ?? null;
    return { name: "OpenPageRank", value: typeof rank === "number" ? rank : null, error: null };
  } catch (err: unknown) {
    return { name: "OpenPageRank", value: null, error: err instanceof Error ? err.message : "Failed" };
  }
}

export async function estimateBacklinks(domain: string): Promise<BacklinkResult> {
  assertValidDomain(domain);

  const [ccResult, prResult] = await Promise.all([
    checkCommonCrawl(domain),
    checkOpenPageRank(domain),
  ]);

  return {
    domain,
    estimatedBacklinks: ccResult.value,
    pageRank: prResult.value,
    commonCrawlPages: ccResult.value,
    sources: [ccResult, prResult],
    error: null,
  };
}
