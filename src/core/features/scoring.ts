/**
 * Domain scoring — rate how "good" a domain is
 */

export interface DomainScore {
  total: number;       // 0-100
  length: number;      // 0-20
  tld: number;         // 0-20
  readability: number; // 0-20
  brandable: number;   // 0-20
  seo: number;         // 0-20
  breakdown: string[];
}

// Common English words for dictionary check
const COMMON_WORDS = new Set([
  "app", "web", "dev", "code", "tech", "data", "cloud", "net", "hub", "lab",
  "run", "go", "get", "my", "the", "ai", "ml", "api", "io", "bit",
  "box", "pay", "flow", "base", "stack", "link", "fast", "snap", "bolt", "spark",
  "fire", "sky", "star", "wave", "cool", "zen", "pro", "max", "top",
  "open", "free", "beta", "alpha", "mega", "super", "hyper", "ultra", "meta",
  "sync", "ship", "dash", "grid", "node", "edge", "core", "loop", "ping",
]);

const TLD_SCORES: Record<string, number> = {
  com: 20, io: 18, dev: 17, ai: 17, app: 16, co: 15,
  org: 14, net: 13, me: 12, sh: 12, gg: 11, so: 11,
  xyz: 8, tech: 10, cloud: 10, run: 10, live: 8,
  site: 6, online: 5, store: 7, cc: 7, to: 9,
};

export function scoreDomain(domain: string): DomainScore {
  const parts = domain.split(".");
  const name = (parts[0] || "").toLowerCase();
  const tld = parts.slice(1).join(".");
  const breakdown: string[] = [];

  // ── Length score (shorter = better) ──
  let length = 0;
  if (name.length <= 3) { length = 20; breakdown.push("Ultra-short name"); }
  else if (name.length <= 5) { length = 18; breakdown.push("Very short name"); }
  else if (name.length <= 7) { length = 15; breakdown.push("Short name"); }
  else if (name.length <= 10) { length = 12; breakdown.push("Medium length"); }
  else if (name.length <= 15) { length = 8; breakdown.push("Long name"); }
  else { length = 4; breakdown.push("Very long name"); }

  // ── TLD score ──
  const tldScore = TLD_SCORES[tld] || 5;
  breakdown.push(`.${tld} TLD (${tldScore >= 15 ? "premium" : tldScore >= 10 ? "good" : "average"})`);

  // ── Readability ──
  let readability = 10;
  // Pronounceable check (has vowels)
  const vowelCount = (name.match(/[aeiou]/gi) || []).length;
  const vowelRatio = vowelCount / name.length;
  if (vowelRatio >= 0.25 && vowelRatio <= 0.6) {
    readability += 5;
    breakdown.push("Good vowel distribution");
  }
  // No numbers or hyphens
  if (!/[0-9-]/.test(name)) {
    readability += 3;
    breakdown.push("Clean — no numbers or hyphens");
  } else {
    readability -= 3;
    breakdown.push("Contains numbers/hyphens");
  }
  // No double consonants clusters
  if (!/[bcdfghjklmnpqrstvwxyz]{4,}/i.test(name)) {
    readability += 2;
  } else {
    readability -= 2;
    breakdown.push("Hard consonant cluster");
  }
  readability = Math.max(0, Math.min(20, readability));

  // ── Brandability ──
  let brandable = 10;
  // Contains common word
  const containsWord = Array.from(COMMON_WORDS).some((w) => name.includes(w));
  if (containsWord) {
    brandable += 4;
    breakdown.push("Contains common word");
  }
  // Single word (no hyphens)
  if (!name.includes("-")) {
    brandable += 3;
  }
  // Memorable length
  if (name.length >= 4 && name.length <= 8) {
    brandable += 3;
    breakdown.push("Memorable length (4-8 chars)");
  }
  brandable = Math.max(0, Math.min(20, brandable));

  // ── SEO potential ──
  let seo = 10;
  // .com bonus
  if (tld === "com") { seo += 5; breakdown.push(".com SEO advantage"); }
  else if (["io", "dev", "ai", "app"].includes(tld)) { seo += 3; }
  // Short domain bonus
  if (name.length <= 8) seo += 3;
  // No weird chars
  if (/^[a-z]+$/.test(name)) seo += 2;
  seo = Math.max(0, Math.min(20, seo));

  const total = Math.min(100, length + tldScore + readability + brandable + seo);

  return { total, length, tld: tldScore, readability, brandable, seo, breakdown };
}

export function scoreGrade(score: number): { grade: string; color: string } {
  if (score >= 85) return { grade: "A+", color: "#00e88f" };
  if (score >= 75) return { grade: "A", color: "#00e88f" };
  if (score >= 65) return { grade: "B+", color: "#5c9cf5" };
  if (score >= 55) return { grade: "B", color: "#5c9cf5" };
  if (score >= 45) return { grade: "C+", color: "#f5c542" };
  if (score >= 35) return { grade: "C", color: "#f5c542" };
  if (score >= 25) return { grade: "D", color: "#f5955c" };
  return { grade: "F", color: "#f55c5c" };
}
