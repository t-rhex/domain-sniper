import { scoreDomain } from "./scoring.js";

const PREFIXES = [
  "get", "try", "use", "go", "my", "hey", "the",
  "super", "hyper", "ultra", "mega", "meta", "neo",
  "re", "un", "co", "ai",
];

const SUFFIXES = [
  "app", "hq", "hub", "lab", "labs", "io", "ly",
  "ify", "ize", "ful", "box", "kit", "now",
  "run", "dev", "ops", "ai", "x", "up",
];

const TECH_WORDS = [
  "sync", "flow", "stack", "link", "dash", "grid",
  "node", "edge", "core", "loop", "ping", "bolt",
  "wave", "spark", "cloud", "beam", "data", "byte",
  "pixel", "craft", "forge", "vault", "pulse", "shift",
];

export interface Suggestion {
  name: string;
  domain: string;
  strategy: string;
}

export function generateSuggestions(
  keyword: string,
  tld: string = "com",
  maxResults: number = 30
): Suggestion[] {
  const word = keyword.toLowerCase().replace(/[^a-z0-9]/g, "");
  if (!word) return [];

  const suggestions: Suggestion[] = [];
  const seen = new Set<string>();

  function add(name: string, strategy: string) {
    const domain = `${name}.${tld}`;
    if (!seen.has(domain) && name.length >= 3 && name.length <= 20) {
      seen.add(domain);
      suggestions.push({ name, domain, strategy });
    }
  }

  // Prefix combinations
  for (const prefix of PREFIXES) {
    if (suggestions.length >= maxResults) break;
    add(`${prefix}${word}`, `prefix: ${prefix}+`);
  }

  // Suffix combinations
  for (const suffix of SUFFIXES) {
    if (suggestions.length >= maxResults) break;
    add(`${word}${suffix}`, `suffix: +${suffix}`);
  }

  // Word mashups
  for (const tech of TECH_WORDS) {
    if (suggestions.length >= maxResults) break;
    add(`${word}${tech}`, `mashup: +${tech}`);
    add(`${tech}${word}`, `mashup: ${tech}+`);
  }

  // Truncations
  if (word.length > 4) {
    add(word.slice(0, 4), "truncation: first 4");
    add(word.slice(0, 5), "truncation: first 5");
  }

  // Vowel removal
  const noVowels = word.replace(/[aeiou]/g, "");
  if (noVowels.length >= 3 && noVowels !== word) {
    add(noVowels, "vowel removal");
  }

  // Double last letter
  add(`${word}${word.slice(-1)}`, "doubled ending");

  // Rhyme patterns
  const rhymeSuffixes = ["oo", "ee", "ify", "ly", "er", "le"];
  for (const r of rhymeSuffixes) {
    if (suggestions.length >= maxResults) break;
    add(`${word}${r}`, `rhyme: +${r}`);
  }

  return suggestions.slice(0, maxResults);
}

export interface ScoredSuggestion extends Suggestion {
  score: number;
  grade: string;
}

/**
 * Generate suggestions across multiple TLDs, scored and sorted by quality
 */
export function generateScoredSuggestions(
  keyword: string,
  tlds: string[] = ["com", "io", "dev", "app", "co"],
  maxResults: number = 30
): ScoredSuggestion[] {
  const word = keyword.toLowerCase().replace(/[^a-z0-9]/g, "");
  if (!word) return [];

  const all: ScoredSuggestion[] = [];
  const seen = new Set<string>();

  for (const tld of tlds) {
    const suggestions = generateSuggestions(word, tld, 50);
    for (const s of suggestions) {
      if (seen.has(s.domain)) continue;
      seen.add(s.domain);
      const score = scoreDomain(s.domain);
      all.push({
        ...s,
        score: score.total,
        grade: score.total >= 85 ? "A+" : score.total >= 75 ? "A" : score.total >= 65 ? "B+" : score.total >= 55 ? "B" : score.total >= 45 ? "C+" : score.total >= 35 ? "C" : "D",
      });
    }
  }

  // Sort by score descending
  all.sort((a, b) => b.score - a.score);

  return all.slice(0, maxResults);
}
