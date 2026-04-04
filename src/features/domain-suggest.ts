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
