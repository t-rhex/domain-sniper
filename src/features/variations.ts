/**
 * Typo & variation generator — check misspellings, hyphens, plurals, prefixes
 */

export interface VariationOptions {
  plurals?: boolean;
  hyphens?: boolean;
  prefixes?: boolean;
  suffixes?: boolean;
  typos?: boolean;
  abbreviations?: boolean;
}

const DEFAULT_OPTIONS: VariationOptions = {
  plurals: true,
  hyphens: true,
  prefixes: true,
  suffixes: true,
  typos: true,
  abbreviations: true,
};

// Common keyboard-adjacent typos
const TYPO_MAP: Record<string, string[]> = {
  a: ["s", "q", "z"], b: ["v", "n", "g"], c: ["x", "v", "d"],
  d: ["s", "f", "e"], e: ["w", "r", "d"], f: ["d", "g", "r"],
  g: ["f", "h", "t"], h: ["g", "j", "y"], i: ["u", "o", "k"],
  j: ["h", "k", "u"], k: ["j", "l", "i"], l: ["k", "o", "p"],
  m: ["n", "k"], n: ["b", "m", "h"], o: ["i", "p", "l"],
  p: ["o", "l"], q: ["w", "a"], r: ["e", "t", "f"],
  s: ["a", "d", "w"], t: ["r", "y", "g"], u: ["y", "i", "j"],
  v: ["c", "b", "f"], w: ["q", "e", "s"], x: ["z", "c", "s"],
  y: ["t", "u", "h"], z: ["a", "x", "s"],
};

const PREFIXES = ["get", "my", "the", "go", "try", "use", "hey"];
const SUFFIXES = ["app", "hq", "io", "lab", "hub", "ly", "ify", "ize"];

export function generateVariations(
  domain: string,
  options: VariationOptions = DEFAULT_OPTIONS
): string[] {
  const parts = domain.split(".");
  const tld = parts.slice(1).join(".") || "com";
  const name = parts[0]!.toLowerCase();
  const variations = new Set<string>();

  // Plurals
  if (options.plurals) {
    if (name.endsWith("s")) {
      variations.add(`${name.slice(0, -1)}.${tld}`);
    } else {
      variations.add(`${name}s.${tld}`);
    }
    if (name.endsWith("y")) {
      variations.add(`${name.slice(0, -1)}ies.${tld}`);
    }
  }

  // Hyphens — split camelCase or compound words
  if (options.hyphens) {
    // Add hyphen at common word boundaries
    for (let i = 2; i < name.length - 1; i++) {
      const left = name.slice(0, i);
      const right = name.slice(i);
      if (left.length >= 2 && right.length >= 2) {
        variations.add(`${left}-${right}.${tld}`);
      }
    }
    // Remove existing hyphens
    if (name.includes("-")) {
      variations.add(`${name.replace(/-/g, "")}.${tld}`);
    }
  }

  // Prefixes
  if (options.prefixes) {
    for (const prefix of PREFIXES) {
      if (!name.startsWith(prefix)) {
        variations.add(`${prefix}${name}.${tld}`);
      }
    }
  }

  // Suffixes
  if (options.suffixes) {
    for (const suffix of SUFFIXES) {
      if (!name.endsWith(suffix)) {
        variations.add(`${name}${suffix}.${tld}`);
      }
    }
  }

  // Typos — swap adjacent chars, drop chars, double chars
  if (options.typos) {
    // Character swaps
    for (let i = 0; i < name.length - 1; i++) {
      const swapped = name.slice(0, i) + name[i + 1] + name[i] + name.slice(i + 2);
      variations.add(`${swapped}.${tld}`);
    }
    // Character drops
    for (let i = 0; i < name.length; i++) {
      if (name.length > 2) {
        const dropped = name.slice(0, i) + name.slice(i + 1);
        variations.add(`${dropped}.${tld}`);
      }
    }
    // Keyboard-adjacent substitutions (limit to first 3)
    let typoCount = 0;
    for (let i = 0; i < name.length && typoCount < 3; i++) {
      const char = name[i]!;
      const adjacent = TYPO_MAP[char];
      if (adjacent) {
        const sub = name.slice(0, i) + adjacent[0] + name.slice(i + 1);
        variations.add(`${sub}.${tld}`);
        typoCount++;
      }
    }
  }

  // Abbreviations
  if (options.abbreviations) {
    // Remove vowels
    const noVowels = name.replace(/[aeiou]/g, "");
    if (noVowels.length >= 2 && noVowels !== name) {
      variations.add(`${noVowels}.${tld}`);
    }
  }

  // Remove the original domain
  variations.delete(domain);

  return Array.from(variations);
}
