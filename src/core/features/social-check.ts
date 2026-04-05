import { assertValidDomain } from "../validate.js";

export interface SocialCheckResult {
  platform: string;
  url: string;
  available: boolean;
  error: string | null;
}

const PLATFORMS: { name: string; urlTemplate: string }[] = [
  { name: "Twitter/X", urlTemplate: "https://x.com/{name}" },
  { name: "GitHub", urlTemplate: "https://github.com/{name}" },
  { name: "Instagram", urlTemplate: "https://www.instagram.com/{name}/" },
  { name: "Reddit", urlTemplate: "https://www.reddit.com/user/{name}" },
  { name: "TikTok", urlTemplate: "https://www.tiktok.com/@{name}" },
  { name: "YouTube", urlTemplate: "https://www.youtube.com/@{name}" },
  { name: "LinkedIn", urlTemplate: "https://www.linkedin.com/company/{name}" },
  { name: "Twitch", urlTemplate: "https://www.twitch.tv/{name}" },
  { name: "Pinterest", urlTemplate: "https://www.pinterest.com/{name}/" },
  { name: "npm", urlTemplate: "https://www.npmjs.com/package/{name}" },
  { name: "PyPI", urlTemplate: "https://pypi.org/project/{name}/" },
  { name: "Mastodon", urlTemplate: "https://mastodon.social/@{name}" },
];

async function checkPlatform(
  platform: { name: string; urlTemplate: string },
  username: string
): Promise<SocialCheckResult> {
  const url = platform.urlTemplate.replace("{name}", encodeURIComponent(username));
  try {
    const resp = await fetch(url, {
      method: "HEAD",
      redirect: "manual",
      signal: AbortSignal.timeout(6000),
      headers: { "User-Agent": "DomainSniper/2.0" },
    });
    // 404 = available, 200 = taken, 3xx = usually taken (redirect to profile)
    const available = resp.status === 404;
    return { platform: platform.name, url, available, error: null };
  } catch (err: unknown) {
    // If HEAD fails, try GET (some platforms block HEAD)
    try {
      const resp = await fetch(url, {
        redirect: "manual",
        signal: AbortSignal.timeout(6000),
        headers: { "User-Agent": "DomainSniper/2.0" },
      });
      const available = resp.status === 404;
      return { platform: platform.name, url, available, error: null };
    } catch {
      return { platform: platform.name, url, available: false, error: "Unreachable" };
    }
  }
}

export async function checkSocialMedia(
  domain: string,
  platforms: typeof PLATFORMS = PLATFORMS
): Promise<SocialCheckResult[]> {
  // Extract name part from domain
  const name = domain.split(".")[0] || "";
  if (!name || name.length < 2) return [];

  // Check in batches of 4 to avoid rate limiting
  const results: SocialCheckResult[] = [];
  const BATCH = 4;
  for (let i = 0; i < platforms.length; i += BATCH) {
    const batch = platforms.slice(i, i + BATCH);
    const batchResults = await Promise.all(
      batch.map((p) => checkPlatform(p, name))
    );
    results.push(...batchResults);
  }
  return results;
}

export function getAvailablePlatforms(results: SocialCheckResult[]): SocialCheckResult[] {
  return results.filter((r) => r.available && !r.error);
}

export { PLATFORMS };
