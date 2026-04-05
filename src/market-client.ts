import { readFileSync, writeFileSync, existsSync, mkdirSync, unlinkSync } from "fs";
import { join } from "path";
import { homedir } from "os";

const APP_DIR = join(homedir(), ".domain-sniper");
const AUTH_FILE = join(APP_DIR, "market-auth.json");

interface AuthState {
  serverUrl: string;
  cookies: string;
  userId: string;
  email: string;
  name: string;
}

function loadAuth(): AuthState | null {
  if (!existsSync(AUTH_FILE)) return null;
  try {
    return JSON.parse(readFileSync(AUTH_FILE, "utf-8"));
  } catch { return null; }
}

function saveAuth(state: AuthState): void {
  if (!existsSync(APP_DIR)) mkdirSync(APP_DIR, { recursive: true });
  writeFileSync(AUTH_FILE, JSON.stringify(state, null, 2), "utf-8");
}

function clearAuth(): void {
  if (existsSync(AUTH_FILE)) {
    unlinkSync(AUTH_FILE);
  }
}

export function getServerUrl(): string {
  return loadAuth()?.serverUrl || process.env.MARKET_URL || "http://localhost:3000";
}

export function isLoggedIn(): boolean {
  return loadAuth() !== null;
}

export function getAuthInfo(): { email: string; name: string; userId: string } | null {
  const auth = loadAuth();
  if (!auth) return null;
  return { email: auth.email, name: auth.name, userId: auth.userId };
}

async function request(method: string, path: string, body?: unknown): Promise<{ ok: boolean; status: number; data: any }> {
  const auth = loadAuth();
  const url = `${getServerUrl()}${path}`;
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (auth?.cookies) headers["Cookie"] = auth.cookies;

  try {
    const resp = await fetch(url, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });

    // Save cookies from response
    const setCookies = resp.headers.getSetCookie();
    if (setCookies.length > 0 && auth) {
      const cookieStr = setCookies.map((c) => c.split(";")[0]).join("; ");
      saveAuth({ ...auth, cookies: cookieStr });
    }

    const data = await resp.json().catch(() => null);
    return { ok: resp.ok, status: resp.status, data };
  } catch (err: unknown) {
    return { ok: false, status: 0, data: { error: err instanceof Error ? err.message : "Request failed" } };
  }
}

// ─── Auth ────────────────────────────────────────────────

export async function signUp(email: string, password: string, name: string, serverUrl?: string): Promise<{ success: boolean; error?: string }> {
  const base = serverUrl || getServerUrl();
  try {
    const resp = await fetch(`${base}/api/auth/sign-up/email`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password, name }),
    });
    const data = await resp.json() as any;
    if (resp.ok && data?.user) {
      const setCookies = resp.headers.getSetCookie();
      const cookieStr = setCookies.map((c: string) => c.split(";")[0]).join("; ");
      saveAuth({ serverUrl: base, cookies: cookieStr, userId: data.user.id, email: data.user.email, name: data.user.name });
      return { success: true };
    }
    return { success: false, error: data?.message || data?.error || "Sign up failed" };
  } catch (err: unknown) {
    return { success: false, error: err instanceof Error ? err.message : "Connection failed" };
  }
}

export async function signIn(email: string, password: string, serverUrl?: string): Promise<{ success: boolean; error?: string }> {
  const base = serverUrl || getServerUrl();
  try {
    const resp = await fetch(`${base}/api/auth/sign-in/email`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const data = await resp.json() as any;
    if (resp.ok && data?.user) {
      const setCookies = resp.headers.getSetCookie();
      const cookieStr = setCookies.map((c: string) => c.split(";")[0]).join("; ");
      saveAuth({ serverUrl: base, cookies: cookieStr, userId: data.user.id, email: data.user.email, name: data.user.name });
      return { success: true };
    }
    return { success: false, error: data?.message || data?.error || "Sign in failed" };
  } catch (err: unknown) {
    return { success: false, error: err instanceof Error ? err.message : "Connection failed" };
  }
}

export function signOut(): void {
  clearAuth();
}

// ─── Listings ────────────────────────────────────────────

export async function browseListings(query: {
  search?: string; category?: string; minPrice?: number; maxPrice?: number;
  verified?: boolean; sort?: string; limit?: number; offset?: number;
} = {}): Promise<{ ok: boolean; data: any }> {
  const params = new URLSearchParams();
  if (query.search) params.set("q", query.search);
  if (query.category) params.set("category", query.category);
  if (query.minPrice !== undefined) params.set("min", String(query.minPrice));
  if (query.maxPrice !== undefined) params.set("max", String(query.maxPrice));
  if (query.verified) params.set("verified", "true");
  if (query.sort) params.set("sort", query.sort);
  if (query.limit) params.set("limit", String(query.limit));
  if (query.offset) params.set("offset", String(query.offset));
  const qs = params.toString();
  return request("GET", `/api/listings${qs ? `?${qs}` : ""}`);
}

export async function viewListing(id: number): Promise<{ ok: boolean; data: any }> {
  return request("GET", `/api/listings/${id}`);
}

export async function createListingApi(domain: string, askingPrice: number, details: {
  title?: string; description?: string; minOffer?: number; buyNow?: boolean; category?: string;
} = {}): Promise<{ ok: boolean; data: any }> {
  return request("POST", "/api/listings", { domain, askingPrice, ...details });
}

export async function verifyListingApi(listingId: number): Promise<{ ok: boolean; data: any }> {
  return request("POST", `/api/listings/${listingId}/verify`);
}

export async function cancelListingApi(listingId: number): Promise<{ ok: boolean; data: any }> {
  return request("DELETE", `/api/listings/${listingId}`);
}

export async function getMyListings(): Promise<{ ok: boolean; data: any }> {
  return request("GET", "/api/my/listings");
}

// ─── Offers ──────────────────────────────────────────────

export async function makeOffer(listingId: number, amount: number, message: string = ""): Promise<{ ok: boolean; data: any }> {
  return request("POST", "/api/offers", { listingId, amount, message });
}

export async function respondToOffer(offerId: number, status: string, counterAmount?: number): Promise<{ ok: boolean; data: any }> {
  return request("PUT", `/api/offers/${offerId}`, { status, counterAmount });
}

export async function getMyOffers(role: "buyer" | "seller" = "buyer"): Promise<{ ok: boolean; data: any }> {
  return request("GET", `/api/my/offers?role=${role}`);
}

// ─── Other ───────────────────────────────────────────────

export async function getMarketStatsApi(): Promise<{ ok: boolean; data: any }> {
  return request("GET", "/api/stats");
}

export async function getUnreadApi(): Promise<{ ok: boolean; data: any }> {
  return request("GET", "/api/my/unread");
}
