import { auth, migrateAuth } from "./auth.js";
import { checkRateLimit, cacheGet, cacheSet, getRedis, isRedisAvailable } from "./redis.js";
import { isPostgresEnabled } from "./pg.js";
import { isValidDomain } from "../src/core/validate.js";

// Run auth migrations before starting server
await migrateAuth();
import {
  createListing,
  getListing,
  updateListingStatus,
  searchListings,
  getUserListings,
  incrementViews,
  createOffer,
  getOffer,
  updateOfferStatus,
  getOffersForListing,
  getUserOffers,
  getOrCreateProfile,
  updateProfile,
  sendMessage,
  getMessages,
  getUnreadCount,
  markRead,
  addToWatchlist,
  removeFromWatchlist,
  getWatchlist,
  getMarketStats,
  type ListingStatus,
  type OfferStatus,
} from "./db.js";
import {
  getVerificationInstructions,
  verifyDomainOwnership,
} from "./verify.js";

const PORT = parseInt(process.env.PORT || process.env.MARKET_PORT || "3000", 10);

// ─── Auth middleware ─────────────────────────────────────

async function getSession(
  req: Request,
): Promise<{ user: { id: string; email: string; name: string } } | null> {
  try {
    const session = await auth.api.getSession({ headers: req.headers });
    return session;
  } catch {
    return null;
  }
}

// ─── Security ────────────────────────────────────────────

const ALLOWED_ORIGINS = new Set([
  "http://localhost:3000",
  "http://localhost:5173",
  process.env.BETTER_AUTH_URL || "",
].filter(Boolean));

// Allow configurable extra origins via env
if (process.env.ALLOWED_ORIGINS) {
  process.env.ALLOWED_ORIGINS.split(",").forEach((o) => ALLOWED_ORIGINS.add(o.trim()));
}

function getAllowedOrigin(req: Request): string {
  const origin = req.headers.get("origin") || "";
  // In production, only allow listed origins. In dev, allow all.
  if (process.env.NODE_ENV === "production" || process.env.RAILWAY_ENVIRONMENT) {
    return ALLOWED_ORIGINS.has(origin) ? origin : "";
  }
  return origin || "*";
}

const SECURITY_HEADERS: Record<string, string> = {
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "X-XSS-Protection": "1; mode=block",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
};

const MAX_BODY_SIZE = 1024 * 100; // 100KB max request body

function json(data: unknown, status: number = 200, req?: Request): Response {
  const origin = req ? getAllowedOrigin(req) : "*";
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Headers": "Content-Type, Authorization, Cookie",
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
      "Access-Control-Allow-Credentials": "true",
      ...SECURITY_HEADERS,
    },
  });
}

function unauthorized(req?: Request): Response {
  return json({ error: "Unauthorized" }, 401, req);
}

// Validate that a URL uses http or https protocol (blocks javascript: URIs, etc.)
function isValidUrl(input: string): boolean {
  try {
    const u = new URL(input);
    return u.protocol === "https:" || u.protocol === "http:";
  } catch { return false; }
}

// Sanitize user input to prevent XSS
function sanitize(input: string): string {
  return input
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;")
    .slice(0, 5000); // Max 5KB per field
}

// ─── Price / amount validation ──────────────────────────

function isValidPrice(value: unknown): value is number {
  return typeof value === "number" && isFinite(value) && value > 0;
}

// ─── Status transition allowlists ───────────────────────

const USER_SETTABLE_LISTING_STATUSES: string[] = ["cancelled"];
const VALID_OFFER_STATUSES_SELLER: string[] = ["accepted", "rejected", "countered"];
const VALID_OFFER_STATUSES_BUYER: string[] = ["withdrawn"];

// ─── Rate Limiting (Redis-backed, in-memory fallback) ───

function getClientIp(req: Request): string {
  // In production behind Railway's proxy, X-Forwarded-For is set by the load balancer.
  // For direct exposure, set TRUST_PROXY=false to use a connection-level IP.
  if (process.env.TRUST_PROXY !== "false") {
    const xff = req.headers.get("x-forwarded-for");
    if (xff) return xff.split(",")[0]!.trim();
    const realIp = req.headers.get("x-real-ip");
    if (realIp) return realIp;
  }
  return "unknown";
}

function rateLimited(resetIn: number): Response {
  return new Response(JSON.stringify({ error: "Too many requests. Try again later." }), {
    status: 429,
    headers: {
      "Content-Type": "application/json",
      "Retry-After": String(resetIn),
      ...SECURITY_HEADERS,
    },
  });
}

// ─── Server ──────────────────────────────────────────────

Bun.serve({
  port: PORT,
  async fetch(req) {
    try {
    const url = new URL(req.url);
    const method = req.method;

    // CORS preflight
    if (method === "OPTIONS") {
      const origin = getAllowedOrigin(req);
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": origin,
          "Access-Control-Allow-Headers": "Content-Type, Authorization, Cookie",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Credentials": "true",
          "Access-Control-Max-Age": "86400",
          ...SECURITY_HEADERS,
        },
      });
    }

    // ─── Request size limit ────────────────────────────
    const contentLength = req.headers.get("content-length");
    if (contentLength && parseInt(contentLength, 10) > MAX_BODY_SIZE) {
      return json({ error: "Request body too large (max 100KB)" }, 413, req);
    }

    // ─── Rate limiting ─────────────────────────────────
    const clientIp = getClientIp(req);

    // Determine bucket
    const isAuthRoute = url.pathname.startsWith("/api/auth");
    const isWriteRoute = method === "POST" || method === "PUT" || method === "DELETE";
    const bucket = isAuthRoute ? "auth" : isWriteRoute ? "write" : "read";

    // Check global limit first
    const globalCheck = await checkRateLimit(clientIp, "global");
    if (!globalCheck.allowed) return rateLimited(globalCheck.resetIn);

    // Check bucket-specific limit
    const bucketCheck = await checkRateLimit(clientIp, bucket);
    if (!bucketCheck.allowed) return rateLimited(bucketCheck.resetIn);

    // Better Auth routes
    if (isAuthRoute) {
      return auth.handler(req);
    }

    // ─── Public routes ─────────────────────────────────

    // GET /api/listings -- Browse listings (with caching)
    if (method === "GET" && url.pathname === "/api/listings") {
      const cacheKey = `listings:${url.search}`;
      const cached = await cacheGet(cacheKey);
      if (cached) {
        return new Response(cached, {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "X-Cache": "HIT",
            "Access-Control-Allow-Origin": getAllowedOrigin(req),
            "Access-Control-Allow-Credentials": "true",
            ...SECURITY_HEADERS,
          },
        });
      }

      const search = url.searchParams.get("q") || undefined;
      const category = url.searchParams.get("category") || undefined;
      const minPrice = url.searchParams.get("min")
        ? parseFloat(url.searchParams.get("min")!)
        : undefined;
      const maxPrice = url.searchParams.get("max")
        ? parseFloat(url.searchParams.get("max")!)
        : undefined;
      const verified = url.searchParams.get("verified") === "true";
      const sortBy = url.searchParams.get("sort") || "newest";
      const limit = parseInt(url.searchParams.get("limit") || "20", 10);
      const offset = parseInt(url.searchParams.get("offset") || "0", 10);

      const result = searchListings({
        search,
        category,
        minPrice,
        maxPrice,
        verified,
        sortBy,
        limit,
        offset,
      });
      const body = JSON.stringify(result);
      await cacheSet(cacheKey, body, 30);
      return new Response(body, {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "X-Cache": "MISS",
          "Access-Control-Allow-Origin": getAllowedOrigin(req),
          "Access-Control-Allow-Credentials": "true",
          ...SECURITY_HEADERS,
        },
      });
    }

    // GET /api/listings/:id -- View listing
    if (method === "GET" && url.pathname.match(/^\/api\/listings\/\d+$/)) {
      const id = parseInt(url.pathname.split("/").pop()!, 10);
      const listing = getListing(id);
      if (!listing) return json({ error: "Not found" }, 404, req);
      incrementViews(id);
      const offers = getOffersForListing(id);
      return json({ listing, offerCount: offers.length }, 200, req);
    }

    // GET /api/stats -- Market stats (with caching)
    if (method === "GET" && url.pathname === "/api/stats") {
      const cached = await cacheGet("market:stats");
      if (cached) {
        return new Response(cached, {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "X-Cache": "HIT",
            "Access-Control-Allow-Origin": getAllowedOrigin(req),
            "Access-Control-Allow-Credentials": "true",
            ...SECURITY_HEADERS,
          },
        });
      }
      const stats = getMarketStats();
      const body = JSON.stringify(stats);
      await cacheSet("market:stats", body, 60);
      return new Response(body, {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "X-Cache": "MISS",
          "Access-Control-Allow-Origin": getAllowedOrigin(req),
          "Access-Control-Allow-Credentials": "true",
          ...SECURITY_HEADERS,
        },
      });
    }

    // GET /api/profile/:userId -- Public profile
    if (method === "GET" && url.pathname.match(/^\/api\/profile\/.+$/)) {
      const userId = url.pathname.split("/").pop()!;
      const profile = getOrCreateProfile(userId);
      return json(profile, 200, req);
    }

    // ─── Authenticated routes ──────────────────────────

    const session = await getSession(req);

    // POST /api/listings -- Create listing
    if (method === "POST" && url.pathname === "/api/listings") {
      if (!session) return unauthorized(req);
      const body = (await req.json()) as {
        domain: string;
        askingPrice: number;
        title?: string;
        description?: string;
        minOffer?: number;
        buyNow?: boolean;
        category?: string;
      };
      if (!body.domain || !body.askingPrice)
        return json({ error: "domain and askingPrice required" }, 400, req);
      if (!isValidDomain(body.domain)) {
        return json({ error: "Invalid domain format" }, 400, req);
      }
      if (!isValidPrice(body.askingPrice)) {
        return json({ error: "askingPrice must be a positive number" }, 400, req);
      }
      if (body.minOffer !== undefined && (typeof body.minOffer !== "number" || !isFinite(body.minOffer) || body.minOffer < 0)) {
        return json({ error: "minOffer must be a non-negative number" }, 400, req);
      }

      const safeDomain = body.domain;
      const safeTitle = body.title ? sanitize(body.title) : undefined;
      const safeDescription = body.description ? sanitize(body.description) : undefined;
      const safeCategory = body.category ? sanitize(body.category) : undefined;

      const listingId = createListing(
        session.user.id,
        safeDomain,
        body.askingPrice,
        {
          title: safeTitle,
          description: safeDescription,
          minOffer: body.minOffer,
          buyNow: body.buyNow,
          category: safeCategory,
        },
      );
      const listing = getListing(listingId)!;
      const verification = getVerificationInstructions(
        safeDomain,
        listing.verification_token!,
      );
      return json({ listing, verification }, 201, req);
    }

    // POST /api/listings/:id/verify -- Verify domain ownership
    if (
      method === "POST" &&
      url.pathname.match(/^\/api\/listings\/\d+\/verify$/)
    ) {
      if (!session) return unauthorized(req);
      const id = parseInt(url.pathname.split("/")[3]!, 10);
      const listing = getListing(id);
      if (!listing) return json({ error: "Not found" }, 404, req);
      if (listing.user_id !== session.user.id)
        return json({ error: "Not your listing" }, 403, req);

      const result = await verifyDomainOwnership(id);
      return json(result, 200, req);
    }

    // PUT /api/listings/:id -- Update listing
    if (method === "PUT" && url.pathname.match(/^\/api\/listings\/\d+$/)) {
      if (!session) return unauthorized(req);
      const id = parseInt(url.pathname.split("/").pop()!, 10);
      const listing = getListing(id);
      if (!listing) return json({ error: "Not found" }, 404, req);
      if (listing.user_id !== session.user.id)
        return json({ error: "Not your listing" }, 403, req);

      const body = (await req.json()) as { status?: string };
      if (body.status) {
        if (!USER_SETTABLE_LISTING_STATUSES.includes(body.status)) {
          return json({ error: `Invalid status. Allowed: ${USER_SETTABLE_LISTING_STATUSES.join(", ")}` }, 400, req);
        }
        updateListingStatus(id, body.status as ListingStatus);
      }
      return json(getListing(id), 200, req);
    }

    // DELETE /api/listings/:id -- Cancel listing
    if (
      method === "DELETE" &&
      url.pathname.match(/^\/api\/listings\/\d+$/)
    ) {
      if (!session) return unauthorized(req);
      const id = parseInt(url.pathname.split("/").pop()!, 10);
      const listing = getListing(id);
      if (!listing) return json({ error: "Not found" }, 404, req);
      if (listing.user_id !== session.user.id)
        return json({ error: "Not your listing" }, 403, req);
      updateListingStatus(id, "cancelled");
      return json({ success: true }, 200, req);
    }

    // GET /api/my/listings -- My listings
    if (method === "GET" && url.pathname === "/api/my/listings") {
      if (!session) return unauthorized(req);
      return json(getUserListings(session.user.id), 200, req);
    }

    // GET /api/my/offers -- My offers (as buyer or seller)
    if (method === "GET" && url.pathname === "/api/my/offers") {
      if (!session) return unauthorized(req);
      const role = url.searchParams.get("role") || "buyer";
      if (role !== "buyer" && role !== "seller") {
        return json({ error: "role must be 'buyer' or 'seller'" }, 400, req);
      }
      return json(getUserOffers(session.user.id, role), 200, req);
    }

    // POST /api/offers -- Make an offer
    if (method === "POST" && url.pathname === "/api/offers") {
      if (!session) return unauthorized(req);
      const body = (await req.json()) as {
        listingId: number;
        amount: number;
        message?: string;
      };
      if (!body.listingId || !body.amount)
        return json({ error: "listingId and amount required" }, 400, req);
      if (!isValidPrice(body.amount)) {
        return json({ error: "amount must be a positive number" }, 400, req);
      }

      const listing = getListing(body.listingId);
      if (!listing) return json({ error: "Listing not found" }, 404, req);
      if (listing.status !== "active")
        return json({ error: "Listing not active" }, 400, req);
      if (listing.user_id === session.user.id)
        return json({ error: "Cannot offer on your own listing" }, 400, req);
      if (listing.min_offer && body.amount < listing.min_offer)
        return json(
          { error: `Minimum offer is $${listing.min_offer}` },
          400,
          req,
        );

      const safeMessage = body.message ? sanitize(body.message) : "";

      const offerId = createOffer(
        body.listingId,
        session.user.id,
        listing.user_id,
        body.amount,
        safeMessage,
      );
      return json(getOffer(offerId), 201, req);
    }

    // PUT /api/offers/:id -- Accept/reject/counter offer
    if (method === "PUT" && url.pathname.match(/^\/api\/offers\/\d+$/)) {
      if (!session) return unauthorized(req);
      const id = parseInt(url.pathname.split("/").pop()!, 10);
      const offer = getOffer(id);
      if (!offer) return json({ error: "Not found" }, 404, req);

      const body = (await req.json()) as {
        status: string;
        counterAmount?: number;
      };

      // Determine allowed statuses based on role
      const allowedStatuses = offer.seller_id === session.user.id
        ? VALID_OFFER_STATUSES_SELLER
        : offer.buyer_id === session.user.id
        ? VALID_OFFER_STATUSES_BUYER
        : [];

      if (!allowedStatuses.includes(body.status)) {
        return json({ error: `Invalid status. Allowed: ${allowedStatuses.join(", ")}` }, 400, req);
      }

      // Validate counterAmount if provided
      if (body.counterAmount !== undefined && !isValidPrice(body.counterAmount)) {
        return json({ error: "counterAmount must be a positive number" }, 400, req);
      }

      updateOfferStatus(
        id,
        body.status as OfferStatus,
        body.counterAmount,
      );

      // If accepted, mark listing as sold
      if (body.status === "accepted") {
        updateListingStatus(offer.listing_id, "sold");
      }

      return json(getOffer(id), 200, req);
    }

    // GET /api/offers/:id/messages -- Get messages for an offer
    if (
      method === "GET" &&
      url.pathname.match(/^\/api\/offers\/\d+\/messages$/)
    ) {
      if (!session) return unauthorized(req);
      const offerId = parseInt(url.pathname.split("/")[3]!, 10);
      const offer = getOffer(offerId);
      if (!offer) return json({ error: "Not found" }, 404, req);
      if (
        offer.buyer_id !== session.user.id &&
        offer.seller_id !== session.user.id
      )
        return json({ error: "Forbidden" }, 403, req);

      markRead(session.user.id, offerId);
      return json(getMessages(offerId), 200, req);
    }

    // POST /api/offers/:id/messages -- Send message
    if (
      method === "POST" &&
      url.pathname.match(/^\/api\/offers\/\d+\/messages$/)
    ) {
      if (!session) return unauthorized(req);
      const offerId = parseInt(url.pathname.split("/")[3]!, 10);
      const offer = getOffer(offerId);
      if (!offer) return json({ error: "Not found" }, 404, req);
      if (
        offer.buyer_id !== session.user.id &&
        offer.seller_id !== session.user.id
      )
        return json({ error: "Forbidden" }, 403, req);

      const body = (await req.json()) as { content: string };
      const safeContent = sanitize(body.content);
      const recipientId =
        session.user.id === offer.buyer_id
          ? offer.seller_id
          : offer.buyer_id;
      const msgId = sendMessage(
        offerId,
        session.user.id,
        recipientId,
        safeContent,
      );
      return json({ id: msgId }, 201, req);
    }

    // GET /api/my/unread -- Unread message count
    if (method === "GET" && url.pathname === "/api/my/unread") {
      if (!session) return unauthorized(req);
      return json({ count: getUnreadCount(session.user.id) }, 200, req);
    }

    // PUT /api/my/profile -- Update profile
    if (method === "PUT" && url.pathname === "/api/my/profile") {
      if (!session) return unauthorized(req);
      const body = (await req.json()) as {
        displayName?: string;
        bio?: string;
        website?: string;
      };
      const safeDisplayName = body.displayName ? sanitize(body.displayName) : undefined;
      const safeBio = body.bio ? sanitize(body.bio) : undefined;
      const safeWebsite = body.website !== undefined
        ? (body.website ? sanitize(body.website) : "")
        : undefined;
      if (safeWebsite && !isValidUrl(safeWebsite)) {
        return json({ error: "website must be a valid http/https URL" }, 400, req);
      }
      updateProfile(session.user.id, {
        displayName: safeDisplayName,
        bio: safeBio,
        website: safeWebsite,
      });
      return json(getOrCreateProfile(session.user.id), 200, req);
    }

    // GET /api/my/watchlist -- Get watchlist
    if (method === "GET" && url.pathname === "/api/my/watchlist") {
      if (!session) return unauthorized(req);
      return json(getWatchlist(session.user.id), 200, req);
    }

    // POST /api/my/watchlist -- Add to watchlist
    if (method === "POST" && url.pathname === "/api/my/watchlist") {
      if (!session) return unauthorized(req);
      const body = (await req.json()) as { listingId: number };
      addToWatchlist(session.user.id, body.listingId);
      return json({ success: true }, 201, req);
    }

    // DELETE /api/my/watchlist/:id -- Remove from watchlist
    if (
      method === "DELETE" &&
      url.pathname.match(/^\/api\/my\/watchlist\/\d+$/)
    ) {
      if (!session) return unauthorized(req);
      const listingId = parseInt(url.pathname.split("/").pop()!, 10);
      removeFromWatchlist(session.user.id, listingId);
      return json({ success: true }, 200, req);
    }

    return json({ error: "Not found" }, 404, req);
    } catch (err: unknown) {
      console.error("Unhandled error:", err);
      const message = process.env.RAILWAY_ENVIRONMENT || process.env.NODE_ENV === "production"
        ? "Internal server error"
        : err instanceof Error ? err.message : "Internal server error";
      return json({ error: message }, 500, req);
    }
  },
});

// Try connecting to Redis on startup
await getRedis();

const startupMessage = `
Domain Sniper Marketplace running on http://localhost:${PORT}
  Auth:  POST /api/auth/sign-up/email, POST /api/auth/sign-in/email
  API:   GET /api/listings, POST /api/listings, POST /api/offers
  Stats: GET /api/stats
  Database: ${isPostgresEnabled() ? "PostgreSQL (via Bun.sql)" : "SQLite"}
  Redis: ${isRedisAvailable() ? "connected" : "in-memory fallback"}
`;
process.stdout.write(startupMessage);
