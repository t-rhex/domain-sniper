import { auth, migrateAuth } from "./auth.js";
import { checkRateLimit, cacheGet, cacheSet, getRedis, isRedisAvailable } from "./redis.js";

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

function json(data: unknown, status: number = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    },
  });
}

function unauthorized(): Response {
  return json({ error: "Unauthorized" }, 401);
}

// ─── Rate Limiting (Redis-backed, in-memory fallback) ───

function getClientIp(req: Request): string {
  return req.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
    || req.headers.get("x-real-ip")
    || "unknown";
}

function rateLimited(resetIn: number): Response {
  return new Response(JSON.stringify({ error: "Too many requests. Try again later." }), {
    status: 429,
    headers: {
      "Content-Type": "application/json",
      "Retry-After": String(resetIn),
      "Access-Control-Allow-Origin": "*",
    },
  });
}

// ─── Server ──────────────────────────────────────────────

Bun.serve({
  port: PORT,
  async fetch(req) {
    const url = new URL(req.url);
    const method = req.method;

    // CORS preflight
    if (method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        },
      });
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
          headers: { "Content-Type": "application/json", "X-Cache": "HIT", "Access-Control-Allow-Origin": "*" },
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
        headers: { "Content-Type": "application/json", "X-Cache": "MISS", "Access-Control-Allow-Origin": "*" },
      });
    }

    // GET /api/listings/:id -- View listing
    if (method === "GET" && url.pathname.match(/^\/api\/listings\/\d+$/)) {
      const id = parseInt(url.pathname.split("/").pop()!, 10);
      const listing = getListing(id);
      if (!listing) return json({ error: "Not found" }, 404);
      incrementViews(id);
      const offers = getOffersForListing(id);
      return json({ listing, offerCount: offers.length });
    }

    // GET /api/stats -- Market stats (with caching)
    if (method === "GET" && url.pathname === "/api/stats") {
      const cached = await cacheGet("market:stats");
      if (cached) {
        return new Response(cached, {
          status: 200,
          headers: { "Content-Type": "application/json", "X-Cache": "HIT", "Access-Control-Allow-Origin": "*" },
        });
      }
      const stats = getMarketStats();
      const body = JSON.stringify(stats);
      await cacheSet("market:stats", body, 60);
      return new Response(body, {
        status: 200,
        headers: { "Content-Type": "application/json", "X-Cache": "MISS", "Access-Control-Allow-Origin": "*" },
      });
    }

    // GET /api/profile/:userId -- Public profile
    if (method === "GET" && url.pathname.match(/^\/api\/profile\/.+$/)) {
      const userId = url.pathname.split("/").pop()!;
      const profile = getOrCreateProfile(userId);
      return json(profile);
    }

    // ─── Authenticated routes ──────────────────────────

    const session = await getSession(req);

    // POST /api/listings -- Create listing
    if (method === "POST" && url.pathname === "/api/listings") {
      if (!session) return unauthorized();
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
        return json({ error: "domain and askingPrice required" }, 400);

      const listingId = createListing(
        session.user.id,
        body.domain,
        body.askingPrice,
        {
          title: body.title,
          description: body.description,
          minOffer: body.minOffer,
          buyNow: body.buyNow,
          category: body.category,
        },
      );
      const listing = getListing(listingId)!;
      const verification = getVerificationInstructions(
        body.domain,
        listing.verification_token!,
      );
      return json({ listing, verification }, 201);
    }

    // POST /api/listings/:id/verify -- Verify domain ownership
    if (
      method === "POST" &&
      url.pathname.match(/^\/api\/listings\/\d+\/verify$/)
    ) {
      if (!session) return unauthorized();
      const id = parseInt(url.pathname.split("/")[3]!, 10);
      const listing = getListing(id);
      if (!listing) return json({ error: "Not found" }, 404);
      if (listing.user_id !== session.user.id)
        return json({ error: "Not your listing" }, 403);

      const result = await verifyDomainOwnership(id);
      return json(result);
    }

    // PUT /api/listings/:id -- Update listing
    if (method === "PUT" && url.pathname.match(/^\/api\/listings\/\d+$/)) {
      if (!session) return unauthorized();
      const id = parseInt(url.pathname.split("/").pop()!, 10);
      const listing = getListing(id);
      if (!listing) return json({ error: "Not found" }, 404);
      if (listing.user_id !== session.user.id)
        return json({ error: "Not your listing" }, 403);

      const body = (await req.json()) as { status?: string };
      if (body.status)
        updateListingStatus(id, body.status as ListingStatus);
      return json(getListing(id));
    }

    // DELETE /api/listings/:id -- Cancel listing
    if (
      method === "DELETE" &&
      url.pathname.match(/^\/api\/listings\/\d+$/)
    ) {
      if (!session) return unauthorized();
      const id = parseInt(url.pathname.split("/").pop()!, 10);
      const listing = getListing(id);
      if (!listing) return json({ error: "Not found" }, 404);
      if (listing.user_id !== session.user.id)
        return json({ error: "Not your listing" }, 403);
      updateListingStatus(id, "cancelled");
      return json({ success: true });
    }

    // GET /api/my/listings -- My listings
    if (method === "GET" && url.pathname === "/api/my/listings") {
      if (!session) return unauthorized();
      return json(getUserListings(session.user.id));
    }

    // GET /api/my/offers -- My offers (as buyer or seller)
    if (method === "GET" && url.pathname === "/api/my/offers") {
      if (!session) return unauthorized();
      const role = (url.searchParams.get("role") || "buyer") as
        | "buyer"
        | "seller";
      return json(getUserOffers(session.user.id, role));
    }

    // POST /api/offers -- Make an offer
    if (method === "POST" && url.pathname === "/api/offers") {
      if (!session) return unauthorized();
      const body = (await req.json()) as {
        listingId: number;
        amount: number;
        message?: string;
      };
      if (!body.listingId || !body.amount)
        return json({ error: "listingId and amount required" }, 400);

      const listing = getListing(body.listingId);
      if (!listing) return json({ error: "Listing not found" }, 404);
      if (listing.status !== "active")
        return json({ error: "Listing not active" }, 400);
      if (listing.user_id === session.user.id)
        return json({ error: "Cannot offer on your own listing" }, 400);
      if (listing.min_offer && body.amount < listing.min_offer)
        return json(
          { error: `Minimum offer is $${listing.min_offer}` },
          400,
        );

      const offerId = createOffer(
        body.listingId,
        session.user.id,
        listing.user_id,
        body.amount,
        body.message || "",
      );
      return json(getOffer(offerId), 201);
    }

    // PUT /api/offers/:id -- Accept/reject/counter offer
    if (method === "PUT" && url.pathname.match(/^\/api\/offers\/\d+$/)) {
      if (!session) return unauthorized();
      const id = parseInt(url.pathname.split("/").pop()!, 10);
      const offer = getOffer(id);
      if (!offer) return json({ error: "Not found" }, 404);

      const body = (await req.json()) as {
        status: string;
        counterAmount?: number;
      };

      // Only seller can accept/reject/counter
      if (
        ["accepted", "rejected", "countered"].includes(body.status) &&
        offer.seller_id !== session.user.id
      ) {
        return json(
          { error: "Only the seller can accept/reject/counter" },
          403,
        );
      }
      // Only buyer can withdraw
      if (
        body.status === "withdrawn" &&
        offer.buyer_id !== session.user.id
      ) {
        return json({ error: "Only the buyer can withdraw" }, 403);
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

      return json(getOffer(id));
    }

    // GET /api/offers/:id/messages -- Get messages for an offer
    if (
      method === "GET" &&
      url.pathname.match(/^\/api\/offers\/\d+\/messages$/)
    ) {
      if (!session) return unauthorized();
      const offerId = parseInt(url.pathname.split("/")[3]!, 10);
      const offer = getOffer(offerId);
      if (!offer) return json({ error: "Not found" }, 404);
      if (
        offer.buyer_id !== session.user.id &&
        offer.seller_id !== session.user.id
      )
        return json({ error: "Forbidden" }, 403);

      markRead(session.user.id, offerId);
      return json(getMessages(offerId));
    }

    // POST /api/offers/:id/messages -- Send message
    if (
      method === "POST" &&
      url.pathname.match(/^\/api\/offers\/\d+\/messages$/)
    ) {
      if (!session) return unauthorized();
      const offerId = parseInt(url.pathname.split("/")[3]!, 10);
      const offer = getOffer(offerId);
      if (!offer) return json({ error: "Not found" }, 404);
      if (
        offer.buyer_id !== session.user.id &&
        offer.seller_id !== session.user.id
      )
        return json({ error: "Forbidden" }, 403);

      const body = (await req.json()) as { content: string };
      const recipientId =
        session.user.id === offer.buyer_id
          ? offer.seller_id
          : offer.buyer_id;
      const msgId = sendMessage(
        offerId,
        session.user.id,
        recipientId,
        body.content,
      );
      return json({ id: msgId }, 201);
    }

    // GET /api/my/unread -- Unread message count
    if (method === "GET" && url.pathname === "/api/my/unread") {
      if (!session) return unauthorized();
      return json({ count: getUnreadCount(session.user.id) });
    }

    // PUT /api/my/profile -- Update profile
    if (method === "PUT" && url.pathname === "/api/my/profile") {
      if (!session) return unauthorized();
      const body = (await req.json()) as {
        displayName?: string;
        bio?: string;
        website?: string;
      };
      updateProfile(session.user.id, body);
      return json(getOrCreateProfile(session.user.id));
    }

    // GET /api/my/watchlist -- Get watchlist
    if (method === "GET" && url.pathname === "/api/my/watchlist") {
      if (!session) return unauthorized();
      return json(getWatchlist(session.user.id));
    }

    // POST /api/my/watchlist -- Add to watchlist
    if (method === "POST" && url.pathname === "/api/my/watchlist") {
      if (!session) return unauthorized();
      const body = (await req.json()) as { listingId: number };
      addToWatchlist(session.user.id, body.listingId);
      return json({ success: true }, 201);
    }

    // DELETE /api/my/watchlist/:id -- Remove from watchlist
    if (
      method === "DELETE" &&
      url.pathname.match(/^\/api\/my\/watchlist\/\d+$/)
    ) {
      if (!session) return unauthorized();
      const listingId = parseInt(url.pathname.split("/").pop()!, 10);
      removeFromWatchlist(session.user.id, listingId);
      return json({ success: true });
    }

    return json({ error: "Not found" }, 404);
  },
});

// Try connecting to Redis on startup
await getRedis();

const startupMessage = `
Domain Sniper Marketplace running on http://localhost:${PORT}
  Auth:  POST /api/auth/sign-up/email, POST /api/auth/sign-in/email
  API:   GET /api/listings, POST /api/listings, POST /api/offers
  Stats: GET /api/stats
  Redis: ${isRedisAvailable() ? "connected" : "in-memory fallback"}
`;
process.stdout.write(startupMessage);
