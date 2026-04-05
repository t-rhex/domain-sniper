# Domain Sniper Marketplace Server

Self-hostable domain marketplace with user authentication, domain listings, offers, and ownership verification.

## Quick Start

```bash
# From the project root
bun run serve

# Or directly
bun run marketplace/index.ts
```

## Configuration

Create a `.env` file in the project root:

```bash
BETTER_AUTH_SECRET=your-secret-key-min-32-chars
BETTER_AUTH_URL=http://localhost:3000
MARKET_PORT=3000
```

## API Endpoints

### Authentication (Better Auth)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/sign-up/email` | Register `{email, password, name}` |
| POST | `/api/auth/sign-in/email` | Login `{email, password}` |

### Listings

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/listings` | Browse listings (query: `q`, `category`, `min`, `max`, `verified`, `sort`, `limit`, `offset`) | No |
| GET | `/api/listings/:id` | View listing details | No |
| POST | `/api/listings` | Create listing `{domain, askingPrice, title?, description?, minOffer?, buyNow?, category?}` | Yes |
| PUT | `/api/listings/:id` | Update listing `{status}` | Yes (owner) |
| DELETE | `/api/listings/:id` | Cancel listing | Yes (owner) |
| POST | `/api/listings/:id/verify` | Verify domain ownership | Yes (owner) |

### Offers

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/api/offers` | Make offer `{listingId, amount, message?}` | Yes |
| PUT | `/api/offers/:id` | Accept/reject/counter `{status, counterAmount?}` | Yes |

### User

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/my/listings` | Your listings | Yes |
| GET | `/api/my/offers?role=buyer\|seller` | Your offers | Yes |
| GET | `/api/my/unread` | Unread message count | Yes |
| PUT | `/api/my/profile` | Update profile `{displayName?, bio?, website?}` | Yes |
| GET | `/api/my/watchlist` | Your watchlist | Yes |
| POST | `/api/my/watchlist` | Add to watchlist `{listingId}` | Yes |
| DELETE | `/api/my/watchlist/:id` | Remove from watchlist | Yes |

### Messages

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/offers/:id/messages` | Get messages for offer | Yes |
| POST | `/api/offers/:id/messages` | Send message `{content}` | Yes |

### Public

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/stats` | Marketplace statistics |
| GET | `/api/profile/:userId` | Public user profile |

## Domain Verification

Before a listing goes active, the seller must prove they own the domain. Three methods supported:

### 1. DNS TXT Record
Add a TXT record to your domain:
```
domain-sniper-verify=<token>
```

### 2. HTTP File
Create a file at:
```
https://yourdomain.com/.well-known/domain-sniper-verify.txt
```
Contents: the verification token

### 3. Meta Tag
Add to your homepage:
```html
<meta name="domain-sniper-verify" content="<token>">
```

Then run: `domain-sniper market verify yourdomain.com`

## Database

Uses SQLite stored at `~/.domain-sniper/marketplace.db` with tables:
- `listings` -- Domain listings with pricing, verification, status
- `offers` -- Buy offers with counter-offer support
- `user_profiles` -- Seller/buyer profiles with ratings
- `reviews` -- Transaction reviews
- `messages` -- Offer-related messaging
- `market_watchlist` -- Saved listings

Auth data stored in separate `~/.domain-sniper/auth.db` (Better Auth managed).

## Self-Hosting

The marketplace is designed to be self-hosted. To run your own instance:

1. Clone the repo
2. Set `BETTER_AUTH_SECRET` and `BETTER_AUTH_URL` in `.env`
3. Run `bun run serve`
4. Point CLI clients to your server: `domain-sniper market login --server https://your-server.com`

## Production Deployment

For production, consider:
- Use PostgreSQL instead of SQLite (swap `bun:sqlite` for `Bun.sql`)
- Add rate limiting
- Put behind a reverse proxy (nginx/Caddy) with TLS
- Set proper CORS origins in `auth.ts`
