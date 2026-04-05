# Architecture

## Overview

Domain Sniper is split into two parts:

```
domain-sniper (open source)     marketplace/ (self-hostable service)
├── src/core/    Business logic  ├── auth.ts     Better Auth
├── src/proxy/   HTTP interceptor├── db.ts       Marketplace DB
├── src/app.tsx  TUI             ├── index.ts    REST API server
├── src/index.tsx CLI            └── verify.ts   Domain verification
└── src/market-client.ts  API client
```

### Core (`src/core/`)

All portable business logic. Zero UI dependencies. Can be imported by any TypeScript project.

```
core/
├── db.ts              SQLite database (domains, scans, sessions, portfolio, cache, snipes)
├── types.ts           Shared type definitions (DomainEntry, 25+ interfaces)
├── validate.ts        Input validation (domain regex, path confinement, session IDs)
├── whois.ts           WHOIS lookup + DNS verification
├── registrar.ts       GoDaddy / Namecheap / Cloudflare API integrations
├── theme.ts           Color palette + status styling
├── paths.ts           Shared path constants
├── index.ts           Barrel export
└── features/
    ├── dns-details.ts         A/AAAA/MX/TXT/CNAME lookups
    ├── http-probe.ts          HTTP status, redirects, parked detection
    ├── ssl-check.ts           TLS certificate inspection
    ├── rdap.ts                Modern WHOIS (structured JSON)
    ├── wayback.ts             Wayback Machine history
    ├── domain-age.ts          Age calculation + expiry countdown
    ├── scoring.ts             Domain quality scoring (0-100)
    ├── domain-suggest.ts      Name generation from keywords
    ├── variations.ts          Typo/plural/prefix variations
    ├── tld-expand.ts          Check name across TLDs
    ├── social-check.ts        Username availability (12 platforms)
    ├── tech-stack.ts          Technology detection (40+)
    ├── backlinks.ts           PageRank + CommonCrawl estimation
    ├── blacklist-check.ts     DNS blocklist reputation (8 lists)
    ├── email-security.ts      SPF/DKIM/DMARC audit
    ├── security-headers.ts    HTTP security headers (A+ to F)
    ├── waf-detect.ts          WAF fingerprinting (10 vendors)
    ├── cors-check.ts          CORS misconfiguration testing
    ├── path-scanner.ts        Sensitive path detection (37 paths)
    ├── port-scanner.ts        TCP connect scan (20 ports)
    ├── cert-transparency.ts   crt.sh subdomain discovery
    ├── subdomain-discovery.ts DNS subdomain brute-force
    ├── takeover-detect.ts     Dangling CNAME detection (16 services)
    ├── zone-transfer.ts       AXFR vulnerability check
    ├── reverse-ip.ts          Shared hosting discovery
    ├── asn-lookup.ts          ASN/IP geolocation
    ├── marketplace.ts         Aftermarket price check
    ├── price-compare.ts       Multi-registrar pricing
    ├── portfolio.ts           Portfolio management
    ├── portfolio-monitor.ts   Health monitoring + renewal alerts
    ├── portfolio-bulk.ts      Bulk operations + CSV export
    ├── session.ts             Scan session management
    ├── filter.ts              Filter + sort domains
    ├── export.ts              CSV/JSON export
    ├── config.ts              Persistent configuration
    ├── watch.ts               Watch mode (hourly monitoring)
    ├── drop-catch.ts          Drop catching (high-frequency polling)
    ├── snipe.ts               Unified snipe pipeline
    ├── webhooks.ts            Slack/Discord/email notifications
    ├── whois-history.ts       WHOIS change tracking
    └── expiring-feed.ts       Expiring domains feed
```

### Data Flow

```
User Input -> Validate -> Process Domain -> [WHOIS + DNS + HTTP + SSL + ...]
                                             | (parallel)
                                          Cache (5min TTL)
                                             |
                                          SQLite DB
                                             |
                                       TUI / CLI / JSON Output
```

### Database Schema

Single SQLite file at `~/.domain-sniper/domain-sniper.db`:
- `domains` -- Every domain ever scanned (deduplicated)
- `scans` -- Full scan results (JSON blob per scan)
- `sessions` -- Named scan batches
- `portfolio` -- Owned domains with financials
- `portfolio_transactions` -- P&L tracking
- `portfolio_valuations` -- Value history
- `acquisition_pipeline` -- Domains being tracked for purchase
- `portfolio_categories` -- Organization categories
- `portfolio_alerts` -- Expiry/SSL/uptime alerts
- `whois_history` -- WHOIS snapshots over time
- `cache` -- TTL-based scan result cache
- `snipes` -- Auto-registration targets
- `migrations` -- Schema version tracking

### Security Model

- All shell commands use `execFile` (never `exec` with string interpolation)
- Domain names validated against strict regex before any system call
- File paths confined to allowed directories via `safePath()`
- Session IDs restricted to alphanumeric + hyphens
- API responses typed (no `any` on external data)
- Registrar API keys stay local (never sent to marketplace)
- Marketplace auth uses Better Auth with hashed passwords
