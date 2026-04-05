# Domain Sniper

All-in-one domain intelligence toolkit -- WHOIS, DNS, security recon, portfolio management, and a self-hostable marketplace. Built with Bun and TypeScript.

## Install

```bash
git clone https://github.com/yourusername/domain-sniper.git
cd domain-sniper
bun install
```

## Quick Start

```bash
# Interactive TUI -- scan domains, browse intel, manage portfolio
bun run start

# Headless check with JSON output (pipe to jq)
bun run start --headless --json example.com startup.io

# Full security recon on a target
bun run start recon example.com
```

## Features

### Intelligence
- **WHOIS & RDAP** -- Registration info, expiry dates, registrar details
- **DNS Records** -- A, AAAA, MX, TXT, CNAME resolution
- **HTTP Probe** -- Status codes, redirects, parked domain detection
- **SSL Certificates** -- Issuer, expiry, SANs, protocol version
- **Domain Scoring** -- 0-100 based on length, TLD, readability, brandability
- **Wayback Machine** -- Archive history and snapshot count
- **Social Media** -- Username availability across 12 platforms
- **Tech Stack** -- Detect 40+ technologies (CMS, frameworks, CDN, analytics)
- **Backlink Estimation** -- PageRank and CommonCrawl page count
- **Domain Suggestions** -- Generate name ideas from keywords
- **TLD Expansion** -- Check a name across all major TLDs
- **Variations** -- Typos, plurals, prefixes, suffixes

### Security Recon
- **Port Scanner** -- TCP connect scan on 20 common ports with banner grabbing
- **Security Headers** -- HSTS, CSP, X-Frame-Options audit (A+ to F grading)
- **Email Security** -- SPF, DKIM, DMARC analysis
- **WAF Detection** -- Identify 10 firewalls (Cloudflare, AWS, Akamai, etc.)
- **Blacklist Check** -- Query 8 DNS blocklists for reputation
- **Sensitive Paths** -- Scan 37 paths for exposed .env, .git, admin panels
- **CORS Check** -- Test 6 attack vectors for misconfigurations
- **Certificate Transparency** -- Subdomain discovery via crt.sh
- **Subdomain Takeover** -- Dangling CNAME detection (16 services)
- **DNS Zone Transfer** -- AXFR vulnerability check
- **Reverse IP** -- Discover co-hosted domains
- **ASN/Geolocation** -- Network, ISP, and location info

### Portfolio Management
- Track owned domains with purchase price, renewal dates, registrar
- Financial tracking -- P&L, transactions, valuations, ROI
- Renewal calendar with 90/60/30/7 day alerts
- Health monitoring -- WHOIS, DNS, HTTP, SSL checks
- Categories, tags, acquisition pipeline
- CSV export for portfolio, transactions, and tax reporting

### Automation
- **Watch Mode** -- Hourly monitoring of tagged domains
- **Drop Catching** -- High-frequency polling for expiring domains
- **Snipe Engine** -- Auto-register domains the moment they become available
- **Webhooks** -- Slack, Discord, and email notifications
- **Expiring Feed** -- Browse domains about to drop

## TUI Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `/` or `i` | Enter domains to scan |
| `f` | Load domains from file |
| `e` | TLD expansion |
| `v` | Generate variations |
| `d` | Suggest similar names |
| `Space` | Tag/untag domain |
| `r` | Register domain |
| `R` | Bulk register (two-step confirm) |
| `Tab` | Cycle intel tabs |
| `n` | Toggle recon mode |
| `s` | Cycle status filter |
| `o` / `O` | Cycle sort / toggle order |
| `p` | Add to portfolio |
| `P` | Portfolio dashboard |
| `M` | Marketplace |
| `w` | Watch tagged domains |
| `D` | Drop catch (expired) |
| `h` | Scan history |
| `c` | Clear cache |
| `x` | Export CSV/JSON |
| `Ctrl+S` | Save session |
| `Ctrl+L` | Load session |
| `?` | Help |
| `q` | Quit |

## CLI Commands

| Command | Description |
|---------|-------------|
| `domain-sniper` | Interactive TUI mode |
| `domain-sniper example.com --headless` | Quick check |
| `domain-sniper --headless --json example.com` | JSON output |
| `domain-sniper recon example.com` | Full security recon |
| `domain-sniper suggest startup` | Generate domain name ideas |
| `domain-sniper portfolio --dashboard` | Portfolio overview |
| `domain-sniper portfolio --health` | Run health checks |
| `domain-sniper portfolio --pnl` | Profit & loss report |
| `domain-sniper portfolio --renewals` | Renewal calendar |
| `domain-sniper portfolio --export-csv domains.csv` | Export portfolio |
| `domain-sniper expiring --tld com` | Browse expiring domains |
| `domain-sniper dropcatch example.com` | Auto-snipe dropping domain |
| `domain-sniper market browse` | Browse marketplace |
| `domain-sniper market list example.com -p 500` | List for sale |
| `domain-sniper proxy start` | Start HTTP intercept proxy |
| `domain-sniper snipe add example.com` | Add snipe target |
| `domain-sniper db --stats` | Database statistics |
| `domain-sniper config --show` | View configuration |
| `domain-sniper completions zsh` | Shell completions |

## Marketplace

A self-hostable domain marketplace with authentication, listings, offers, messaging, and domain ownership verification.

```bash
# Start the marketplace server
bun run serve

# Browse from CLI
domain-sniper market browse

# List a domain for sale
domain-sniper market list mydomain.com --price 500
```

See [marketplace/README.md](marketplace/README.md) for full API documentation, verification methods, and self-hosting instructions.

## HTTP Proxy

Intercept and inspect HTTP/HTTPS traffic for domain intelligence gathering.

```bash
# Start the proxy
domain-sniper proxy start

# Start with custom port
domain-sniper proxy start --port 8888
```

The proxy generates a local CA certificate at `~/.domain-sniper/ca/`. Install it in your browser to inspect HTTPS traffic.

## Snipe Engine

Automatically register domains the moment they become available.

```bash
# Add a domain to watch
domain-sniper snipe add example.com

# List active snipes
domain-sniper snipe list

# Remove a snipe
domain-sniper snipe remove example.com
```

Requires a registrar API key configured in `.env`.

## Configuration

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

### Registrar API (for domain registration)
- GoDaddy, Namecheap, or Cloudflare
- Set `REGISTRAR_PROVIDER`, `REGISTRAR_API_KEY`, `REGISTRAR_API_SECRET`

### Marketplace
- Set `BETTER_AUTH_SECRET` (min 32 chars) for auth
- Set `BETTER_AUTH_URL` for server URL
- Set `MARKET_URL` to point CLI at your marketplace instance

### Persistent config
```bash
domain-sniper config --set concurrency=10
domain-sniper config --set notifications.webhookUrl=https://hooks.slack.com/...
```

## Self-Hosting the Marketplace

1. Clone the repo
2. Set `BETTER_AUTH_SECRET` and `BETTER_AUTH_URL` in `.env`
3. Run `bun run serve`
4. Point CLI clients to your server: `domain-sniper market login --server https://your-server.com`

For production, consider PostgreSQL, rate limiting, and TLS. See [marketplace/README.md](marketplace/README.md).

## Architecture

```
src/core/           Portable business logic (40+ modules)
src/proxy/          HTTP/HTTPS interceptor
src/app.tsx         TUI (React + @opentui)
src/index.tsx       CLI (Commander)
src/market-client.ts  Marketplace API client
marketplace/        Self-hostable marketplace server
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full breakdown.

## Security

- Registrar API keys never leave your machine
- All inputs validated, all queries parameterized
- Shell commands use `execFile` (no injection)
- File paths confined to allowed directories

See [docs/SECURITY.md](docs/SECURITY.md) for the full security model.

## Tech Stack

- **Runtime:** Bun
- **Language:** TypeScript (strict mode)
- **TUI:** @opentui/react
- **Database:** SQLite (bun:sqlite)
- **Auth:** Better Auth
- **Tests:** bun:test

## Contributing

1. Fork the repo
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Write tests first, then implement
4. Ensure `bunx tsc --noEmit` passes
5. Ensure `bun test` passes
6. Submit a pull request

## License

MIT -- see [LICENSE](LICENSE).
