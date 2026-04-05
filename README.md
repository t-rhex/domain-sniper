# Domain Sniper

All-in-one domain intelligence toolkit — availability checker, security recon, portfolio manager, and marketplace. Built with Bun and TypeScript.

## Install

```bash
bun install
```

## Quick Start

```bash
# TUI mode (interactive)
bun run start

# Check domains
bun run start example.com github.com

# Headless mode
bun run start --headless example.com

# JSON output (pipe to jq)
bun run start --headless --json example.com

# Full security recon
bun run start recon example.com
```

## Features

### Domain Intelligence
- **WHOIS & RDAP** — Registration info, expiry dates, registrar details
- **DNS Records** — A, AAAA, MX, TXT, CNAME resolution
- **HTTP Probe** — Status codes, redirects, parked domain detection
- **SSL Certificates** — Issuer, expiry, SANs, protocol version
- **Domain Scoring** — 0-100 score based on length, TLD, readability, brandability, SEO
- **Wayback Machine** — Archive history and snapshot count
- **Social Media** — Username availability across 12 platforms
- **Tech Stack** — Detect 40+ technologies (CMS, frameworks, CDN, analytics)
- **Backlink Estimation** — PageRank and CommonCrawl page count

### Security Recon (toggle with `n` key)
- **Port Scanner** — TCP connect scan on 20 common ports with banner grabbing
- **Security Headers** — HSTS, CSP, X-Frame-Options audit with A+ to F grading
- **Email Security** — SPF, DKIM, DMARC analysis with grading
- **WAF Detection** — Identify 10 firewalls (Cloudflare, AWS, Akamai, etc.)
- **Blacklist Check** — Query 8 DNS blocklists for reputation
- **Sensitive Paths** — Scan 37 paths for exposed .env, .git, admin panels
- **CORS Check** — Test 6 attack vectors for misconfigurations
- **Certificate Transparency** — Find all subdomains via crt.sh
- **Subdomain Takeover** — Detect dangling CNAMEs to 16 services
- **DNS Zone Transfer** — AXFR vulnerability check
- **Reverse IP** — Discover co-hosted domains
- **ASN/Geolocation** — Network, ISP, and location info

### Portfolio Manager
- Track owned domains with purchase price, renewal dates, registrar
- Financial tracking — P&L, transactions, valuations, ROI
- Renewal calendar with 90/60/30/7 day alerts
- Health monitoring — WHOIS, DNS, HTTP, SSL checks
- Categories, tags, acquisition pipeline
- CSV export for portfolio, transactions, and tax reporting

### Marketplace
- List domains for sale with domain ownership verification (DNS TXT, HTTP file, meta tag)
- Browse and search listings
- Make and receive offers with counter-offer support
- User authentication via Better Auth
- Messaging between buyers and sellers

### CLI Commands

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
| `domain-sniper serve` | Start marketplace server |
| `domain-sniper db --stats` | Database statistics |
| `domain-sniper config --show` | View configuration |
| `domain-sniper completions zsh` | Shell completions |

### TUI Keyboard Shortcuts

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
| `Tab` | Cycle INTEL tabs |
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

### Persistent config
```bash
domain-sniper config --set concurrency=10
domain-sniper config --set notifications.webhookUrl=https://hooks.slack.com/...
```

## Tech Stack

- **Runtime:** Bun
- **Language:** TypeScript (strict mode)
- **TUI:** @opentui/react
- **Database:** SQLite (bun:sqlite)
- **Auth:** Better Auth
- **Tests:** bun:test (111 tests)

## License

MIT
