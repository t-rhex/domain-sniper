# domsniper

All-in-one domain intelligence toolkit -- WHOIS, DNS, security recon, portfolio management, and automated domain sniping. Built with Bun.

[![npm](https://img.shields.io/npm/v/domsniper)](https://www.npmjs.com/package/domsniper)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Install

```bash
# Run directly (no install)
bunx domsniper

# Install globally
bun add -g domsniper

# Or clone for development
git clone https://github.com/t-rhex/domain-sniper.git
cd domain-sniper && bun install
```

**Requirements:** [Bun](https://bun.sh) runtime, `whois` and `dig` CLI tools.

## Quick Start

```bash
# Interactive TUI
domsniper

# Check a domain
domsniper example.com --headless

# JSON output (pipe to jq)
domsniper --headless --json example.com

# Full security recon
domsniper recon example.com

# Generate name ideas
domsniper suggest startup --check

# Snipe a domain (auto-register when it drops)
domsniper snipe add expiring-domain.com
domsniper snipe run
```

## Features

### Domain Intelligence
- **WHOIS & RDAP** -- Registration, expiry, registrar details
- **DNS Records** -- A, AAAA, MX, TXT, CNAME
- **HTTP Probe** -- Status, redirects, parked domain detection
- **SSL Certificates** -- Issuer, expiry, SANs, protocol
- **Domain Scoring** -- 0-100 (length, TLD, readability, brandability, SEO)
- **Wayback Machine** -- Archive history, snapshot count
- **Social Media** -- Username availability (12 platforms)
- **Tech Stack** -- 40+ technologies (CMS, frameworks, CDN, analytics)
- **Backlinks** -- PageRank + CommonCrawl estimation
- **Suggestions** -- Name ideas from keywords
- **TLD Expansion** -- Check a name across all major TLDs
- **Variations** -- Typos, plurals, prefixes, suffixes

### Security Recon (toggle with `n` key)
- **Port Scanner** -- 20 ports, banner grabbing
- **Security Headers** -- 9 headers, A+ to F grading
- **Email Security** -- SPF/DKIM/DMARC audit
- **WAF Detection** -- 10 firewalls (Cloudflare, AWS, Akamai, etc.)
- **Blacklist Check** -- 8 DNS blocklists
- **Sensitive Paths** -- 37 paths (.env, .git, admin panels, SQL dumps)
- **CORS Check** -- 6 attack vectors
- **Cert Transparency** -- Subdomain discovery via crt.sh
- **Subdomain Takeover** -- 16 services (GitHub Pages, Heroku, S3, etc.)
- **DNS Zone Transfer** -- AXFR vulnerability check
- **Reverse IP** -- Shared hosting discovery
- **ASN/Geolocation** -- Network, ISP, location

### Portfolio Manager
- Track domains with purchase price, renewal dates, registrar
- P&L tracking, transactions, valuations, ROI
- Renewal calendar with alerts (90/60/30/7 days)
- Health monitoring (WHOIS, DNS, HTTP, SSL)
- Categories, pipeline, bulk operations
- CSV export (portfolio, transactions, tax)

### Automation
- **Snipe Engine** -- Watch -> detect expiry -> auto-register -> notify
- **Watch Mode** -- Hourly monitoring
- **Drop Catch** -- 30-second polling for pending-delete domains
- **Webhooks** -- Slack, Discord, email notifications

### HTTP Proxy
- Intercept and log HTTP traffic
- Request replay
- CA cert generation for HTTPS
- Credential redaction in logs

## TUI Shortcuts

| Key | Action | Key | Action |
|-----|--------|-----|--------|
| `/` | Scan domains | `Tab` | Cycle intel tabs |
| `e` | TLD expansion | `n` | Toggle recon mode |
| `f` | Load from file | `s` | Cycle status filter |
| `v` | Variations | `o/O` | Sort field/order |
| `d` | Suggestions | `Space` | Tag/untag |
| `r` | Register | `R` | Bulk register |
| `S` | Snipe domain | `D` | Drop catch |
| `p` | Add to portfolio | `P` | Portfolio dashboard |
| `M` | Marketplace | `w` | Watch tagged |
| `h` | Scan history | `c` | Clear cache |
| `x` | Export CSV/JSON | `?` | Help |
| `Ctrl+S` | Save session | `q` | Quit |

## CLI Commands

```bash
# Scanning
domsniper example.com --headless          # Quick check
domsniper --headless --json example.com   # JSON output
domsniper --headless --recon example.com  # With security recon
domsniper recon example.com              # Standalone recon report

# Domain discovery
domsniper suggest startup --check         # Generate + check ideas
domsniper expiring --tld com             # Browse expiring domains

# Sniping
domsniper snipe add example.com           # Add snipe target
domsniper snipe list                      # List targets
domsniper snipe run                       # Start snipe engine
domsniper dropcatch example.com           # Direct drop catch

# Portfolio
domsniper portfolio --dashboard           # Overview
domsniper portfolio --pnl                 # Profit & loss
domsniper portfolio --health              # Health check all domains
domsniper portfolio --renewals            # Renewal calendar
domsniper portfolio --export-csv out.csv  # Export

# Marketplace
domsniper market signup                   # Create account
domsniper market browse                   # Browse listings
domsniper market list example.com -p 500  # List for sale
domsniper market offer -l 1 -a 300       # Make offer

# Proxy
domsniper proxy start --port 8080         # Start interceptor
domsniper proxy history --host target.com # Browse captured traffic
domsniper proxy replay 42                 # Replay a request

# Utilities
domsniper db --stats                      # Database stats
domsniper config --show                   # View config
domsniper check-update                    # Check for updates
domsniper completions zsh                 # Shell completions
```

## Configuration

```bash
cp .env.example .env
```

Key settings:
- `REGISTRAR_PROVIDER` / `REGISTRAR_API_KEY` -- For domain registration (GoDaddy/Namecheap/Cloudflare)
- `MARKET_URL` -- Marketplace server URL
- `S3_BUCKET` / `S3_ACCESS_KEY_ID` -- Cloud export storage

```bash
# Persistent config
domsniper config --set concurrency=10
domsniper config --set notifications.webhookUrl=https://hooks.slack.com/...
```

## Architecture

```
src/core/              Portable business logic (40+ modules)
src/core/db.ts         SQLite database (scans, portfolio, cache, snipes)
src/proxy/             HTTP/HTTPS interceptor
src/app.tsx            TUI (React + @opentui)
src/index.tsx          CLI (Commander)
src/market-client.ts   Marketplace API client
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/SECURITY.md](docs/SECURITY.md).

## Contributing

1. Fork and clone
2. `bun install`
3. Write tests: `bun test`
4. Type check: `bunx tsc --noEmit`
5. Submit PR

## License

MIT
