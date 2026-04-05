# Security

## For Users

### API Keys
- Registrar API keys (GoDaddy/Namecheap/Cloudflare) are stored in your local `.env` file
- They are NEVER sent to the marketplace server or any third party
- The marketplace uses separate Better Auth credentials

### Proxy
- The HTTP proxy generates a local CA certificate at `~/.domain-sniper/ca/`
- Only install the CA cert on machines you control
- Never share your CA private key (`ca.key`)

### Database
- All data stored locally at `~/.domain-sniper/`
- The `domain-sniper.db` contains your scan history, portfolio, and snipe targets
- Back it up if you care about the data

## For Developers

### Input Validation
- All domain names pass through `isValidDomain()` regex before any operation
- Shell commands use `execFile()` with argument arrays -- never string interpolation
- File paths are resolved and confined to allowed directories

### What We Protect Against
- **Command injection** -- `execFile` prevents `; rm -rf /` in domain names
- **Path traversal** -- `safePath()` prevents `../../etc/passwd` in file inputs
- **SQL injection** -- All queries use parameterized bindings
- **Session fixation** -- Session IDs validated against `[a-z0-9-]` regex
- **XSS via domain names** -- Domains stripped of HTML/script characters by regex

### Pentest/Recon Features
The security scanning features (port scan, path scanner, CORS check, etc.) are for **authorized testing only**. Use them on domains you own or have explicit permission to test.
