<p align="center">
  <pre align="center">
  ██████╗ ███████╗██████╗  ██████╗ ██╗   ██╗███╗   ██╗
  ██╔══██╗██╔════╝██╔══██╗██╔════╝ ██║   ██║████╗  ██║
  ██████╔╝█████╗  ██║  ██║██║  ███╗██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║  ██║██║   ██║██║   ██║██║╚██╗██║
  ██║  ██║███████╗██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝
  </pre>
</p>

<p align="center">
  <strong>Black-box & white-box security auditor for web applications — Enhanced.</strong>
</p>

<p align="center">
  <a href="https://github.com/aloc999/redgun/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="License"></a>
  <img src="https://img.shields.io/badge/node-%3E%3D18-green" alt="Node">
  <img src="https://img.shields.io/badge/modules-51-ff4444" alt="Modules">
</p>

<br>

## What is RedGun?

RedGun is a security auditing CLI tool that finds vulnerabilities in your web applications. It includes **51 security modules** covering techniques from modern techniques. Two modes:

**Remote scan** (black-box): Give it a URL. It crawls with Katana-style JS parsing, fingerprints with httpx-style probing, then tests — XSS, SQLi, SSRF, CORS, XXE, OAuth, IDOR, cache deception, DOM-based, HTTP smuggling, CRLF, parameter pollution, file upload, and more.

**Local audit** (white-box): Point it at your project directory. It reads your source code checking for secrets, SSTI, XXE, insecure deserialization, prototype pollution, JWT attacks, OAuth flaws, IDOR, business logic, command injection, weak crypto, and more.

<br>

## Quick start

```bash
# Install globally
npm install -g redgun-security

# Interactive mode
redgun

# Or run directly
redgun scan https://target.com    # Remote scan (black-box)
redgun audit .                    # Local audit (white-box)
redgun audit . --ci               # CI mode (exit code 0 or 1)
redgun history                    # View saved reports
redgun modules                    # List all modules
```

<br>

## Remote Scan Modules (33 — Black-box)

| Module | What it tests |
|---|---|
| **Probe & Fingerprint** | Status code, title, technologies (40+), CDN/WAF detection, favicon hash, response time, virtual host discovery |
| **Crawl & Extract** | JS file parsing, endpoint extraction, form discovery, parameter mining, email harvesting, secret detection in bundles |
| **HTTP Headers** | Missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, CORP, COEP |
| **Exposed Files** | `.env`, `.git/config`, `package.json`, `.DS_Store`, source maps, actuator, swagger, phpinfo, Docker files, backups |
| **Secrets Detection** | API keys (AWS, Stripe, Firebase, Supabase, OpenAI, Anthropic), tokens, passwords in page source |
| **XSS Reflected** | 6 payloads × 14 parameters, DOM-based indicators |
| **SQL Injection** | Error-based, UNION-based, time-based blind across common parameters |
| **CORS Misconfiguration** | Wildcard + credentials, reflected origin, null origin |
| **Open Redirect** | 12 redirect parameters tested with external URL |
| **SSRF** | AWS metadata, internal IPs, localhost, IPv6, decimal IP, file:// protocol |
| **Host Header Injection** | Reflected host, X-Forwarded-Host poisoning |
| **HTTP Request Smuggling** | CL.TE probe detection |
| **CRLF Injection** | Header injection via URL encoding variants |
| **GraphQL Introspection** | Schema exposure via introspection query at 5 endpoints |
| **Clickjacking** | Missing X-Frame-Options and frame-ancestors CSP |
| **Cookie Security** | Missing HttpOnly, Secure, SameSite flags |
| **HTTP Methods** | TRACE, PUT, DELETE enabled |
| **Subdomain Enumeration** | 40+ common subdomains, dangerous subdomain detection |
| **DNS & Email** | SPF, DKIM, DMARC analysis |
| **Technology Fingerprint** | 40+ frameworks, servers, and services detected |
| **API Discovery** | Common API paths, auth testing |
| **SSL/TLS Analysis** | HTTP vs HTTPS detection |
| **Path Traversal / LFI** | Double-encoding, unicode bypass, null byte |
| **NoSQL Injection** | MongoDB operator injection auth bypass |
| **WebSocket Security** | Origin validation, authentication checks |
| **Cache Poisoning** | Unkeyed headers (X-Forwarded-Host, X-Forwarded-Scheme, X-Original-URL) |
| **Race Conditions** | Detection guidance for concurrent request attacks |
| **XXE Injection** | XML entity injection at upload/import/SOAP endpoints |
| **OAuth Misconfiguration** | redirect_uri validation, OIDC config exposure, implicit flow detection |
| **Access Control Bypass** | Admin panel exposure, 403 bypass via X-Original-URL/X-Forwarded-For, robots.txt disclosure |
| **Web Cache Deception** | Static extension cache deception, path normalization inconsistency |
| **Parameter Pollution** | HTTP Parameter Pollution, null byte truncation, duplicate params |
| **File Upload Testing** | Upload endpoint discovery, OPTIONS probing |
| **DOM-Based Vulnerabilities** | DOM sinks (document.write, innerHTML, eval, postMessage), source-to-sink flow |
| **HTTP/2 Attacks** | H2.CL/H2.TE smuggling indicators, HPACK injection surface |

<br>

## Local Audit Modules (18 — White-box)

| Module | What it checks |
|---|---|
| **Code Secrets** | 25+ secret patterns (AWS, GitHub, Stripe, OpenAI, Anthropic, Discord, Telegram, npm, etc.) with line numbers |
| **Environment Files** | `.env` in `.gitignore`, real secrets in `.env.example`, sensitive config exposure |
| **Dependencies** | `npm audit` for CVEs, supply-chain attack package detection |
| **Code Vulnerabilities** | SQL injection (template literals), XSS (`v-html`, `dangerouslySetInnerHTML`, `innerHTML`), eval(), ReDoS |
| **Auth & Middleware** | Rate limiting, CORS wildcards, CSRF protection, session config, JWT expiration, hardcoded passwords |
| **Headers Config** | CSP/HSTS in Nuxt, Next.js, Vercel, Netlify, Express configs |
| **SSRF Detection** | User-controlled URLs in fetch/axios/request/http.get/urllib |
| **SSTI Detection** | Jinja2, Twig, Nunjucks, Pug, EJS, Handlebars, Velocity, Freemarker, Thymeleaf |
| **Insecure Deserialization** | pickle, yaml.load, unserialize, ObjectInputStream, Marshal, BinaryFormatter |
| **Prototype Pollution** | Object.assign, spread operator, deepmerge, lodash.merge, __proto__ access |
| **JWT Vulnerabilities** | Algorithm "none", verify disabled, weak secrets, expiration bypass, decode without verify |
| **Path Traversal / LFI** | User input in file paths, readFile, sendFile, include/require |
| **Command Injection** | exec, spawn, child_process, system, subprocess with user input, shell interpolation |
| **Weak Cryptography** | MD5, SHA1, DES, RC4, ECB mode, Math.random, hardcoded keys/IVs |
| **XXE Detection** | XML parsers without entity disabled, DOMParser, lxml, simplexml with user input |
| **Access Control / IDOR** | Direct object reference, role from user input, admin headers, ownership checks |
| **OAuth / OIDC Flaws** | redirect_uri manipulation, missing state, client_secret exposure, token storage |
| **Business Logic** | Price manipulation, negative quantity, workflow step skipping, race conditions, referral abuse |

<br>

## GitHub Action

Add `.github/workflows/security.yml` to your repo:

```yaml
name: Security
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: write
  pull-requests: write
  security-events: write

jobs:
  redgun:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aloc999/redgun@v1
```

### Inputs

| Input | Description | Default |
|---|---|
| `path` | Project path to audit | `.` |
| `min-score` | Minimum score required to pass (0-100) | `70` |
| `fail-on-score` | Fail the workflow if score is below min-score | `true` |
| `comment-pr` | Post a comment on pull requests | `true` |
| `update-badge` | Update the security badge file on push | `true` |
| `upload-sarif` | Upload SARIF findings to GitHub Code Scanning | `true` |

### Outputs

| Output | Description |
|---|---|
| `score` | Security score from 0 to 100 |
| `grade` | Grade from A to F |
| `total-findings` | Total number of findings |
| `critical-findings` | Number of critical findings |
| `high-findings` | Number of high severity findings |

<br>

## Scoring

Every scan produces a security score from 0 to 100, graded A through F.

| Severity | Score impact | Meaning |
|---|---|
| **Critical** | -15 | Exploitable vulnerability, immediate action required |
| **High** | -8 | Serious risk, fix soon |
| **Medium** | -3 | Moderate risk, fix when possible |
| **Low** | -1 | Minor risk |
| **Info** | 0 | Informational, no action needed |

<br>

## Configuration

### CLI options

```bash
redgun scan                          # Interactive remote scan
redgun scan https://target.com       # Direct URL scan
redgun audit .                       # Audit current directory
redgun audit /path/to/project        # Audit specific project
redgun audit . --ci                  # CI mode, exit 1 if score < 70
redgun audit . --ci --min-score 80   # Custom threshold
redgun audit . --modules secrets,jwt # Run specific modules only
redgun audit . --sarif               # Generate SARIF output
redgun history                       # Browse saved reports
redgun modules                       # List all modules
```

### Config file (optional)

Create `redgun.config.js` in your project root:

```js
export default {
  url: 'https://your-site.com',
  ignore: ['Firebase API Key'],
  ci: {
    minScore: 70,
    failOnCritical: true,
  },
}
```

### `.redgunignore` (optional)

Create a `.redgunignore` file to exclude files from local audit:

```
**/i18n/**
**/locales/**
*.locale.*
```

<br>

## Techniques & Sources

### HackTricks Techniques

- **SSRF** — AWS/GCP metadata, internal IP bypass, DNS rebinding indicators
- **SSTI** — Template engine detection and exploitation patterns
- **Insecure Deserialization** — Language-specific gadget chain detection
- **Prototype Pollution** — Object merge sinks and __proto__ injection
- **JWT Attacks** — Algorithm confusion, none bypass, key brute-force indicators
- **HTTP Request Smuggling** — CL.TE/TE.CL probe methodology
- **Cache Poisoning** — Unkeyed header detection and Web Cache Deception
- **CRLF Injection** — Header injection via encoding variants
- **GraphQL** — Introspection, batching, query depth abuse
- **NoSQL Injection** — MongoDB operator injection ($ne, $gt, $regex)
- **Host Header Injection** — Password reset poisoning, cache poisoning via Host
- **Path Traversal** — Double encoding, unicode bypass, null byte truncation
- **Command Injection** — Shell metacharacter injection patterns
- **Race Conditions** — Single-packet HTTP/2 attack detection guidance
- **Open Redirect** — OAuth token theft chain detection
- **Subdomain Takeover** — Dangling CNAME detection
- **Weak Cryptography** — Deprecated algorithms and hardcoded key detection

### PortSwigger Web Security Academy Techniques

- **XXE (XML External Entity)** — Entity injection, DTD-based file read, blind OOB XXE, parameter entities
- **Access Control** — Horizontal/vertical privilege escalation, IDOR, 403 bypass via headers (X-Original-URL, X-Rewrite-URL), referer-based control
- **OAuth 2.0 Vulnerabilities** — redirect_uri manipulation, state CSRF, implicit flow token theft, client_secret exposure, PKCE bypass
- **Business Logic** — Price manipulation, negative quantity, workflow step skipping, race condition exploitation, referral abuse, trial abuse
- **Web Cache Deception** — Static extension deception, path normalization inconsistency, cache key manipulation
- **DOM-Based Vulnerabilities** — Source-to-sink analysis, document.write, innerHTML, eval, postMessage hijacking
- **HTTP Parameter Pollution** — Duplicate parameters, server-side truncation, null byte injection
- **File Upload** — Unrestricted upload, extension bypass, content-type manipulation, polyglot files
- **HTTP/2 Attacks** — H2.CL smuggling, H2.TE smuggling, HPACK header injection, request tunneling

### Katana (ProjectDiscovery) Techniques

- **JavaScript Crawling** — Parse all JS bundles including lazy-loaded chunks for endpoints
- **Endpoint Extraction** — API routes, fetch/axios calls, URL patterns from source
- **Form Discovery** — Automatic form detection with CSRF and sensitive field analysis
- **Parameter Mining** — Extract all parameters from URLs, forms, and JS source
- **Secret Extraction** — API keys, tokens, and credentials from JS bundles
- **Email Harvesting** — Email addresses from page source for social engineering

### httpx (ProjectDiscovery) Techniques

- **Technology Detection** — 40+ technologies fingerprinted (frameworks, CMS, servers, BaaS, analytics)
- **CDN/WAF Detection** — Cloudflare, AWS CloudFront, Fastly, Akamai, Imperva, Sucuri, Azure, Vercel, Netlify
- **WAF Fingerprinting** — ModSecurity, Wordfence, F5 BIG-IP, Cloudflare WAF, Incapsula
- **Favicon Hashing** — MD5 hash for Shodan-style fingerprinting
- **Virtual Host Discovery** — Host header manipulation to find hidden vhosts
- **Response Analysis** — Status codes, content-length, response time, title extraction
- **TLS/Certificate Info** — Protocol detection, certificate validation

<br>

## Project Structure

```
redgun/
├── bin/
│   └── redgun.js                    # CLI entry point
├── src/
│   ├── core/
│   │   ├── findings.js              # Shared findings store
│   │   ├── score.js                 # A-F score calculator
│   │   └── reporter/
│   │       ├── console.js           # Terminal output
│   │       ├── json.js              # JSON + SARIF export
│   │       └── html.js              # HTML report
│   ├── local/                       # White-box modules (18)
│   │   ├── index.js                 # Module orchestrator
│   │   ├── secrets.js               # Source code secrets
│   │   ├── env.js                   # .env audit
│   │   ├── dependencies.js          # npm audit + supply chain
│   │   ├── code-vulnerabilities.js  # SQLi, XSS, eval, ReDoS
│   │   ├── auth.js                  # Auth & middleware
│   │   ├── headers-config.js        # CSP/HSTS config
│   │   ├── ssrf.js                  # SSRF (HackTricks)
│   │   ├── ssti.js                  # SSTI (HackTricks)
│   │   ├── deserialization.js       # Insecure deserialization (HackTricks)
│   │   ├── prototype-pollution.js   # Prototype pollution (HackTricks)
│   │   ├── jwt.js                   # JWT vulnerabilities (HackTricks)
│   │   ├── path-traversal.js        # LFI/path traversal (HackTricks)
│   │   ├── command-injection.js     # OS command injection (HackTricks)
│   │   ├── crypto.js               # Weak cryptography (HackTricks)
│   │   ├── xxe.js                   # XXE detection (PortSwigger)
│   │   ├── access-control.js        # IDOR/access control (PortSwigger)
│   │   ├── oauth.js                 # OAuth/OIDC flaws (PortSwigger)
│   │   └── business-logic.js        # Business logic (PortSwigger)
│   ├── remote/                      # Black-box enhanced modules
│   │   ├── crawler.js               # Katana-style JS crawler
│   │   ├── probe.js                 # httpx-style fingerprinting
│   │   └── portswigger.js           # PortSwigger remote tests
│   └── utils/
│       ├── fetch.js                 # HTTP with timeout
│       └── patterns.js              # Shared regex patterns
├── scan.js                          # Remote scan engine (33 modules)
├── action.yml                       # GitHub Action definition
├── .github/workflows/security.yml
└── package.json
```

<br>

## License

MIT. See [LICENSE](LICENSE).

This tool is intended for authorized security testing only. You are solely responsible for how you use it.
