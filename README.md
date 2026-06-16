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
  <strong>Black-box & white-box security auditor for web applications — HackTricks Enhanced.</strong>
</p>

<p align="center">
  <a href="https://github.com/aloc999/redgun/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="License"></a>
  <img src="https://img.shields.io/badge/node-%3E%3D18-green" alt="Node">
  <img src="https://img.shields.io/badge/modules-39-ff4444" alt="Modules">
  <img src="https://img.shields.io/badge/HackTricks-Enhanced-critical" alt="HackTricks">
</p>

<br>

## What is RedGun?

RedGun is a security auditing CLI tool that finds vulnerabilities in your web applications. It includes **39 security modules** covering techniques from [HackTricks](https://book.hacktricks.wiki). Two modes:

**Remote scan** (black-box): Give it a URL. It tests your site from the outside — XSS, SQLi, SSRF, CORS, CRLF injection, cache poisoning, host header injection, HTTP request smuggling, GraphQL introspection, path traversal, NoSQL injection, and more.

**Local audit** (white-box): Point it at your project directory. It reads your source code checking for secrets, SSTI, insecure deserialization, prototype pollution, JWT vulnerabilities, command injection, weak crypto, path traversal, and more.

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

## Remote Scan Modules (25 — Black-box)

| Module | What it tests | Source |
|---|---|---|
| **HTTP Headers** | Missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, CORP, COEP | OWASP |
| **Exposed Files** | `.env`, `.git/config`, `package.json`, `.DS_Store`, source maps, actuator, swagger, phpinfo, Docker files, backups | HackTricks |
| **Secrets Detection** | API keys (AWS, Stripe, Firebase, Supabase, OpenAI, Anthropic), tokens, passwords in page source | HackTricks |
| **XSS Reflected** | 6 payloads × 14 parameters, DOM-based indicators | HackTricks |
| **SQL Injection** | Error-based, UNION-based, time-based blind across common parameters | HackTricks |
| **CORS Misconfiguration** | Wildcard + credentials, reflected origin, null origin | HackTricks |
| **Open Redirect** | 12 redirect parameters tested with external URL | HackTricks |
| **SSRF** | AWS metadata, internal IPs, localhost, IPv6, decimal IP, file:// protocol | HackTricks |
| **Host Header Injection** | Reflected host, X-Forwarded-Host poisoning | HackTricks |
| **HTTP Request Smuggling** | CL.TE probe detection | HackTricks |
| **CRLF Injection** | Header injection via URL encoding variants | HackTricks |
| **GraphQL Introspection** | Schema exposure via introspection query at 5 endpoints | HackTricks |
| **Clickjacking** | Missing X-Frame-Options and frame-ancestors CSP | OWASP |
| **Cookie Security** | Missing HttpOnly, Secure, SameSite flags | OWASP |
| **HTTP Methods** | TRACE, PUT, DELETE enabled | HackTricks |
| **Subdomain Enumeration** | 40+ common subdomains, dangerous subdomain detection | HackTricks |
| **DNS & Email** | SPF, DKIM, DMARC analysis | HackTricks |
| **Technology Fingerprint** | 40+ frameworks, servers, and services detected | — |
| **API Discovery** | Common API paths, auth testing | HackTricks |
| **SSL/TLS Analysis** | HTTP vs HTTPS detection | OWASP |
| **Path Traversal / LFI** | Double-encoding, unicode bypass, null byte | HackTricks |
| **NoSQL Injection** | MongoDB operator injection auth bypass | HackTricks |
| **WebSocket Security** | Origin validation, authentication checks | HackTricks |
| **Cache Poisoning** | Unkeyed headers (X-Forwarded-Host, X-Forwarded-Scheme, X-Original-URL) | HackTricks |
| **Race Conditions** | Detection guidance for concurrent request attacks | HackTricks |

<br>

## Local Audit Modules (14 — White-box)

| Module | What it checks | Source |
|---|---|---|
| **Code Secrets** | 25+ secret patterns (AWS, GitHub, Stripe, OpenAI, Anthropic, Discord, Telegram, npm, etc.) with line numbers | HackTricks |
| **Environment Files** | `.env` in `.gitignore`, real secrets in `.env.example`, sensitive config exposure | OWASP |
| **Dependencies** | `npm audit` for CVEs, supply-chain attack package detection | OWASP |
| **Code Vulnerabilities** | SQL injection (template literals), XSS (`v-html`, `dangerouslySetInnerHTML`, `innerHTML`), eval(), ReDoS | HackTricks |
| **Auth & Middleware** | Rate limiting, CORS wildcards, CSRF protection, session config, JWT expiration, hardcoded passwords | HackTricks |
| **Headers Config** | CSP/HSTS in Nuxt, Next.js, Vercel, Netlify, Express configs | OWASP |
| **SSRF Detection** | User-controlled URLs in fetch/axios/request/http.get/urllib | HackTricks |
| **SSTI Detection** | Jinja2, Twig, Nunjucks, Pug, EJS, Handlebars, Velocity, Freemarker, Thymeleaf | HackTricks |
| **Insecure Deserialization** | pickle, yaml.load, unserialize, ObjectInputStream, Marshal, BinaryFormatter | HackTricks |
| **Prototype Pollution** | Object.assign, spread operator, deepmerge, lodash.merge, __proto__ access | HackTricks |
| **JWT Vulnerabilities** | Algorithm "none", verify disabled, weak secrets, expiration bypass, decode without verify | HackTricks |
| **Path Traversal / LFI** | User input in file paths, readFile, sendFile, include/require | HackTricks |
| **Command Injection** | exec, spawn, child_process, system, subprocess with user input, shell interpolation | HackTricks |
| **Weak Cryptography** | MD5, SHA1, DES, RC4, ECB mode, Math.random, hardcoded keys/IVs | HackTricks |

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
|---|---|---|
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
|---|---|---|
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

## HackTricks Techniques Included

RedGun integrates techniques documented in [HackTricks](https://book.hacktricks.wiki):

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
│   ├── local/                       # White-box modules (14)
│   │   ├── index.js                 # Module orchestrator
│   │   ├── secrets.js               # Source code secrets
│   │   ├── env.js                   # .env audit
│   │   ├── dependencies.js          # npm audit + supply chain
│   │   ├── code-vulnerabilities.js  # SQLi, XSS, eval, ReDoS
│   │   ├── auth.js                  # Auth & middleware
│   │   ├── headers-config.js        # CSP/HSTS config
│   │   ├── ssrf.js                  # SSRF detection
│   │   ├── ssti.js                  # SSTI detection
│   │   ├── deserialization.js       # Insecure deserialization
│   │   ├── prototype-pollution.js   # Prototype pollution
│   │   ├── jwt.js                   # JWT vulnerabilities
│   │   ├── path-traversal.js        # LFI/path traversal
│   │   ├── command-injection.js     # OS command injection
│   │   └── crypto.js               # Weak cryptography
│   └── utils/
│       ├── fetch.js                 # HTTP with timeout
│       └── patterns.js              # Shared regex patterns
├── scan.js                          # Remote scan engine (25 modules)
├── action.yml                       # GitHub Action definition
├── .github/workflows/security.yml
└── package.json
```

<br>

## License

MIT. See [LICENSE](LICENSE).

This tool is intended for authorized security testing only. You are solely responsible for how you use it.
