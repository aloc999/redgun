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
  <img src="https://img.shields.io/badge/modules-120-ff4444" alt="Modules">
  <img src="https://img.shields.io/badge/version-4.0.0-critical" alt="Version">
</p>

<br>

## What is RedGun?

RedGun is the most comprehensive free CLI security scanner for bug bounty hunters. ~120 modules covering the full workflow: authenticated scanning via browser engine, validation engine with confidence scoring, AI-powered attack chain discovery, interactive REPL, auto PoC generation, taint analysis, custom detectors, and exports to Burp/Zap/Caido.

**Remote scan** (black-box): Puppeteer browser engine → 60+ probes (XSS, SQLi, SSRF, XXE, OAuth, SAML, LDAP, NoSQL, gRPC, AI/LLM injection, and more).

**Local audit** (white-box): 40+ source code analyses including taint tracing (source-to-sink), mass assignment, type confusion, and supply chain attacks.

Built by [@aloc999 (Hashemi)](https://github.com/aloc999).

<br>

## Quick start

```bash
npm install -g redgun-security

redgun                                      # Interactive mode
redgun scan https://target.com              # Remote scan
redgun scan --proxy http://127.0.0.1:8080   # Burp/Zap/Caido proxy
redgun scan --auth myprofile                # Authenticated scan
redgun scan --scope targets.txt             # Multi-target
redgun scan --fuzz                          # Wordlist fuzzing
redgun scan --rate 10                       # Configurable rate limit
redgun scan --burp                          # Burp XML export
redgun scan --pdf                           # PDF report
redgun scan --webhook https://hooks.slack.com/...  # Notifications
redgun audit .                              # Local audit
redgun audit . --ci --min-score 80          # CI mode
redgun repl https://target.com              # Interactive shell
redgun poc                                  # PoC generator
redgun graph https://target.com             # D3.js asset graph
redgun detector add --name "X" --pattern "secret=%s" --severity high
redgun detector list                        # List custom detectors
redgun har https://target.com               # HAR export
redgun caido https://target.com             # Caido export
redgun watch https://target.com --interval 60  # Continuous monitoring
redgun h1-scope program.json                # Parse HackerOne scope
redgun diff scan1.json scan2.json           # Diff mode
redgun auth add --name prod --method bearer --token eyJ...
redgun auth list                            # List profiles
redgun modules                              # List all modules
```

<br>

## Remote Scan Modules (55 — Black-box)

| Module | What it tests |
|---|---|
| **Browser Engine** | Headless Chromium: DOM XSS injection, network capture, WebSocket, postMessage, localStorage, screenshot on alert |
| **Probe & Fingerprint** | Status code, title, 40+ techs, CDN/WAF, favicon hash, vhost discovery |
| **Crawl & Extract** | JS parsing, endpoint extraction, form discovery, parameter mining, email harvesting, secret detection |
| **Port Scanner** | 34 common ports with banner grabbing |
| **S3 Bucket Enumeration** | AWS S3 bucket discovery + public access detection |
| **DNS Zone Transfer** | AXFR attempt |
| **HTTP Headers** | CSP, HSTS, X-Frame-Options, X-Content-Type, Referrer-Policy, Permissions-Policy, COOP, CORP, COEP |
| **Exposed Files** | .env, .git, package.json, actuator, swagger, phpinfo, Docker, backups |
| **Secrets Detection** | AWS, Stripe, Firebase, Supabase, OpenAI, Anthropic, GitHub, Slack, Twilio, Discord |
| **XSS Reflected** | 6 payloads x 14 parameters |
| **SQL Injection** | Error-based, UNION-based, time-based blind |
| **CORS Misconfig** | Wildcard + credentials, reflected origin, null origin |
| **Open Redirect** | 12 redirect parameters |
| **SSRF** | AWS/GCP metadata, IPv4/IPv6, DNS rebinding, redirect chains, gopher/file |
| **SSRF Bypass Chains** | Decimal/hex/octal IP, DNS rebinding (nip.io/xip.io), redirect chain, double encoding |
| **Host Header Injection** | Reflected host, X-Forwarded-Host |
| **HTTP Request Smuggling** | CL.TE probe detection |
| **CRLF Injection** | Header injection via encoding variants |
| **HTTP Response Splitting** | CRLF in URL parameters |
| **GraphQL Introspection** | Schema exposure, 5 endpoint queries |
| **Clickjacking** | X-Frame-Options, frame-ancestors CSP |
| **Cookie Security** | HttpOnly, Secure, SameSite flags |
| **HTTP Methods** | TRACE, PUT, DELETE enabled |
| **Subdomain Enumeration** | 40+ common subdomains |
| **DNS & Email** | SPF, DKIM, DMARC |
| **Technology Fingerprint** | 40+ frameworks, servers, services |
| **API Discovery** | Common API paths, auth testing |
| **SSL/TLS Analysis** | HTTP vs HTTPS detection |
| **Path Traversal / LFI** | Double-encoding, unicode bypass, null byte |
| **NoSQL Injection** | MongoDB $ne operator auth bypass |
| **WebSocket Security** | Origin validation, auth checks |
| **Cache Poisoning** | Unkeyed headers, Web Cache Deception |
| **Race Conditions** | Concurrent request attack detection |
| **XXE Injection** | XML entity injection |
| **OAuth Misconfig** | redirect_uri, OIDC config, implicit flow |
| **Access Control Bypass** | Admin panel, 403 bypass via headers, robots.txt |
| **Web Cache Deception** | Static extension, path normalization |
| **Parameter Pollution** | HPP, null byte truncation |
| **File Upload Testing** | Endpoint discovery |
| **DOM-Based** | DOM sinks, postMessage, source-to-sink |
| **HTTP/2 Attacks** | H2.CL/H2.TE smuggling, HPACK |
| **SAML/SSO** | Metadata, unsigned assertion, XSW probe |
| **LDAP Injection** | Auth bypass via wildcards |
| **MFA Bypass** | Post-MFA access, OTP rate limiting |
| **Password Reset** | Email enum, Host header, token entropy |
| **CSRF Remote** | Token detection, cookie-based, SameSite |
| **Subdomain Takeover** | Dangling CNAME to AWS/Azure/Heroku/GitHub/Netlify/Vercel |
| **Cloud Metadata SSRF** | AWS/GCP/Azure IMDS |
| **JWT Advanced** | kid/JWK/jku/none/key confusion |
| **gRPC / OpenAPI** | Reflection enumeration, Swagger fuzzing |
| **Timing Side-Channel** | Login timing differences |
| **XSSI / JSON Hijacking** | JSON array inclusion, sensitive data detection |
| **Tabnabbing** | target=_blank without noopener |
| **Subresource Integrity (SRI)** | External scripts/CSS without integrity hash |
| **Open Graph Injection** | Meta tag injection via user input |
| **Cookie Tossing** | Subdomain cookie injection |
| **AI/LLM Injection** | Prompt injection, system prompt extraction |
| **CSS Injection** | Attribute selector exfil, font-face, CSS keylogger |
| **PostMessage** | Missing origin, BroadcastChannel, wildcard targetOrigin |
| **ESI Injection** | Edge-Side Includes on CDNs |
| **HTTP/3 QUIC** | 0-RTT replay, Alt-Svc |
| **HPACK Bomb** | Header table overflow |

<br>

## Local Audit Modules (40 — White-box)

| Module | What it checks |
|---|---|
| **Code Secrets** | 25+ secret patterns with line numbers and fix suggestions |
| **Environment Files** | .env in .gitignore, real secrets in .env.example |
| **Dependencies** | npm audit for CVEs, supply-chain attack detection |
| **Code Vulnerabilities** | SQLi template literals, XSS v-html/innerHTML, eval, ReDoS |
| **Auth & Middleware** | Rate limiting, CORS, CSRF, session, JWT, hardcoded passwords |
| **Headers Config** | CSP/HSTS in Nuxt, Next.js, Vercel, Netlify, Express |
| **SSRF Detection** | User URLs in fetch/axios/request/http.get/urllib |
| **SSTI Detection** | Jinja2, Twig, Nunjucks, Pug, EJS, Handlebars, Velocity, Freemarker, Thymeleaf |
| **Insecure Deserialization** | pickle, yaml.load, unserialize, Marshal, BinaryFormatter |
| **Prototype Pollution** | Object.assign, spread, deepmerge, lodash.merge, \_\_proto\_\_ |
| **JWT Vulnerabilities** | alg none, verify false, weak secrets, expiration bypass |
| **JWT Advanced** | kid injection, JWK injection, jku SSRF, x5u, key confusion |
| **Path Traversal / LFI** | readFile, sendFile, include/require with user input |
| **Command Injection** | exec, spawn, child_process, system, subprocess |
| **Weak Cryptography** | MD5, SHA1, DES, RC4, ECB, Math.random, hardcoded keys/IVs |
| **XXE Detection** | DOMParser, lxml, simplexml, LIBXML_NOENT |
| **Access Control / IDOR** | Direct object ref, role from user input, admin headers |
| **OAuth / OIDC Flaws** | redirect_uri, missing state, client_secret, implicit flow |
| **Business Logic** | Price manipulation, negative quantity, workflow skipping, referral abuse |
| **SAML / SSO** | Signature validation, XSW, NameID injection, audience restriction |
| **LDAP Injection** | Filter concatenation, auth bypass, TLS/SSL enforcement |
| **CSRF Analysis** | Token entropy, predictable sources, double submit |
| **Account Takeover** | Reset token, OTP, MFA bypass, user enumeration |
| **Cloud Misconfig** | S3 public ACL, IAM wildcards, GCP/Azure creds, Lambda |
| **CI/CD Pipeline** | pull_request_target, secrets, elevated permissions |
| **Mobile Security** | API keys, debuggable, ATS, WebView, deep links |
| **Web3 / Smart Contracts** | Reentrancy, delegatecall, tx.origin, proxy, unchecked |
| **XPath / SSI** | XPath evaluate/select, SSI directives |
| **Timing Side-Channels** | String compare, conditional sleep, HMAC oracle |
| **Client-Side Template Injection** | AngularJS, Vue v-html, React dangerouslySetInnerHTML, Svelte |
| **Service Worker / WebRTC** | importScripts, fetch listener, cache poisoning, IP leak |
| **Padding / Compression Oracle** | CBC decrypt errors, CRIME/BREACH, OAEP |
| **AI/LLM Injection** | System prompt, tool-use, RAG indirect injection |
| **CSS Injection** | Attribute selector, font-face unicode-range, CSS keylogger |
| **PostMessage** | Missing origin, BroadcastChannel, wildcard targetOrigin |
| **Electron / React Native** | contextIsolation, nodeIntegration, shell.openExternal, IPC |
| **WebAuthn / Passkeys** | Weak challenge, relay attack surface, empty allowCredentials |
| **Supply Chain** | Dependency confusion, lockfile integrity, postinstall, curl\|bash |
| **Client-Side Proto Pollution** | Gadget chains, jQuery $.extend, Angular merge, DOM sources |
| **Mass Assignment** | ORM bulk create, req.body spread, activation bypass |
| **XSSI / Tabnabbing / Type Confusion** | Script inclusion, window.opener, PHP strcmp/==, JS coercion |
| **Response Splitting / SQL Trunc** | CRLF in headers, VARCHAR truncation impersonation |
| **SRI / Open Graph Injection** | Missing integrity hashes, user-controlled meta tags |
| **Taint Analysis** | Source (req.body) → Sink (eval, exec, innerHTML) path tracing |
| **Custom Detectors** | User-defined regex patterns for any vulnerability class |

<br>

## Validation Engine

After scanning, every finding is validated to eliminate false positives:

| Vuln | Validation |
|---|---|
| SQLi | UNION SELECT probe with DB error detection |
| XSS | Payload reflection + encoding detection |
| SSRF | Metadata endpoint timing |
| JWT | alg=none forged token test |
| LFI | /etc/passwd retrieval |
| Open Redirect | Redirect chain confirmation |
| CORS | Cross-origin credential test |
| NoSQLi | $ne operator auth bypass |
| Command Injection | sleep-based timing |

Each finding: confidence score (0-100%), badge (CONFIRMED/REJECTED/INCONCLUSIVE), and findings <30% auto-eliminated.

<br>

## Attack Chain Engine

**Hardcoded chains (10):** Open Redirect→OAuth Theft→ATO, XSS→Cookie→Session Hijack, SSRF→Cloud Meta→Credential Dump, SQLi→Password→Stuffing, NoSQL→Auth→IDOR, JWT kid→LFI→Key Forge, CORS→CSRF, Subdomain→Cookie→Fixation.

**AI Chain Discovery (15 additional):** Uses heuristic matching to find novel chains like Mass Assignment→Role Elevation, Type Confusion→JWT Key Confusion, Cookie Tossing→CSRF Fixation, Tabnabbing→OAuth Theft, GraphQL→IDOR Cross-Tenant, File Upload→SVG XSS, SSRF→Internal→LFI→Source Leak, and more.

<br>

## Interactive REPL

```
redgun repl https://target.com
redgun> get /api/users
redgun> post /api/login {"email":"test@test.com"}
redgun> xss q
redgun> sqli id
redgun> findings
redgun> score
redgun> exit
```

Live shell for on-the-fly probing: raw HTTP, XSS/SQLi quick tests, findings inspection.

<br>

## Auto PoC Generator

```bash
redgun poc    # → ./scans/pocs/poc-xss-*.md
              # → ./scans/bug-bounty-report.md
```

Generates curl, Python, Burp, and sqlmap PoC scripts for all CONFIRMED findings.

<br>

## Taint Analysis + Custom Detectors

| Feature | Description |
|---|---|
| **Taint Analysis** | Traces `req.body/req.query/$_GET` → `eval()/exec()/innerHTML/.send()` data flow paths |
| **Custom Detectors** | `redgun detector add --name "API key leak" --pattern "api_key=[A-Z0-9]{20}" --severity high` |

Both run automatically during `redgun audit .`

<br>

## Exports & Integrations

| Command | Output |
|---|---|
| `redgun har` | HTTP Archive (.har) → Burp/Zap/Caido |
| `redgun caido` | Caido JSON with severity-colored findings + highlights |
| `redgun graph` | D3.js interactive asset graph (.html) |
| `redgun --burp` | Burp Suite XML findings export |
| `redgun --pdf` | PDF report |
| `redgun --webhook` | Discord/Slack notification |
| `redgun h1-scope` | Parse HackerOne program scope JSON |

<br>

## Continuous Monitor

```bash
redgun watch https://target.com --interval 60
```

Scans every N minutes. Alerts on new findings. Tracks baseline score drift.

<br>

## GitHub Action

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
      - uses: aloc999/redgun@v4
```

<br>

## Scoring

| Severity | Score impact | Meaning |
|---|---|---|
| **Critical** | -15 | Exploitable, immediate action |
| **High** | -8 | Serious risk, fix soon |
| **Medium** | -3 | Moderate risk |
| **Low** | -1 | Minor risk |
| **Info** | 0 | Informational |

<br>

## Project Structure

```
redgun/
├── bin/
│   └── redgun.js                       # CLI entry point (20+ commands)
├── src/
│   ├── core/
│   │   ├── findings.js                 # Findings store + validation fields
│   │   ├── score.js                    # A-F score calculator
│   │   ├── validator.js                # Validation engine (18 vuln types)
│   │   ├── chains.js                   # Attack chain builder (10 chains)
│   │   ├── ai-chains.js                # AI chain discovery (15+ templates)
│   │   ├── repl.js                     # Interactive REPL shell
│   │   ├── poc-generator.js            # Auto PoC scripts (curl/py/Burp/sqlmap)
│   │   ├── session.js                  # Auth session management + profiles
│   │   ├── proxy.js                    # Burp/Zap/Caido proxy routing
│   │   ├── waf-bypass.js               # Payload encoding/evasion
│   │   ├── concurrent.js              # Parallel execution (5 workers)
│   │   ├── h1-scope.js                 # HackerOne scope parser
│   │   ├── monitor.js                  # Continuous monitoring + asset graph
│   │   ├── custom-detector.js         # Custom rules + taint analysis
│   │   ├── integrations.js             # HAR export, Caido export, Shodan
│   │   ├── advanced-features.js       # Fuzzer, diff, resume, Burp, webhooks, PDF, log levels
│   │   └── reporter/
│   │       ├── console.js              # Terminal output with validation badges
│   │       ├── json.js                 # JSON + SARIF export
│   │       └── html.js                 # HTML report with confidence bars
│   ├── local/                          # White-box modules (40)
│   │   ├── index.js                    # Module orchestrator
│   │   ├── secrets.js, env.js, dependencies.js, auth.js
│   │   ├── code-vulnerabilities.js, headers-config.js
│   │   ├── ssrf.js, ssti.js, deserialization.js, prototype-pollution.js
│   │   ├── jwt.js, jwt-advanced.js
│   │   ├── path-traversal.js, command-injection.js, crypto.js
│   │   ├── xxe.js, access-control.js, oauth.js, business-logic.js
│   │   ├── saml.js, ldap.js, csrf.js, ato.js
│   │   ├── cloud.js, cicd.js, mobile.js, web3.js
│   │   ├── xpath-ssi.js, timing.js, csti.js
│   │   ├── service-worker.js, padding-oracle.js
│   │   ├── llm-ai.js, css-injection.js, postmessage.js
│   │   ├── electron.js, webauthn.js
│   │   ├── supply-chain-advanced.js, client-proto.js
│   │   └── remaining-vulns.js          # Mass assignment, type confusion, SRI, OG injection, etc.
│   ├── remote/                         # Black-box enhanced modules
│   │   ├── browser.js                  # Puppeteer: DOM XSS, network, WS, storage, screenshots
│   │   ├── crawler.js                  # Katana-style JS crawler
│   │   ├── probe.js                    # httpx-style fingerprinting
│   │   ├── portswigger.js              # XXE, OAuth, ACL, WCD, HPP, upload, DOM, H2
│   │   ├── advanced.js                 # SAML, LDAP, MFA, WS, pw reset, CSRF, takeover, cloud
│   │   ├── complete.js                 # SSRF bypass, JWT adv, gRPC, OpenAPI, WebRTC, SSI, XPath, timing
│   │   ├── modern.js                   # AI/LLM, CSS, PostMessage, ESI, HTTP/3, HPACK, SMTP
│   │   └── remaining.js                # Port scanner, S3, AXFR, response splitting, XSSI, tabnabbing, SRI, OG, cookie toss
│   └── utils/
│       ├── fetch.js                    # HTTP with configurable rate limit, proxy, auth session
│       └── patterns.js                 # 25+ secret patterns, XSS/SQLi/SSRF/SSTI regex
├── scan.js                             # Remote scan engine (55 modules)
├── action.yml                          # GitHub Action definition
├── .github/workflows/security.yml
└── package.json
```

<br>

## License

MIT. See [LICENSE](LICENSE). Built by [@aloc999 (Hashemi)](https://github.com/aloc999).

This tool is for authorized security testing only. You are responsible for how you use it.
