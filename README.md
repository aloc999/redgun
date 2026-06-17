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
  <img src="https://img.shields.io/badge/modules-100-ff4444" alt="Modules">
  <img src="https://img.shields.io/badge/version-3.0.0-critical" alt="Version">
</p>

<br>

## What is RedGun?

RedGun is a comprehensive security auditing CLI tool with ~100 modules. Covers the full bug bounty workflow: authenticated scanning, browser engine (Puppeteer), attack chain chaining, validation engine with false-positive elimination, proxy support (Burp/Zap), concurrent execution, and more. Built for actual bounty hunting, not just reporting.

**Remote scan** (black-box): Browser engine launches Chromium to capture network traffic, WebSocket, postMessage, DOM XSS. Then 60+ probes — XSS, SQLi, SSRF, XXE, OAuth, SAML, LDAP, IDOR, cache deception, HTTP smuggling, CRLF, parameter pollution, file upload, NoSQL, gRPC, AI/LLM injection, and more.

**Local audit** (white-box): Scans 33 vulnerability classes in source code — secrets, SSTI, XXE, deserialization, proto pollution, JWT (kid/JWK/none), OAuth, IDOR, business logic, SAML, LDAP, CSRF, ATO, cloud misconfigs, CI/CD, mobile, smart contracts, CSS injection, postMessage, Electron/RN, WebAuthn, supply chain, and more.

Built by [@aloc999 (Hashemi)](https://github.com/aloc999).

<br>

## Quick start

```bash
npm install -g redgun-security

redgun                                      # Interactive mode
redgun scan https://target.com              # Remote scan
redgun scan --proxy http://127.0.0.1:8080   # With Burp/Zap proxy
redgun scan --auth myprofile                # Authenticated scan
redgun scan --scope targets.txt             # Multi-target
redgun audit .                              # Local audit
redgun audit . --ci                         # CI mode
redgun diff scan1.json scan2.json           # Diff two scans
redgun auth add --name myprofile ...        # Manage auth profiles
redgun auth list                            # List profiles
redgun modules                              # List all modules
```

<br>

## Remote Scan Modules (51 — Black-box)

| Module | What it tests |
|---|---|
| **Browser Engine** | Headless Chromium: DOM XSS injection, network capture, WebSocket, postMessage, localStorage audit, screenshot on alert |
| **Probe & Fingerprint** | Status code, title, 40+ techs, CDN/WAF, favicon hash, response time, vhost discovery |
| **Crawl & Extract** | JS file parsing, endpoint extraction, form discovery, parameter mining, email harvesting, secret detection |
| **HTTP Headers** | CSP, HSTS, X-Frame-Options, X-Content-Type, Referrer-Policy, Permissions-Policy, COOP, CORP, COEP |
| **Exposed Files** | .env, .git, package.json, .DS_Store, actuator, swagger, phpinfo, Docker, backups |
| **Secrets Detection** | AWS, Stripe, Firebase, Supabase, OpenAI, Anthropic, GitHub, Slack, Twilio, Discord in page source |
| **XSS Reflected** | 6 payloads x 14 parameters, DOM-based indicators |
| **SQL Injection** | Error-based, UNION-based, time-based blind |
| **CORS Misconfig** | Wildcard + credentials, reflected origin, null origin |
| **Open Redirect** | 12 redirect parameters, external URL confirmation |
| **SSRF** | AWS/GCP metadata, IPv4/IPv6, DNS rebinding, redirect chains, gopher/file protocols |
| **SSRF Bypass Chains** | Decimal/hex/octal IP, DNS rebinding (nip.io/xip.io), redirect chain, double encoding |
| **Host Header Injection** | Reflected host, X-Forwarded-Host poisoning |
| **HTTP Request Smuggling** | CL.TE probe detection |
| **CRLF Injection** | Header injection via encoding variants |
| **GraphQL Introspection** | Schema exposure, 5 endpoint queries |
| **Clickjacking** | X-Frame-Options, frame-ancestors CSP |
| **Cookie Security** | HttpOnly, Secure, SameSite flags |
| **HTTP Methods** | TRACE, PUT, DELETE enabled |
| **Subdomain Enumeration** | 40+ common subdomains, dangerous detection |
| **DNS & Email** | SPF, DKIM, DMARC analysis |
| **Technology Fingerprint** | 40+ frameworks, servers, services |
| **API Discovery** | Common API paths, auth testing |
| **SSL/TLS Analysis** | HTTP vs HTTPS detection |
| **Path Traversal / LFI** | Double-encoding, unicode bypass, null byte |
| **NoSQL Injection** | MongoDB $ne operator auth bypass |
| **WebSocket Security** | Origin validation, auth checks |
| **Cache Poisoning** | Unkeyed headers, Web Cache Deception |
| **Race Conditions** | Concurrent request attack detection |
| **XXE Injection** | XML entity injection at upload/import/SOAP endpoints |
| **OAuth Misconfig** | redirect_uri validation, OIDC config, implicit flow |
| **Access Control Bypass** | Admin panel, 403 bypass via headers, robots.txt |
| **Web Cache Deception** | Static extension, path normalization |
| **Parameter Pollution** | HPP, null byte truncation |
| **File Upload Testing** | Endpoint discovery, OPTIONS probing |
| **DOM-Based** | DOM sinks, postMessage, source-to-sink |
| **HTTP/2 Attacks** | H2.CL/H2.TE smuggling, HPACK |
| **SAML/SSO** | Metadata exposure, unsigned assertion, XSW probe |
| **LDAP Injection** | Auth bypass via wildcard filters |
| **MFA Bypass** | Post-MFA path access, OTP rate limiting |
| **Password Reset** | Email enumeration, Host header, token entropy |
| **CSRF Remote** | Token detection, cookie-based, SameSite |
| **Subdomain Takeover** | Dangling CNAME to AWS/Azure/Heroku/GitHub/Netlify/Vercel |
| **Cloud Metadata SSRF** | AWS/GCP/Azure IMDS probing |
| **JWT Advanced** | kid/JWK/jku/none/key confusion |
| **gRPC / OpenAPI** | Reflection enumeration, Swagger schema fuzzing |
| **Timing Side-Channel** | Login timing differences |
| **AI/LLM Injection** | Prompt injection, system prompt extraction |
| **CSS Injection** | Attribute selector exfil, font-face, CSS keylogger |
| **PostMessage** | Missing origin, BroadcastChannel, wildcard targetOrigin |
| **ESI Injection** | Edge-Side Includes on CDNs |
| **HTTP/3 QUIC** | 0-RTT replay, Alt-Svc detection |
| **HPACK Bomb** | Header table overflow |

<br>

## Local Audit Modules (33 — White-box)

| Module | What it checks |
|---|---|
| **Code Secrets** | 25+ secret patterns with line numbers and fix suggestions |
| **Environment Files** | .env in .gitignore, real secrets in .env.example |
| **Dependencies** | npm audit for CVEs, supply-chain attack package detection |
| **Code Vulnerabilities** | SQLi template literals, XSS v-html/innerHTML, eval, ReDoS |
| **Auth & Middleware** | Rate limiting, CORS, CSRF, session, JWT, hardcoded passwords |
| **Headers Config** | CSP/HSTS in Nuxt, Next.js, Vercel, Netlify, Express |
| **SSRF Detection** | User URLs in fetch/axios/request/http.get/urllib |
| **SSTI Detection** | Jinja2, Twig, Nunjucks, Pug, EJS, Handlebars, Velocity, Freemarker, Thymeleaf |
| **Insecure Deserialization** | pickle, yaml.load, unserialize, ObjectInputStream, Marshal, BinaryFormatter |
| **Prototype Pollution** | Object.assign, spread, deepmerge, lodash.merge, __proto__ |
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

<br>

## Validation Engine (v2.0+)

After scanning, RedGun automatically validates every finding to eliminate false positives:

| Vuln | Validation Method |
|---|---|
| **SQLi** | UNION SELECT probe with DB error detection |
| **XSS** | Payload reflection check with HTML encoding detection |
| **SSRF** | Metadata endpoint timing analysis |
| **JWT** | Forged alg=none token authentication test |
| **LFI** | /etc/passwd retrieval verification |
| **Open Redirect** | Follow redirect chain to external URL |
| **CORS** | Cross-origin request with credential leak check |
| **NoSQLi** | $ne operator auth bypass confirmation |
| **Command Injection** | sleep-based timing confirmation |

Each finding gets: confidence score (0-100%), exploitability badge (CONFIRMED/REJECTED/INCONCLUSIVE), and validation note. Findings below 30% confidence are auto-eliminated.

<br>

## Attack Chain Engine (v2.2+)

Automatically chains validated vulnerabilities into complex exploit paths:

| Chain | Impact |
|---|---|
| Open Redirect → OAuth Theft → ATO | CRITICAL |
| XSS → Cookie Steal → Session Hijacking | CRITICAL |
| SSRF → Cloud Metadata → Credential Dump | CRITICAL |
| JWT kid → Path Traversal → Key Forge | CRITICAL |
| SQLi → Password Dump → Credential Stuffing | CRITICAL |
| NoSQLi → Auth Bypass → IDOR → Mass Extraction | CRITICAL |
| CORS → CSRF → Privilege Escalation | HIGH |
| Subdomain Takeover → Cookie Scope → Session Fixation | HIGH |

Each chain includes step-by-step exploitation instructions and confidence scoring.

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
      - uses: aloc999/redgun@v3
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

## Configuration

```bash
redgun scan                              # Interactive scan
redgun scan https://target.com           # Direct URL
redgun scan --proxy http://127.0.0.1:8080  # Burp/Zap proxy
redgun scan --auth myprofile             # Authenticated scan
redgun scan --scope targets.txt          # Multi-target
redgun scan --fuzz                       # Wordlist fuzzing
redgun scan --burp                       # Burp XML export
redgun scan --resume                     # Resume last scan
redgun scan --modules browser,headers    # Specific modules
redgun audit .                           # Local audit
redgun audit . --ci --min-score 80       # CI mode
redgun diff scan1.json scan2.json        # Diff mode
redgun auth add --name prod --method bearer --token eyJ...   # Save profile
redgun auth list                         # List profiles
redgun history                           # View reports
redgun modules                           # List modules
```

<br>

## Project Structure

```
redgun/
├── bin/
│   └── redgun.js                       # CLI entry point
├── src/
│   ├── core/
│   │   ├── findings.js                 # Findings store + validation fields
│   │   ├── score.js                    # A-F score calculator
│   │   ├── validator.js                # Validation engine (18 vuln types)
│   │   ├── chains.js                   # Attack chain builder (10 chains)
│   │   ├── session.js                  # Auth session management + profiles
│   │   ├── proxy.js                    # Burp/Zap proxy routing
│   │   ├── waf-bypass.js               # Payload encoding/evasion
│   │   ├── concurrent.js              # Parallel execution (5 workers)
│   │   ├── advanced-features.js       # Fuzzer, diff, resume, Burp export
│   │   └── reporter/
│   │       ├── console.js              # Terminal output with validation badges
│   │       ├── json.js                 # JSON + SARIF export
│   │       └── html.js                 # HTML report with confidence bars
│   ├── local/                          # White-box modules (33)
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
│   └── remote/                         # Black-box enhanced modules
│       ├── browser.js                  # Puppeteer: DOM XSS, network, WS, storage
│       ├── crawler.js                  # Katana-style JS crawler
│       ├── probe.js                    # httpx-style fingerprinting
│       ├── portswigger.js              # XXE, OAuth, ACL, WCD, HPP, upload, DOM, H2
│       ├── advanced.js                 # SAML, LDAP, MFA, WS replay, pw reset, CSRF, takeover, cloud
│       ├── complete.js                 # SSRF bypass, JWT adv, gRPC, OpenAPI, WebRTC, XSS auto, SSI, XPath, timing
│       ├── modern.js                   # AI/LLM, CSS, PostMessage, ESI, HTTP/3, HPACK, SMTP
│   └── utils/
│       ├── fetch.js                    # HTTP with rate limiter, proxy, auth session
│       └── patterns.js                 # 25+ secret patterns, XSS/SQLi/SSRF/SSTI regex
├── scan.js                             # Remote scan engine (51 modules)
├── action.yml                          # GitHub Action definition
├── .github/workflows/security.yml
└── package.json
```

<br>

## License

MIT. See [LICENSE](LICENSE). Built by [@aloc999 (Hashemi)](https://github.com/aloc999).

This tool is for authorized security testing only. You are responsible for how you use it.
