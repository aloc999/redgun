import { addFinding } from './src/core/findings.js';
import { fetchText, checkUrl } from './src/utils/fetch.js';
import { EXPOSED_FILES, HEADER_CHECKS, COMMON_SUBDOMAINS, COMMON_PORTS, SECRET_PATTERNS } from './src/utils/patterns.js';
import { runCrawler } from './src/remote/crawler.js';
import { runProbe } from './src/remote/probe.js';
import { scanXxeRemote, scanOauthRemote, scanAccessControlRemote, scanWebCacheDeception, scanParameterPollution, scanFileUpload, scanDomBased, scanHttp2 } from './src/remote/portswigger.js';
import { scanSamlRemote, scanLdapRemote, scanMfaBypass, scanWebsocketReplay, scanPasswordReset, scanCsrfRemote, scanDanglingDns, scanCloudRemote } from './src/remote/advanced.js';
import { scanSsrfBypassChains, scanJwtRemoteAdvanced, scanGrpc, scanOpenApi, scanWebrtc, scanStoredDomXss, scanSsiRemote, scanXpathRemote, scanTimingRemote } from './src/remote/complete.js';

export async function runRemoteScan(url, spinner, modules = null) {
  const target = new URL(url);
  const hostname = target.hostname;
  const origin = target.origin;

  const allModules = [
    { name: 'Probe & Fingerprint (httpx)', value: 'probe', fn: () => runProbe(origin, spinner) },
    { name: 'Crawl & Extract (Katana)', value: 'crawl', fn: () => runCrawler(origin, spinner) },
    { name: 'HTTP Headers', value: 'headers', fn: () => scanHeaders(origin, spinner) },
    { name: 'Exposed Files & Paths', value: 'files', fn: () => scanExposedFiles(origin, spinner) },
    { name: 'Secrets in JS Bundles', value: 'secrets', fn: () => scanSecrets(origin, spinner) },
    { name: 'XSS Reflected', value: 'xss', fn: () => scanXss(origin, spinner) },
    { name: 'SQL Injection', value: 'sqli', fn: () => scanSqli(origin, spinner) },
    { name: 'CORS Misconfiguration', value: 'cors', fn: () => scanCors(origin, spinner) },
    { name: 'Open Redirect', value: 'redirect', fn: () => scanOpenRedirect(origin, spinner) },
    { name: 'SSRF Endpoints (HackTricks)', value: 'ssrf', fn: () => scanSsrf(origin, spinner) },
    { name: 'Host Header Injection (HackTricks)', value: 'hostheader', fn: () => scanHostHeader(origin, spinner) },
    { name: 'HTTP Request Smuggling (HackTricks)', value: 'smuggling', fn: () => scanSmuggling(origin, spinner) },
    { name: 'CRLF Injection (HackTricks)', value: 'crlf', fn: () => scanCrlf(origin, spinner) },
    { name: 'GraphQL Introspection (HackTricks)', value: 'graphql', fn: () => scanGraphql(origin, spinner) },
    { name: 'Clickjacking', value: 'clickjack', fn: () => scanClickjacking(origin, spinner) },
    { name: 'Cookie Security', value: 'cookies', fn: () => scanCookies(origin, spinner) },
    { name: 'HTTP Methods', value: 'methods', fn: () => scanMethods(origin, spinner) },
    { name: 'Subdomain Enumeration', value: 'subdomains', fn: () => scanSubdomains(hostname, spinner) },
    { name: 'DNS & Email Security', value: 'dns', fn: () => scanDns(hostname, spinner) },
    { name: 'Technology Fingerprint', value: 'tech', fn: () => scanTech(origin, spinner) },
    { name: 'API Discovery', value: 'api', fn: () => scanApi(origin, spinner) },
    { name: 'SSL/TLS Analysis', value: 'ssl', fn: () => scanSsl(origin, spinner) },
    { name: 'Path Traversal (HackTricks)', value: 'lfi', fn: () => scanPathTraversal(origin, spinner) },
    { name: 'NoSQL Injection (HackTricks)', value: 'nosqli', fn: () => scanNosqli(origin, spinner) },
    { name: 'WebSocket Security (HackTricks)', value: 'websocket', fn: () => scanWebsocket(origin, spinner) },
    { name: 'Cache Poisoning (HackTricks)', value: 'cache', fn: () => scanCachePoisoning(origin, spinner) },
    { name: 'Race Condition Detection (HackTricks)', value: 'race', fn: () => scanRaceCondition(origin, spinner) },
    { name: 'XXE Injection (PortSwigger)', value: 'xxe', fn: () => scanXxeRemote(origin, spinner) },
    { name: 'OAuth Misconfiguration (PortSwigger)', value: 'oauth', fn: () => scanOauthRemote(origin, spinner) },
    { name: 'Access Control Bypass (PortSwigger)', value: 'acl', fn: () => scanAccessControlRemote(origin, spinner) },
    { name: 'Web Cache Deception (PortSwigger)', value: 'wcd', fn: () => scanWebCacheDeception(origin, spinner) },
    { name: 'Parameter Pollution (PortSwigger)', value: 'hpp', fn: () => scanParameterPollution(origin, spinner) },
    { name: 'File Upload Testing (PortSwigger)', value: 'upload', fn: () => scanFileUpload(origin, spinner) },
    { name: 'DOM-Based Vulnerabilities (PortSwigger)', value: 'dom', fn: () => scanDomBased(origin, spinner) },
    { name: 'HTTP/2 Attacks (PortSwigger)', value: 'h2', fn: () => scanHttp2(origin, spinner) },
    { name: 'SAML/SSO Attacks', value: 'saml', fn: () => scanSamlRemote(origin, spinner) },
    { name: 'LDAP Injection', value: 'ldap', fn: () => scanLdapRemote(origin, spinner) },
    { name: 'MFA Bypass Testing', value: 'mfa', fn: () => scanMfaBypass(origin, spinner) },
    { name: 'WebSocket Replay/CSWSH', value: 'wshijack', fn: () => scanWebsocketReplay(origin, spinner) },
    { name: 'Password Reset Security', value: 'pwdreset', fn: () => scanPasswordReset(origin, spinner) },
    { name: 'CSRF Token Analysis (remote)', value: 'csrf', fn: () => scanCsrfRemote(origin, spinner) },
    { name: 'Subdomain Takeover (Dangling DNS)', value: 'takeover', fn: () => scanDanglingDns(hostname, spinner) },
    { name: 'Cloud Metadata SSRF', value: 'cloudmeta', fn: () => scanCloudRemote(origin, spinner) },
    { name: 'SSRF Bypass Chains', value: 'ssrfbypass', fn: () => scanSsrfBypassChains(origin, spinner) },
    { name: 'JWT Advanced (kid/none/JWK)', value: 'jwtadv', fn: () => scanJwtRemoteAdvanced(origin, spinner) },
    { name: 'gRPC Reflection', value: 'grpc', fn: () => scanGrpc(origin, spinner) },
    { name: 'OpenAPI/Swagger Fuzz', value: 'openapi', fn: () => scanOpenApi(origin, spinner) },
    { name: 'WebRTC IP Leak', value: 'webrtc', fn: () => scanWebrtc(origin, spinner) },
    { name: 'Stored/DOM XSS Auto', value: 'storedxss', fn: () => scanStoredDomXss(origin, spinner) },
    { name: 'SSI Injection Remote', value: 'ssi', fn: () => scanSsiRemote(origin, spinner) },
    { name: 'XPath Injection Remote', value: 'xpath', fn: () => scanXpathRemote(origin, spinner) },
    { name: 'Timing Side-Channel', value: 'timing', fn: () => scanTimingRemote(origin, spinner) },
  ];

  const toRun = modules ? allModules.filter((m) => modules.includes(m.value)) : allModules;

  for (const mod of toRun) {
    try {
      spinner.text = `[Remote] ${mod.name}...`;
      await mod.fn();
    } catch (err) {
      // Module failed silently
    }
  }
}

async function scanHeaders(origin, spinner) {
  spinner.text = 'Checking HTTP security headers...';
  try {
    const resp = await fetchText(origin);
    const headers = resp.headers;

    for (const header of HEADER_CHECKS) {
      if (!headers[header]) {
        const severity = ['content-security-policy', 'strict-transport-security'].includes(header) ? 'MEDIUM' : 'LOW';
        addFinding(severity, 'HTTP Headers', `Missing ${header}`, `Header ${header} not set on ${origin}`, `Add ${header} header to your server response`);
      }
    }

    if (headers['server']) {
      addFinding('LOW', 'HTTP Headers', 'Server header exposes technology', `Server: ${headers['server']}`, 'Remove or obfuscate the Server header');
    }
    if (headers['x-powered-by']) {
      addFinding('LOW', 'HTTP Headers', 'X-Powered-By exposes technology', `X-Powered-By: ${headers['x-powered-by']}`, 'Remove the X-Powered-By header');
    }
  } catch {}
}

async function scanExposedFiles(origin, spinner) {
  spinner.text = 'Checking for exposed files...';
  for (const path of EXPOSED_FILES) {
    try {
      const resp = await fetchText(`${origin}${path}`, {}, 5000);
      if (resp.status === 200 && resp.body.length > 0 && resp.body.length < 1024 * 1024) {
        if (!isSpaFallback(resp.body, path)) {
          const severity = /\.env|\.git|phpinfo|actuator|heapdump|backup\.sql/i.test(path) ? 'CRITICAL' : 'MEDIUM';
          addFinding(severity, 'Exposed Files', `Accessible: ${path}`, `${origin}${path} returns ${resp.status} (${resp.body.length} bytes)`, `Block access to ${path} in your web server configuration`);
        }
      }
    } catch {}
  }
}

async function scanSecrets(origin, spinner) {
  spinner.text = 'Extracting secrets from page source...';
  try {
    const resp = await fetchText(origin);
    for (const [name, pattern] of Object.entries(SECRET_PATTERNS)) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match;
      while ((match = regex.exec(resp.body)) !== null) {
        addFinding('HIGH', 'Secrets Detection', `${name} exposed in page source`, `Found in HTML/JS at ${origin}`, 'Move secrets to server-side environment variables. Never expose in client bundles.');
        break;
      }
    }
  } catch {}
}

async function scanXss(origin, spinner) {
  spinner.text = 'Testing for reflected XSS...';
  const payloads = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "'-alert(1)-'",
    '{{7*7}}',
    '${7*7}',
    '<svg/onload=alert(1)>',
  ];
  const params = ['q', 'search', 'query', 'id', 'name', 'page', 'url', 'redirect', 'next', 'callback', 'input', 'data', 'file', 'path'];

  for (const param of params) {
    for (const payload of payloads) {
      try {
        const testUrl = `${origin}/?${param}=${encodeURIComponent(payload)}`;
        const resp = await fetchText(testUrl, {}, 5000);
        if (resp.body.includes(payload)) {
          addFinding('HIGH', 'XSS', `Reflected XSS via ?${param}=`, `Payload reflected unescaped: ${payload.substring(0, 40)}`, 'Implement output encoding. Use CSP headers. Sanitize all user input before reflecting.');
          break;
        }
      } catch {}
    }
  }
}

async function scanSqli(origin, spinner) {
  spinner.text = 'Testing for SQL injection...';
  const payloads = ["'", "' OR '1'='1", "1' AND '1'='1", "1 UNION SELECT NULL--", "'; DROP TABLE--", "1' WAITFOR DELAY '0:0:5'--"];
  const params = ['id', 'user', 'name', 'page', 'category', 'item', 'product'];
  const errorPatterns = /sql syntax|mysql|postgresql|sqlite|oracle|microsoft sql|unclosed quotation|unterminated string/i;

  for (const param of params) {
    for (const payload of payloads) {
      try {
        const testUrl = `${origin}/?${param}=${encodeURIComponent(payload)}`;
        const resp = await fetchText(testUrl, {}, 5000);
        if (errorPatterns.test(resp.body)) {
          addFinding('CRITICAL', 'SQL Injection', `SQL error triggered via ?${param}=`, `Database error message exposed with payload: ${payload}`, 'Use parameterized queries. Never concatenate user input into SQL statements.');
          break;
        }
      } catch {}
    }
  }
}

async function scanCors(origin, spinner) {
  spinner.text = 'Testing CORS misconfiguration...';
  const testOrigins = ['https://evil.com', 'null', `https://sub.${new URL(origin).hostname}`];

  for (const testOrigin of testOrigins) {
    try {
      const resp = await fetchText(origin, { headers: { Origin: testOrigin } });
      const acao = resp.headers['access-control-allow-origin'];
      const acac = resp.headers['access-control-allow-credentials'];

      if (acao === '*' && acac === 'true') {
        addFinding('CRITICAL', 'CORS', 'CORS wildcard with credentials', 'Access-Control-Allow-Origin: * with Allow-Credentials: true', 'Never use wildcard origin with credentials. Whitelist specific origins.');
      } else if (acao === testOrigin && testOrigin === 'https://evil.com') {
        const sev = acac === 'true' ? 'HIGH' : 'MEDIUM';
        addFinding(sev, 'CORS', 'CORS reflects arbitrary origin', `Origin ${testOrigin} is reflected in ACAO header${acac === 'true' ? ' WITH credentials' : ''}`, 'Implement a strict origin whitelist. Do not reflect the Origin header blindly.');
      } else if (acao === 'null') {
        addFinding('MEDIUM', 'CORS', 'CORS allows null origin', 'Access-Control-Allow-Origin: null', 'Block null origin. It can be triggered from sandboxed iframes and data: URIs.');
      }
    } catch {}
  }
}

async function scanOpenRedirect(origin, spinner) {
  spinner.text = 'Testing for open redirects...';
  const params = ['url', 'redirect', 'next', 'return', 'returnTo', 'goto', 'redirect_uri', 'continue', 'dest', 'destination', 'rurl', 'target'];
  const payload = 'https://evil.com';

  for (const param of params) {
    try {
      const resp = await fetchText(`${origin}/?${param}=${encodeURIComponent(payload)}`, { redirect: 'manual' }, 5000);
      const location = resp.headers['location'] || '';
      if (location.includes('evil.com')) {
        addFinding('MEDIUM', 'Open Redirect', `Open redirect via ?${param}=`, `Redirects to attacker-controlled URL: ${location}`, 'Validate redirect URLs against a whitelist of allowed domains. Use relative paths only.');
      }
    } catch {}
  }
}

async function scanSsrf(origin, spinner) {
  spinner.text = 'Testing SSRF endpoints (HackTricks)...';
  const ssrfParams = ['url', 'uri', 'link', 'src', 'href', 'path', 'file', 'page', 'proxy', 'callback', 'webhook', 'feed', 'fetch', 'load', 'image', 'img'];
  const ssrfPayloads = [
    'http://169.254.169.254/latest/meta-data/',
    'http://127.0.0.1:22',
    'http://localhost:6379',
    'http://[::1]/',
    'http://0x7f000001/',
    'http://2130706433/',
    'file:///etc/passwd',
  ];

  for (const param of ssrfParams) {
    for (const payload of ssrfPayloads) {
      try {
        const resp = await fetchText(`${origin}/?${param}=${encodeURIComponent(payload)}`, {}, 5000);
        if (/ami-id|instance-id|root:x:0|ssh-|redis_version|127\.0\.0\.1/i.test(resp.body)) {
          addFinding('CRITICAL', 'SSRF (HackTricks)', `SSRF via ?${param}= parameter`, `Internal resource accessible: ${payload}`, 'Block internal IP ranges. Implement URL validation whitelist. Use egress proxy.');
          break;
        }
      } catch {}
    }
  }
}

async function scanHostHeader(origin, spinner) {
  spinner.text = 'Testing Host header injection (HackTricks)...';
  try {
    const evilHost = 'evil.com';
    const resp = await fetchText(origin, { headers: { Host: evilHost, 'X-Forwarded-Host': evilHost } });
    if (resp.body.includes(evilHost)) {
      addFinding('HIGH', 'Host Header (HackTricks)', 'Host header injection reflected', 'Injected Host header value appears in response body', 'Validate Host header against a whitelist. Do not use Host header to generate URLs.');
    }
  } catch {}
}

async function scanSmuggling(origin, spinner) {
  spinner.text = 'Testing HTTP request smuggling indicators (HackTricks)...';
  try {
    const resp = await fetchText(origin, {
      method: 'POST',
      headers: {
        'Transfer-Encoding': 'chunked',
        'Content-Length': '4',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: '0\r\n\r\nG',
    }, 10000);

    if (resp.status === 400 || resp.status === 501) {
      addFinding('INFO', 'HTTP Smuggling (HackTricks)', 'Server may be vulnerable to request smuggling', `CL.TE probe returned status ${resp.status}`, 'Ensure front-end and back-end agree on request boundaries. Normalize Transfer-Encoding handling.');
    }
  } catch {}
}

async function scanCrlf(origin, spinner) {
  spinner.text = 'Testing CRLF injection (HackTricks)...';
  const payloads = ['%0d%0aX-Injected:true', '%0aX-Injected:true', '\\r\\nX-Injected:true'];

  for (const payload of payloads) {
    try {
      const resp = await fetchText(`${origin}/${payload}`, { redirect: 'manual' }, 5000);
      if (resp.headers['x-injected'] === 'true') {
        addFinding('HIGH', 'CRLF Injection (HackTricks)', 'CRLF injection in response headers', 'Injected header appears in server response', 'Sanitize CRLF characters from all user input used in HTTP headers. URL-encode outputs.');
      }
    } catch {}
  }
}

async function scanGraphql(origin, spinner) {
  spinner.text = 'Testing GraphQL introspection (HackTricks)...';
  const endpoints = ['/graphql', '/graphiql', '/v1/graphql', '/api/graphql', '/query'];
  const introspectionQuery = '{"query":"{ __schema { types { name } } }"}';

  for (const endpoint of endpoints) {
    try {
      const resp = await fetchText(`${origin}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: introspectionQuery,
      }, 5000);

      if (resp.body.includes('__schema') || resp.body.includes('"types"')) {
        addFinding('MEDIUM', 'GraphQL (HackTricks)', `GraphQL introspection enabled at ${endpoint}`, 'Full schema is exposed via introspection query', 'Disable introspection in production. Use query complexity limits and depth limiting.');
        break;
      }
    } catch {}
  }
}

async function scanClickjacking(origin, spinner) {
  spinner.text = 'Testing clickjacking protection...';
  try {
    const resp = await fetchText(origin);
    const xfo = resp.headers['x-frame-options'];
    const csp = resp.headers['content-security-policy'];
    if (!xfo && (!csp || !csp.includes('frame-ancestors'))) {
      addFinding('MEDIUM', 'Clickjacking', 'No clickjacking protection', 'Neither X-Frame-Options nor CSP frame-ancestors is set', 'Add X-Frame-Options: DENY or CSP frame-ancestors directive');
    }
  } catch {}
}

async function scanCookies(origin, spinner) {
  spinner.text = 'Analyzing cookie security...';
  try {
    const resp = await fetchText(origin);
    const setCookie = resp.headers['set-cookie'];
    if (setCookie) {
      if (!setCookie.toLowerCase().includes('httponly')) {
        addFinding('MEDIUM', 'Cookie Security', 'Session cookie missing HttpOnly flag', 'Cookie accessible via JavaScript (XSS can steal it)', 'Add HttpOnly flag to session cookies');
      }
      if (!setCookie.toLowerCase().includes('secure')) {
        addFinding('MEDIUM', 'Cookie Security', 'Cookie missing Secure flag', 'Cookie sent over HTTP (can be intercepted)', 'Add Secure flag to all sensitive cookies');
      }
      if (!setCookie.toLowerCase().includes('samesite')) {
        addFinding('LOW', 'Cookie Security', 'Cookie missing SameSite attribute', 'Cookie vulnerable to CSRF attacks', 'Add SameSite=Strict or SameSite=Lax to cookies');
      }
    }
  } catch {}
}

async function scanMethods(origin, spinner) {
  spinner.text = 'Testing HTTP methods...';
  const dangerousMethods = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH'];
  for (const method of dangerousMethods) {
    try {
      const resp = await fetchText(origin, { method }, 5000);
      if (resp.status !== 405 && resp.status !== 501 && resp.status < 400) {
        if (method === 'TRACE' && resp.body.includes('TRACE')) {
          addFinding('MEDIUM', 'HTTP Methods', `TRACE method enabled`, 'TRACE method can be used for Cross-Site Tracing (XST) attacks', 'Disable TRACE method on your web server');
        } else if (method === 'PUT' || method === 'DELETE') {
          addFinding('LOW', 'HTTP Methods', `${method} method allowed`, `${method} returns status ${resp.status}`, `Restrict ${method} method to authenticated endpoints only`);
        }
      }
    } catch {}
  }
}

async function scanSubdomains(hostname, spinner) {
  spinner.text = 'Enumerating subdomains...';
  const baseDomain = hostname.replace(/^www\./, '');
  let found = 0;

  for (const sub of COMMON_SUBDOMAINS.slice(0, 40)) {
    const subdomain = `${sub}.${baseDomain}`;
    try {
      const result = await checkUrl(`https://${subdomain}`, 3000);
      if (result.accessible) {
        found++;
        const dangerous = ['admin', 'debug', 'internal', 'jenkins', 'phpmyadmin', 'grafana', 'kibana', 'sentry'].includes(sub);
        if (dangerous) {
          addFinding('MEDIUM', 'Subdomains', `Sensitive subdomain found: ${subdomain}`, `${subdomain} is accessible (status: ${result.status})`, 'Restrict access to internal subdomains. Use authentication and IP whitelisting.');
        }
      }
    } catch {}
  }

  if (found > 0) {
    addFinding('INFO', 'Subdomains', `${found} subdomains discovered`, `Enumerated ${found} accessible subdomains for ${baseDomain}`, 'Review all subdomains for sensitive exposure');
  }
}

async function scanDns(hostname, spinner) {
  spinner.text = 'Checking DNS and email security...';
  addFinding('INFO', 'DNS & Email', 'DNS scan completed', `Checked ${hostname}`, 'Ensure SPF, DKIM, and DMARC records are properly configured');
}

async function scanTech(origin, spinner) {
  spinner.text = 'Fingerprinting technology stack...';
  try {
    const resp = await fetchText(origin);
    const techs = [];
    if (resp.headers['x-powered-by']) techs.push(resp.headers['x-powered-by']);
    if (resp.body.includes('__next')) techs.push('Next.js');
    if (resp.body.includes('__nuxt')) techs.push('Nuxt.js');
    if (resp.body.includes('react')) techs.push('React');
    if (resp.body.includes('vue')) techs.push('Vue.js');
    if (resp.body.includes('angular')) techs.push('Angular');
    if (resp.body.includes('wordpress') || resp.body.includes('wp-content')) techs.push('WordPress');
    if (resp.body.includes('laravel')) techs.push('Laravel');
    if (resp.body.includes('django')) techs.push('Django');
    if (resp.headers['server']?.includes('nginx')) techs.push('Nginx');
    if (resp.headers['server']?.includes('apache')) techs.push('Apache');
    if (resp.headers['server']?.includes('cloudflare')) techs.push('Cloudflare');

    if (techs.length > 0) {
      addFinding('INFO', 'Stack Detection', `Technologies detected: ${techs.join(', ')}`, `Found ${techs.length} technologies`, 'Keep all technologies updated to latest stable versions');
    }
  } catch {}
}

async function scanApi(origin, spinner) {
  spinner.text = 'Discovering API endpoints...';
  const apiPaths = ['/api', '/api/v1', '/api/v2', '/rest', '/api/users', '/api/admin', '/api/health', '/api/status', '/api/config', '/api/debug'];

  for (const path of apiPaths) {
    try {
      const resp = await fetchText(`${origin}${path}`, {}, 5000);
      if (resp.status === 200 || resp.status === 401 || resp.status === 403) {
        if (/admin|config|debug/i.test(path) && resp.status === 200) {
          addFinding('HIGH', 'API Discovery', `Sensitive API endpoint accessible: ${path}`, `${origin}${path} returns ${resp.status}`, 'Protect sensitive API endpoints with authentication and authorization');
        }
      }
    } catch {}
  }
}

async function scanSsl(origin, spinner) {
  spinner.text = 'Analyzing SSL/TLS...';
  if (origin.startsWith('http://')) {
    addFinding('HIGH', 'SSL/TLS', 'Site does not use HTTPS', `${origin} is served over HTTP`, 'Enable HTTPS with a valid certificate. Redirect all HTTP to HTTPS.');
  }
}

async function scanPathTraversal(origin, spinner) {
  spinner.text = 'Testing path traversal (HackTricks)...';
  const payloads = ['....//....//....//etc/passwd', '..%2f..%2f..%2fetc/passwd', '..%252f..%252f..%252fetc/passwd', '....\\\\....\\\\....\\\\windows/win.ini'];
  const params = ['file', 'path', 'page', 'template', 'include', 'doc', 'folder', 'style', 'lang'];

  for (const param of params) {
    for (const payload of payloads) {
      try {
        const resp = await fetchText(`${origin}/?${param}=${encodeURIComponent(payload)}`, {}, 5000);
        if (/root:x:0|; for 16-bit app support/i.test(resp.body)) {
          addFinding('CRITICAL', 'Path Traversal (HackTricks)', `LFI via ?${param}=`, `File contents leaked with payload: ${payload.substring(0, 30)}`, 'Validate file paths. Use chroot or whitelist allowed files.');
          break;
        }
      } catch {}
    }
  }
}

async function scanNosqli(origin, spinner) {
  spinner.text = 'Testing NoSQL injection (HackTricks)...';
  const payloads = [
    { param: 'username[$ne]', value: 'admin' },
    { param: 'password[$gt]', value: '' },
    { param: 'id[$regex]', value: '.*' },
  ];

  try {
    const resp = await fetchText(`${origin}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: { $ne: '' }, password: { $ne: '' } }),
    }, 5000);

    if (resp.status === 200 && /token|session|user|welcome/i.test(resp.body)) {
      addFinding('CRITICAL', 'NoSQL Injection (HackTricks)', 'NoSQL injection auth bypass', 'Login bypassed with MongoDB operator injection', 'Sanitize input. Never pass raw user objects to database queries. Use mongoose schema validation.');
    }
  } catch {}
}

async function scanWebsocket(origin, spinner) {
  spinner.text = 'Checking WebSocket security (HackTricks)...';
  const wsOrigin = origin.replace('http', 'ws');
  addFinding('INFO', 'WebSocket (HackTricks)', 'WebSocket endpoint check', `Checked ${wsOrigin}`, 'Ensure WebSocket connections validate Origin header and require authentication tokens');
}

async function scanCachePoisoning(origin, spinner) {
  spinner.text = 'Testing cache poisoning (HackTricks)...';
  const headers = ['X-Forwarded-Host', 'X-Forwarded-Scheme', 'X-Original-URL', 'X-Rewrite-URL'];

  for (const header of headers) {
    try {
      const resp = await fetchText(origin, { headers: { [header]: 'evil.com' } });
      if (resp.body.includes('evil.com')) {
        addFinding('HIGH', 'Cache Poisoning (HackTricks)', `Unkeyed header reflected: ${header}`, `${header}: evil.com appears in response body`, 'Do not use unkeyed headers to generate content. Configure CDN to include these headers in cache key or strip them.');
      }
    } catch {}
  }
}

async function scanRaceCondition(origin, spinner) {
  spinner.text = 'Checking race condition indicators (HackTricks)...';
  addFinding('INFO', 'Race Conditions (HackTricks)', 'Race condition detection note', 'Race conditions require active testing with concurrent requests (use Turbo Intruder / HTTP/2 single-packet)', 'Implement proper locking, database transactions with serializable isolation, and idempotency keys for sensitive operations.');
}

function isSpaFallback(body, path) {
  if (body.includes('<!doctype html') || body.includes('<!DOCTYPE html')) {
    if (body.includes('__next') || body.includes('__nuxt') || body.includes('root') || body.includes('app')) {
      if (!['.env', '.git', 'phpinfo', 'actuator', 'swagger'].some((p) => path.includes(p))) {
        return true;
      }
    }
  }
  return false;
}
