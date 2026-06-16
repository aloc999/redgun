import { addFinding } from '../core/findings.js';
import { fetchText, fetchWithTimeout } from '../utils/fetch.js';

export async function scanSamlRemote(origin, spinner) {
  spinner.text = 'Testing SAML/SSO endpoints...';
  const samlPaths = ['/saml', '/auth/saml', '/sso', '/auth/sso', '/Shibboleth.sso', '/adfs/ls', '/saml/SSO', '/saml2', '/websso/SAML2/Metadata'];

  for (const path of samlPaths) {
    try {
      const resp = await fetchText(`${origin}${path}`, {}, 5000);
      if (resp.status === 200 || resp.status === 302) {
        if (path.includes('Metadata') && resp.status === 200) {
          addFinding('MEDIUM', 'SAML/SSO', `SAML metadata exposed: ${path}`, `${origin}${path} returns SAML metadata XML`, 'Review metadata for certificate info and supported bindings. Ensure entity IDs are correct.');
        } else {
          addFinding('INFO', 'SAML/SSO', `SAML endpoint found: ${path}`, `Status: ${resp.status}`, 'Test for XML Signature Wrapping (XSW1-XSW8), signature stripping, and comment injection in NameID.');
        }
      }
    } catch {}
  }

  try {
    const xswPayload = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="test" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
      <saml:Issuer>evil-idp</saml:Issuer>
      <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
      <saml:Assertion ID="evil-assertion" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
        <saml:Issuer>evil-idp</saml:Issuer>
        <saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">admin@target.com</saml:NameID></saml:Subject>
        <saml:Conditions NotBefore="2024-01-01T00:00:00Z" NotOnOrAfter="2030-01-01T00:00:00Z"/>
        <saml:AuthnStatement AuthnInstant="2024-01-01T00:00:00Z">
          <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
        </saml:AuthnStatement>
      </saml:Assertion>
    </samlp:Response>`;

    const encodedXsw = Buffer.from(xswPayload).toString('base64');
    const samlConsumes = ['/saml/acs', '/auth/saml/callback', '/sso/acs', '/Shibboleth.sso/SAML2/POST'];

    for (const consumer of samlConsumes) {
      try {
        const resp = await fetchText(`${origin}${consumer}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: `SAMLResponse=${encodeURIComponent(encodedXsw)}`,
        }, 5000);

        if (resp.status === 200 || resp.status === 302) {
          if (!resp.body.includes('error') && !resp.body.includes('invalid signature') && !resp.body.includes('Unauthorized')) {
            addFinding('HIGH', 'SAML/SSO', `SAML POST ACS at ${consumer} accepts unsigned assertion`, `Unsigned SAML response returned ${resp.status} without error`, 'Always validate SAML signatures. Check for XML Signature Wrapping (XSW) vulnerabilities.');
            break;
          }
        }
      } catch {}
    }
  } catch {}
}

export async function scanLdapRemote(origin, spinner) {
  spinner.text = 'Testing LDAP injection...';
  const params = ['user', 'username', 'login', 'uid', 'email', 'search', 'query', 'filter', 'cn', 'name'];
  const payloads = ['*)(uid=*))(|(uid=*', '*', 'admin*', '*)(|(uid=*', 'admin)(|(uid=*'];

  for (const param of params) {
    for (const payload of payloads.slice(0, 3)) {
      try {
        const resp = await fetchText(`${origin}/?${param}=${encodeURIComponent(payload)}`, {}, 5000);
        if (resp.status === 200 && (resp.body.toLowerCase().includes('admin') || resp.body.length > 10000)) {
          addFinding('CRITICAL', 'LDAP Injection', `LDAP injection via ?${param}=`, `Payload "${payload}" returned sensitive data`, 'Escape LDAP special characters. Use parameterized queries.');
          break;
        }
      } catch {}
    }
  }

  try {
    const resp = await fetchText(`${origin}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: '*)(uid=*))(|(uid=*', password: 'anything' }),
    }, 5000);

    if (resp.status === 200) {
      addFinding('CRITICAL', 'LDAP Injection', 'LDAP injection auth bypass at /api/login', 'Wildcard LDAP payload returned success', 'Validate and escape all inputs in LDAP filters. Never concatenate user input into LDAP queries.');
    }
  } catch {}
}

export async function scanMfaBypass(origin, spinner) {
  spinner.text = 'Testing MFA/OTP bypass vectors...';

  const postMfaPaths = ['/dashboard', '/account', '/settings', '/profile', '/home', '/user', '/mfa/setup', '/mfa/disable', '/2fa', '/api/me', '/api/user'];

  for (const path of postMfaPaths) {
    try {
      const resp = await fetchText(`${origin}${path}`, {}, 5000);
      if (resp.status === 200 && !resp.body.toLowerCase().includes('login') && !resp.body.toLowerCase().includes('2fa') && !resp.body.toLowerCase().includes('mfa')) {
        addFinding('HIGH', 'MFA Bypass', `Post-login path accessible without MFA: ${path}`, `${origin}${path} returns 200 without MFA challenge`, 'Enforce MFA at middleware level, not per-route. Gate all authenticated endpoints behind MFA check.');
      }
    } catch {}
  }

  try {
    const otpEndpoints = ['/api/verify-otp', '/api/mfa/verify', '/api/2fa/verify', '/api/auth/totp', '/api/otp'];
    for (const ep of otpEndpoints) {
      for (let i = 0; i < 3; i++) {
        try {
          const resp = await fetchText(`${origin}${ep}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code: String(Math.floor(Math.random() * 1000000)).padStart(6, '0') }),
          }, 3000);

          if (resp.status !== 429 && resp.status !== 400 && resp.status !== 401) {
            addFinding('MEDIUM', 'MFA Bypass', `OTP endpoint ${ep} may lack rate limiting`, `No rate limit response after 3 attempts`, 'Implement rate limiting on OTP verification. After 5 failed attempts, lock and require re-login.');
          }
        } catch {}
      }
    }
  } catch {}
}

export async function scanWebsocketReplay(origin, spinner) {
  spinner.text = 'Testing WebSocket vulnerabilities (enhanced)...';
  const wsOrigin = origin.replace('https://', 'wss://').replace('http://', 'ws://');

  addFinding('INFO', 'WebSocket (enhanced)', 'WebSocket replay/tampering check', `Check ${wsOrigin} for: CSWSH (Cross-Site WebSocket Hijacking), missing Origin validation, unauthenticated message handling, and message replay attacks`, 'Validate WebSocket Origin header. Require auth token in connect params. Implement message sequence numbers to prevent replay. Use per-message deflate compression.');
}

export async function scanPasswordReset(origin, spinner) {
  spinner.text = 'Testing password reset security...';

  let hasTargetParam = false;

  try {
    const resp = await fetchText(`${origin}/account/password/reset?email=test@example.com`, {}, 5000);
    if (resp.status === 200) {
      if (resp.body.includes('sent') || resp.body.includes('email') || resp.body.includes('check')) {
        addFinding('INFO', 'Password Reset', 'Email enumeration via reset endpoint', 'Check if response differs for existing vs non-existing emails', 'Use generic messages: "If that email exists, we sent a reset link."');
      }
    }
  } catch {}

  const hostTest = ['evil.com', 'localhost', '127.0.0.1'];
  for (const host of hostTest) {
    try {
      const resp = await fetchText(`${origin}/account/password/reset?email=target@victim.com`, {
        headers: { Host: host, 'X-Forwarded-Host': host },
      }, 5000);

      if (resp.body.includes(host)) {
        hasTargetParam = true;
        addFinding('HIGH', 'Password Reset', `Host header injection in password reset (${host})`, 'Reset link URL reflects attacker-controlled Host header', 'Generate reset URLs from a configured base URL, not the request Host header.');
        break;
      }
    } catch {}
  }

  if (!hasTargetParam) {
    try {
      const token = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
      const resp = await fetchText(`${origin}/account/password/reset/verify?token=${token}`, {}, 5000);
      if (resp.status === 200) {
        addFinding('LOW', 'Password Reset', 'Reset token endpoint accessible', `Token: ${token.substring(0, 8)}...`, 'Ensure reset tokens are cryptographically random (32+ bytes) and expire quickly (< 15 min).');
      }
    } catch {}
  }
}

export async function scanCsrfRemote(origin, spinner) {
  spinner.text = 'CSRF token analysis (remote)...';

  try {
    const resp = await fetchText(origin);
    const body = resp.body;

    const csrfPatterns = [
      /csrf[_-]?token|_token|<input[^>]*name=['"](?:csrf|_token|authenticity_token|__RequestVerificationToken)['"]/gi,
    ];

    let foundToken = false;
    for (const pattern of csrfPatterns) {
      if (pattern.test(body)) foundToken = true;
    }

    if (!foundToken) {
      const forms = body.match(/<form[^>]*method[^>]*(?:post|put|delete|patch)/gi);
      if (forms) {
        addFinding('HIGH', 'CSRF (remote)', 'Forms with POST/PUT/DELETE may lack CSRF protection', `${forms.length} state-changing forms found without CSRF tokens`, 'Add CSRF tokens to all state-changing forms. Use SameSite cookies.');
      }
    }

    const cookieTokens = body.match(/cookie\s*.*token|document\.cookie.*csrf/i);
    if (cookieTokens) {
      addFinding('MEDIUM', 'CSRF (remote)', 'CSRF token from cookies detected (vulnerable to cookie jar overflow)', 'CSRF token is read from cookies — not safe for SPA CSRF protection', 'Use custom header (X-CSRF-Token) with token from meta tag, not cookie. Implement Double Submit Cookie only with SameSite=Strict.');
    }
  } catch {}
}

export async function scanDanglingDns(hostname, spinner) {
  spinner.text = 'Checking for dangling DNS subdomain takeover...';

  const services = [
    { pattern: /\.cloudfront\.net/i, name: 'AWS CloudFront', indicator: 'The request could not be satisfied' },
    { pattern: /\.s3\.amazonaws\.com/i, name: 'AWS S3', indicator: 'NoSuchBucket' },
    { pattern: /\.azurewebsites\.net/i, name: 'Azure Web Apps', indicator: '404 Web Site not found' },
    { pattern: /\.herokuapp\.com/i, name: 'Heroku', indicator: 'No such app' },
    { pattern: /\.github\.io/i, name: 'GitHub Pages', indicator: 'There isnt a GitHub Pages site here' },
    { pattern: /\.netlify\.app|\.netlify\.com/i, name: 'Netlify', indicator: 'Not Found' },
    { pattern: /\.vercel\.app/i, name: 'Vercel', indicator: 'DEPLOYMENT_NOT_FOUND' },
    { pattern: /\.firebaseapp\.com/i, name: 'Firebase Hosting', indicator: 'Site Not Found' },
    { pattern: /\.surge\.sh/i, name: 'Surge.sh', indicator: 'project not found' },
  ];

  addFinding('INFO', 'Subdomain Takeover', 'Dangling CNAME check', 'Check DNS records for dangling CNAMEs to cloud services (CloudFront, S3, Heroku, GitHub Pages, Netlify, Vercel)', 'Remove DNS records pointing to decommissioned cloud resources to prevent subdomain takeover');
}

export async function scanCloudRemote(origin, spinner) {
  spinner.text = 'Testing cloud metadata access via SSRF...';

  const metadataUrls = [
    'http://169.254.169.254/latest/meta-data/',
    'http://metadata.google.internal/computeMetadata/v1/',
    'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
  ];

  const ssrfParams = ['url', 'link', 'src', 'callback', 'webhook', 'fetch', 'proxy', 'redirect'];

  for (const url of metadataUrls.slice(0, 1)) {
    for (const param of ssrfParams) {
      try {
        const resp = await fetchText(`${origin}/?${param}=${encodeURIComponent(url)}`, {}, 5000);
        if (resp.body.includes('instance-id') || resp.body.includes('ami-id') || resp.body.includes('local-hostname')) {
          addFinding('CRITICAL', 'Cloud Metadata', `Cloud metadata accessible via ?${param}= SSRF`, 'AWS IMDSv1 instance metadata exposed', 'Upgrade to IMDSv2 (uses session tokens). Block 169.254.169.254 at network level.');
          return;
        }
      } catch {}
    }
  }
}
