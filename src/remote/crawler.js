import { addFinding } from '../core/findings.js';
import { fetchText } from '../utils/fetch.js';

export async function runCrawler(origin, spinner) {
  spinner.text = '[Katana] Crawling target for endpoints...';

  const discovered = {
    urls: new Set(),
    jsFiles: new Set(),
    forms: [],
    params: new Set(),
    apiEndpoints: new Set(),
    emails: new Set(),
    subdomains: new Set(),
    secrets: [],
  };

  try {
    const resp = await fetchText(origin);
    const body = resp.body;

    extractUrls(body, origin, discovered);
    extractJsFiles(body, origin, discovered);
    extractForms(body, discovered);
    extractParams(body, discovered);
    extractEmails(body, discovered);

    for (const jsUrl of [...discovered.jsFiles].slice(0, 20)) {
      try {
        spinner.text = `[Katana] Parsing JS: ${jsUrl.substring(0, 60)}...`;
        const jsResp = await fetchText(jsUrl, {}, 8000);
        extractEndpointsFromJs(jsResp.body, origin, discovered);
        extractSecretsFromJs(jsResp.body, jsUrl, discovered);
      } catch {}
    }
  } catch {}

  if (discovered.apiEndpoints.size > 0) {
    addFinding(
      'INFO',
      'Crawler (Katana)',
      `Discovered ${discovered.apiEndpoints.size} API endpoints from JS`,
      `Endpoints: ${[...discovered.apiEndpoints].slice(0, 10).join(', ')}${discovered.apiEndpoints.size > 10 ? '...' : ''}`,
      'Review discovered endpoints for authentication and authorization requirements'
    );
  }

  if (discovered.forms.length > 0) {
    addFinding(
      'INFO',
      'Crawler (Katana)',
      `Discovered ${discovered.forms.length} forms`,
      `Actions: ${discovered.forms.map(f => f.action).slice(0, 5).join(', ')}`,
      'Test discovered forms for injection vulnerabilities'
    );

    for (const form of discovered.forms) {
      if (form.method === 'GET' && form.hasSensitiveFields) {
        addFinding(
          'MEDIUM',
          'Crawler (Katana)',
          'Sensitive form uses GET method',
          `Form action: ${form.action} - sends sensitive data in URL`,
          'Use POST method for forms that submit sensitive data (passwords, tokens, etc.)'
        );
      }
      if (!form.hasCsrf && form.method === 'POST') {
        addFinding(
          'MEDIUM',
          'Crawler (Katana)',
          'POST form without CSRF token',
          `Form action: ${form.action}`,
          'Add CSRF token to all state-changing forms'
        );
      }
    }
  }

  if (discovered.params.size > 0) {
    addFinding(
      'INFO',
      'Crawler (Katana)',
      `Discovered ${discovered.params.size} unique parameters`,
      `Parameters: ${[...discovered.params].slice(0, 20).join(', ')}`,
      'Fuzz discovered parameters for injection vulnerabilities'
    );
  }

  if (discovered.secrets.length > 0) {
    for (const secret of discovered.secrets.slice(0, 5)) {
      addFinding(
        'HIGH',
        'Crawler (Katana)',
        `Secret found in JS bundle: ${secret.type}`,
        `File: ${secret.file}\nValue: ${secret.value.substring(0, 20)}...`,
        'Remove secrets from client-side JavaScript. Use server-side proxying for API calls.'
      );
    }
  }

  if (discovered.emails.size > 0) {
    addFinding(
      'LOW',
      'Crawler (Katana)',
      `${discovered.emails.size} email addresses discovered`,
      `Emails: ${[...discovered.emails].slice(0, 5).join(', ')}`,
      'Email addresses can be used for phishing and social engineering'
    );
  }

  return discovered;
}

function extractUrls(html, origin, discovered) {
  const urlPatterns = [
    /href\s*=\s*['"]([^'"#]+)['"]/gi,
    /src\s*=\s*['"]([^'"]+)['"]/gi,
    /action\s*=\s*['"]([^'"]+)['"]/gi,
    /url\s*\(\s*['"]?([^'")]+)['"]?\s*\)/gi,
    /window\.location\s*=\s*['"]([^'"]+)['"]/gi,
  ];

  for (const pattern of urlPatterns) {
    let match;
    while ((match = pattern.exec(html)) !== null) {
      let url = match[1];
      if (url.startsWith('/')) url = origin + url;
      else if (!url.startsWith('http')) continue;
      if (url.startsWith(origin)) discovered.urls.add(url);
    }
  }
}

function extractJsFiles(html, origin, discovered) {
  const jsPattern = /src\s*=\s*['"]([^'"]*\.(?:js|mjs|chunk\.js|bundle\.js)[^'"]*)['"]/gi;
  let match;
  while ((match = jsPattern.exec(html)) !== null) {
    let url = match[1];
    if (url.startsWith('/')) url = origin + url;
    else if (url.startsWith('./')) url = origin + url.substring(1);
    else if (!url.startsWith('http')) url = origin + '/' + url;
    discovered.jsFiles.add(url);
  }
}

function extractForms(html, discovered) {
  const formPattern = /<form[^>]*>([\s\S]*?)<\/form>/gi;
  let match;
  while ((match = formPattern.exec(html)) !== null) {
    const formHtml = match[0];
    const action = formHtml.match(/action\s*=\s*['"]([^'"]*)['"]/i)?.[1] || '';
    const method = (formHtml.match(/method\s*=\s*['"]([^'"]*)['"]/i)?.[1] || 'GET').toUpperCase();
    const hasCsrf = /csrf|_token|authenticity_token|__RequestVerificationToken/i.test(formHtml);
    const hasSensitiveFields = /type\s*=\s*['"]password['"]|name\s*=\s*['"](?:password|secret|token|card|ssn|credit)/i.test(formHtml);

    const inputPattern = /name\s*=\s*['"]([^'"]+)['"]/gi;
    let inputMatch;
    while ((inputMatch = inputPattern.exec(formHtml)) !== null) {
      discovered.params.add(inputMatch[1]);
    }

    discovered.forms.push({ action, method, hasCsrf, hasSensitiveFields });
  }
}

function extractParams(html, discovered) {
  const paramPatterns = [
    /[?&]([a-zA-Z_][a-zA-Z0-9_]*)=/g,
    /name\s*=\s*['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]/g,
  ];

  for (const pattern of paramPatterns) {
    let match;
    while ((match = pattern.exec(html)) !== null) {
      discovered.params.add(match[1]);
    }
  }
}

function extractEmails(html, discovered) {
  const emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  let match;
  while ((match = emailPattern.exec(html)) !== null) {
    if (!match[0].includes('example.com') && !match[0].includes('test.com')) {
      discovered.emails.add(match[0]);
    }
  }
}

function extractEndpointsFromJs(jsContent, origin, discovered) {
  const endpointPatterns = [
    /['"`](\/api\/[^'"`\s{]+)['"`]/g,
    /['"`](\/v[0-9]+\/[^'"`\s{]+)['"`]/g,
    /['"`](\/(?:users?|admin|auth|login|register|graphql|webhook|upload|download|export|import|config|settings|profile|account|payment|order|cart|search|notify|message)[^'"`\s{]*)['"`]/g,
    /(?:fetch|axios|http|request|ajax)\s*\(\s*['"`]([^'"`]+)['"`]/g,
    /(?:url|endpoint|path|route|href)\s*[:=]\s*['"`](\/[^'"`]+)['"`]/g,
  ];

  for (const pattern of endpointPatterns) {
    let match;
    while ((match = pattern.exec(jsContent)) !== null) {
      const endpoint = match[1];
      if (endpoint.length > 2 && endpoint.length < 200 && !endpoint.includes('${')) {
        discovered.apiEndpoints.add(endpoint);
      }
    }
  }

  const paramPattern = /['"`]\?([a-zA-Z_]+)=|['"`]&([a-zA-Z_]+)=/g;
  let paramMatch;
  while ((paramMatch = paramPattern.exec(jsContent)) !== null) {
    discovered.params.add(paramMatch[1] || paramMatch[2]);
  }
}

function extractSecretsFromJs(jsContent, fileUrl, discovered) {
  const secretPatterns = [
    { pattern: /AKIA[0-9A-Z]{16}/g, type: 'AWS Access Key' },
    { pattern: /sk_live_[0-9a-zA-Z]{24,}/g, type: 'Stripe Secret Key' },
    { pattern: /ghp_[A-Za-z0-9_]{36,}/g, type: 'GitHub Token' },
    { pattern: /sk-[a-zA-Z0-9]{48}/g, type: 'OpenAI Key' },
    { pattern: /xox[baprs]-[0-9a-zA-Z-]{10,}/g, type: 'Slack Token' },
    { pattern: /AIza[0-9A-Za-z\-_]{35}/g, type: 'Google API Key' },
    { pattern: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g, type: 'Private Key' },
  ];

  for (const { pattern, type } of secretPatterns) {
    let match;
    while ((match = pattern.exec(jsContent)) !== null) {
      discovered.secrets.push({ type, value: match[0], file: fileUrl });
      break;
    }
  }
}
