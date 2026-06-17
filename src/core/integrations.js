import { writeFileSync, existsSync, mkdirSync } from 'fs';
import { getFindings } from './findings.js';
import { fetchText } from '../utils/fetch.js';

export async function generateHar(origin, outputPath = './scans/redgun.har') {
  if (!existsSync('./scans')) mkdirSync('./scans', { recursive: true });

  const entries = [];
  const startTime = new Date();

  const baseReq = await captureRequest(origin);
  if (baseReq) entries.push(baseReq);

  const paths = ['/api', '/api/v1', '/graphql', '/login', '/.well-known/security.txt', '/robots.txt'];
  for (const path of paths) {
    const req = await captureRequest(`${origin}${path}`);
    if (req) entries.push(req);
  }

  const har = {
    log: {
      version: '1.2',
      creator: { name: 'RedGun Security Scanner', version: '3.1.0' },
      entries,
    },
  };

  writeFileSync(outputPath, JSON.stringify(har, null, 2));
  return outputPath;
}

async function captureRequest(url) {
  try {
    const start = Date.now();
    const resp = await fetchText(url, {}, 5000);
    const time = Date.now() - start;

    return {
      startedDateTime: new Date(start).toISOString(),
      time,
      request: {
        method: 'GET',
        url,
        httpVersion: 'HTTP/1.1',
        headers: [{ name: 'User-Agent', value: 'RedGun-Security-Scanner/1.0' }],
        cookies: [],
        queryString: [],
        headersSize: -1,
        bodySize: -1,
      },
      response: {
        status: resp.status,
        statusText: resp.status === 200 ? 'OK' : resp.status === 404 ? 'Not Found' : 'Error',
        httpVersion: 'HTTP/1.1',
        headers: Object.entries(resp.headers).map(([name, value]) => ({ name, value })),
        cookies: [],
        content: {
          size: resp.body.length,
          mimeType: resp.headers['content-type'] || 'text/html',
          text: resp.body,
        },
        redirectURL: '',
        headersSize: -1,
        bodySize: resp.body.length,
      },
      cache: {},
      timings: { send: 0, wait: time, receive: 0 },
    };
  } catch {}
  return null;
}

export async function exportCaido(origin, outputPath = './scans/caido-export.json') {
  if (!existsSync('./scans')) mkdirSync('./scans', { recursive: true });

  const findings = getFindings();
  const entries = [];

  for (const f of findings) {
    entries.push({
      type: 'request',
      host: new URL(origin).hostname,
      port: 443,
      tls: true,
      method: 'GET',
      path: '/',
      query: '',
      headers: [['User-Agent', 'RedGun-Security-Scanner/1.0']],
      body: '',
      color: f.severity === 'CRITICAL' ? '#f44336' : f.severity === 'HIGH' ? '#ff5722' : f.severity === 'MEDIUM' ? '#ff9800' : '#2196f3',
      comment: `[${f.severity}] ${f.module}: ${f.title}\nValidation: ${f.validationNote || 'N/A'}\nConfidence: ${f.confidence || 0}%\nFix: ${f.fix || 'N/A'}`,
      finding: {
        title: f.title,
        description: f.details || '',
        severity: f.severity,
        confidence: f.confidence ? (f.confidence >= 80 ? 'Certain' : f.confidence >= 50 ? 'Firm' : 'Tentative') : 'Tentative',
        remediation: f.fix || '',
      },
      highlights: [],
    });
  }

  writeFileSync(outputPath, JSON.stringify(entries, null, 2));
  return outputPath;
}

export async function queryShodan(hostname, apiKey = '') {
  if (!apiKey) return null;

  try {
    const resp = await fetchText(`https://api.shodan.io/dns/resolve?hostnames=${hostname}&key=${apiKey}`, {}, 5000);
    return JSON.parse(resp.body);
  } catch {
    return null;
  }
}
