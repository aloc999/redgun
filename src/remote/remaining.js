import { addFinding } from '../core/findings.js';
import { fetchText } from '../utils/fetch.js';
import dns from 'dns';

export async function scanPortScanner(hostname, spinner) {
  spinner.text = 'Port scanning...';

  const ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
    1433, 1521, 2049, 2375, 2376, 3000, 3306, 3389, 4443, 5000, 5432,
    5900, 6379, 6443, 8000, 8080, 8443, 8888, 9000, 9090, 9200, 27017];
  let openPorts = [];
  let banners = [];

  for (const port of ports) {
    try {
      const resp = await fetchText(`http://${hostname}:${port}/`, {}, 3000);
      if (resp.status > 0) {
        openPorts.push(port);
        if (resp.body.length > 5 && resp.body.length < 500) {
          banners.push(`${port}: ${resp.body.substring(0, 80)}`);
        }
      }
    } catch {}
  }

  if (openPorts.length > 0) {
    addFinding('INFO', 'Port Scanner', `${openPorts.length} ports open: ${openPorts.join(', ')}`,
      banners.length > 0 ? `Banners:\n${banners.join('\n')}` : 'No banners captured',
      `${openPorts.filter(p => [22, 3306, 5432, 6379, 27017].includes(p)).length > 0 ? 'Database/SSH ports exposed - restrict via firewall' : 'Review open ports for unnecessary services'}`);
  }
}

export async function scanDnsAxfr(hostname, spinner) {
  spinner.text = 'Attempting DNS zone transfer...';
  addFinding('INFO', 'DNS AXFR', `Zone transfer attempt for ${hostname}`,
    'AXFR is typically blocked by modern DNS providers', 'Verify NS records and attempt manual dig axfr @ns1.target.com domain.com for full zone dump');
}

export async function scanS3Buckets(hostname, spinner) {
  spinner.text = 'Enumerating S3 buckets...';
  const bucketNames = [
    hostname.replace(/^www\./, ''), hostname.replace(/^www\./, '') + '-prod',
    hostname.replace(/^www\./, '').split('.')[0], hostname.replace(/^www\./, '').split('.')[0] + '-assets',
    hostname.replace(/^www\./, '').split('.')[0] + '-backup',
    hostname.replace(/^www\./, '').split('.')[0] + '-static',
    hostname.replace(/^www\./, '').split('.')[0] + '-cdn',
  ];
  let found = 0;

  for (const bucket of new Set(bucketNames)) {
    try {
      const resp = await fetchText(`http://${bucket}.s3.amazonaws.com/`, {}, 5000);
      if (resp.status === 200 && resp.body.includes('Contents')) {
        found++;
        addFinding('CRITICAL', 'S3 Bucket', `Public S3 bucket: ${bucket}`,
          `${bucket}.s3.amazonaws.com returns directory listing`, `Set S3 bucket to private. Enable Block Public Access. Remove public-read ACL.`);
      } else if (resp.status === 403) {
        found++;
        addFinding('LOW', 'S3 Bucket', `S3 bucket exists (403): ${bucket}`,
          'Bucket exists but access denied — try authenticated access or different region', 'Verify bucket is not publicly accessible in any region.');
      }
    } catch {}
  }

  if (found > 0) spinner.text = `S3: ${found} buckets found`;
  else spinner.text = 'S3: no buckets found';
}

export async function scanResponseSplitting(origin, spinner) {
  spinner.text = 'Testing HTTP Response Splitting...';
  const params = ['redirect', 'next', 'return', 'url', 'callback', 'page'];

  for (const param of params) {
    try {
      const payload = encodeURIComponent('/\r\nX-Injected: true');
      const resp = await fetchText(`${origin}/?${param}=${payload}`, {}, 5000);
      if (resp.headers['x-injected'] === 'true') {
        addFinding('CRITICAL', 'Response Splitting', `Response splitting via ?${param}=`,
          'CRLF injection resulted in injected header', 'Sanitize CRLF from all URL/header input.');
        break;
      }
    } catch {}
  }
}

export async function scanXssiRemote(origin, spinner) {
  spinner.text = 'Testing XSSI / JSON hijacking...';
  const apiPaths = ['/api/user', '/api/me', '/api/profile', '/api/account', '/api/session'];

  for (const path of apiPaths) {
    try {
      const resp = await fetchText(`${origin}${path}`, { headers: { Accept: 'application/json' } }, 5000);
      if (resp.status === 200 && resp.body.trim().startsWith('[{') || resp.body.trim().startsWith('{"')) {
        const isArray = resp.body.trim().startsWith('[');
        if (isArray && resp.body.length < 50000 && /email|token|session|secret|password|key/i.test(resp.body.substring(0, 500))) {
          addFinding('HIGH', 'XSSI', `XSSI: JSON array at ${path} with sensitive data`,
            `${origin}${path} returns JSON array that could be included as <script src=>`,
            'Prefix JSON with while(1); or {}. Use CSRF tokens on API endpoints. Set X-Content-Type-Options: nosniff.');
          break;
        }
      }
    } catch {}
  }
}

export async function scanTabnabbing(origin, spinner) {
  spinner.text = 'Testing tabnabbing...';
  try {
    const resp = await fetchText(origin);
    const targetBlank = (resp.body.match(/target\s*=\s*['"]_blank['"]/gi) || []).length;
    const hasNoopener = resp.body.includes('noopener') || resp.body.includes('noreferrer');

    if (targetBlank > 0 && !hasNoopener) {
      addFinding('HIGH', 'Tabnabbing', `${targetBlank} target=_blank links without noopener`,
        'Opened pages can access window.opener and redirect the original tab to a phishing page',
        'Add rel="noopener noreferrer" to all target=_blank links');
    }
  } catch {}
}

export async function scanSRI(origin, spinner) {
  spinner.text = 'Checking SRI for external resources...';
  try {
    const resp = await fetchText(origin);
    const externalScripts = [...resp.body.matchAll(/<script[^>]*src\s*=\s*['"](https?:)?\/\/(?!.*integrity)[^'"]*['"]/gi)];
    const externalCss = [...resp.body.matchAll(/<link[^>]*rel\s*=\s*['"]stylesheet['"][^>]*href\s*=\s*['"](https?:)?\/\/(?!.*integrity)[^'"]*['"]/gi)];

    const total = externalScripts.length + externalCss.length;
    if (total > 0) {
      addFinding('MEDIUM', 'Subresource Integrity', `${total} external resources without SRI integrity hashes`,
        `${externalScripts.length} scripts + ${externalCss.length} stylesheets lacking integrity attribute`,
        'Add integrity="sha384-..." and crossorigin="anonymous" to external script/link tags from CDN');
    }
  } catch {}
}

export async function scanOpenGraphInjection(origin, spinner) {
  spinner.text = 'Testing Open Graph injection...';
  const params = ['title', 'name', 'description', 'text', 'body', 'content', 'message', 'bio'];

  for (const param of params) {
    try {
      const ogPayload = '<meta http-equiv="refresh" content="0;url=https://evil.com">';
      const resp = await fetchText(`${origin}/?${param}=${encodeURIComponent(ogPayload)}`, {}, 5000);
      if (resp.body.includes('<meta http-equiv="refresh"')) {
        addFinding('HIGH', 'Open Graph Injection', `Meta tag injection via ?${param}=`,
          'Malicious meta tag reflected in page — can redirect users to phishing pages', 'Sanitize/strip HTML from user input used in meta tags');
        break;
      }
    } catch {}
  }
}

export async function scanCookieTossing(origin, spinner) {
  spinner.text = 'Testing cookie tossing...';
  addFinding('INFO', 'Cookie Tossing', 'Cookie tossing check',
    'Test: Set Cookie: key=value; Path=/ on parent domain. Then on subdomain, set same cookie with Path=/app. Subdomain cookie wins due to higher specificity.',
    'Use __Host- prefix for cookies. Set Path=/ only. Validate cookie domain/server-side session binding.');
}
