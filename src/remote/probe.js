import { addFinding } from '../core/findings.js';
import { fetchText, fetchWithTimeout } from '../utils/fetch.js';
import crypto from 'crypto';

export async function runProbe(origin, spinner) {
  spinner.text = '[httpx] Probing target...';

  const results = {
    statusCode: null,
    title: '',
    technologies: [],
    server: '',
    contentLength: 0,
    responseTime: 0,
    tls: {},
    cdn: null,
    waf: null,
    faviconHash: null,
    headers: {},
  };

  try {
    const start = Date.now();
    const resp = await fetchText(origin);
    results.responseTime = Date.now() - start;
    results.statusCode = resp.status;
    results.headers = resp.headers;
    results.contentLength = resp.body.length;

    results.title = extractTitle(resp.body);
    results.server = resp.headers['server'] || '';
    results.technologies = detectTechnologies(resp.headers, resp.body);
    results.cdn = detectCdn(resp.headers);
    results.waf = detectWaf(resp.headers, resp.body);

    spinner.text = '[httpx] Checking favicon hash...';
    results.faviconHash = await getFaviconHash(origin);

    spinner.text = '[httpx] Analyzing TLS certificate...';
    results.tls = await getTlsInfo(origin);

    spinner.text = '[httpx] Virtual host discovery...';
    await vhostDiscovery(origin, resp.body.length, spinner);

  } catch {}

  addFinding(
    'INFO',
    'Probe (httpx)',
    `Target fingerprint: ${results.title || 'N/A'}`,
    `Status: ${results.statusCode} | Server: ${results.server || 'hidden'} | Size: ${results.contentLength}B | Time: ${results.responseTime}ms\nTechnologies: ${results.technologies.join(', ') || 'none detected'}\nCDN: ${results.cdn || 'none'} | WAF: ${results.waf || 'none'} | Favicon hash: ${results.faviconHash || 'N/A'}`,
    'Technology fingerprinting helps identify version-specific vulnerabilities'
  );

  if (results.waf) {
    addFinding(
      'INFO',
      'Probe (httpx)',
      `WAF detected: ${results.waf}`,
      `Web Application Firewall identified via response headers/behavior`,
      'WAF may need bypass techniques for testing. Try encoding, case variation, and chunked payloads.'
    );
  }

  if (results.cdn) {
    addFinding(
      'INFO',
      'Probe (httpx)',
      `CDN detected: ${results.cdn}`,
      'Content Delivery Network fronts the origin server',
      'Consider testing the origin server directly if IP can be found (via DNS history, email headers, or certificate transparency)'
    );
  }

  if (results.responseTime > 5000) {
    addFinding(
      'LOW',
      'Probe (httpx)',
      'Slow response time detected',
      `Response took ${results.responseTime}ms`,
      'Slow responses may indicate resource exhaustion vulnerability potential'
    );
  }

  return results;
}

function extractTitle(html) {
  const match = html.match(/<title[^>]*>([^<]+)<\/title>/i);
  return match ? match[1].trim().substring(0, 100) : '';
}

function detectTechnologies(headers, body) {
  const techs = [];
  const checks = [
    { test: () => headers['x-powered-by']?.includes('Express'), name: 'Express.js' },
    { test: () => headers['x-powered-by']?.includes('PHP'), name: 'PHP' },
    { test: () => headers['x-powered-by']?.includes('ASP.NET'), name: 'ASP.NET' },
    { test: () => headers['x-aspnet-version'], name: `ASP.NET ${headers['x-aspnet-version'] || ''}` },
    { test: () => headers['x-drupal-cache'], name: 'Drupal' },
    { test: () => headers['x-generator']?.includes('WordPress'), name: 'WordPress' },
    { test: () => headers['x-shopify-stage'], name: 'Shopify' },
    { test: () => body.includes('__next'), name: 'Next.js' },
    { test: () => body.includes('__nuxt') || body.includes('nuxt'), name: 'Nuxt.js' },
    { test: () => body.includes('ng-version') || body.includes('ng-app'), name: 'Angular' },
    { test: () => body.includes('data-reactroot') || body.includes('__NEXT_DATA__'), name: 'React' },
    { test: () => body.includes('data-v-') || body.includes('Vue.js'), name: 'Vue.js' },
    { test: () => body.includes('svelte'), name: 'Svelte' },
    { test: () => body.includes('data-astro'), name: 'Astro' },
    { test: () => body.includes('wp-content') || body.includes('wp-includes'), name: 'WordPress' },
    { test: () => body.includes('Joomla'), name: 'Joomla' },
    { test: () => body.includes('laravel'), name: 'Laravel' },
    { test: () => body.includes('django') || headers['x-frame-options'] === 'SAMEORIGIN' && body.includes('csrfmiddlewaretoken'), name: 'Django' },
    { test: () => body.includes('rails') || headers['x-request-id'] && headers['x-runtime'], name: 'Ruby on Rails' },
    { test: () => body.includes('spring') || headers['x-application-context'], name: 'Spring Boot' },
    { test: () => headers['server']?.toLowerCase().includes('nginx'), name: 'Nginx' },
    { test: () => headers['server']?.toLowerCase().includes('apache'), name: 'Apache' },
    { test: () => headers['server']?.toLowerCase().includes('iis'), name: 'IIS' },
    { test: () => headers['server']?.toLowerCase().includes('gunicorn'), name: 'Gunicorn' },
    { test: () => headers['server']?.toLowerCase().includes('uvicorn'), name: 'Uvicorn (ASGI)' },
    { test: () => body.includes('firebase') || body.includes('firebaseapp'), name: 'Firebase' },
    { test: () => body.includes('supabase'), name: 'Supabase' },
    { test: () => body.includes('tailwind') || body.includes('tw-'), name: 'Tailwind CSS' },
    { test: () => body.includes('bootstrap'), name: 'Bootstrap' },
    { test: () => body.includes('jquery') || body.includes('jQuery'), name: 'jQuery' },
    { test: () => body.includes('gtag') || body.includes('google-analytics'), name: 'Google Analytics' },
    { test: () => body.includes('hotjar'), name: 'Hotjar' },
    { test: () => body.includes('sentry'), name: 'Sentry' },
    { test: () => body.includes('stripe'), name: 'Stripe' },
    { test: () => body.includes('recaptcha'), name: 'reCAPTCHA' },
    { test: () => body.includes('cloudflare'), name: 'Cloudflare' },
    { test: () => body.includes('vercel'), name: 'Vercel' },
    { test: () => body.includes('netlify'), name: 'Netlify' },
    { test: () => body.includes('graphql'), name: 'GraphQL' },
    { test: () => body.includes('socket.io'), name: 'Socket.IO' },
    { test: () => body.includes('webpack'), name: 'Webpack' },
    { test: () => body.includes('vite'), name: 'Vite' },
  ];

  for (const { test, name } of checks) {
    try { if (test()) techs.push(name); } catch {}
  }

  return [...new Set(techs)];
}

function detectCdn(headers) {
  if (headers['cf-ray'] || headers['cf-cache-status']) return 'Cloudflare';
  if (headers['x-amz-cf-id'] || headers['x-amz-cf-pop']) return 'AWS CloudFront';
  if (headers['x-fastly-request-id']) return 'Fastly';
  if (headers['x-akamai-transformed']) return 'Akamai';
  if (headers['x-cdn'] === 'Imperva') return 'Imperva';
  if (headers['x-sucuri-id']) return 'Sucuri';
  if (headers['x-azure-ref']) return 'Azure CDN';
  if (headers['x-vercel-cache']) return 'Vercel Edge';
  if (headers['x-nf-request-id']) return 'Netlify';
  if (headers['server']?.includes('KeyCDN')) return 'KeyCDN';
  if (headers['server']?.includes('bunny')) return 'BunnyCDN';
  return null;
}

function detectWaf(headers, body) {
  if (headers['cf-ray'] && headers['cf-mitigated']) return 'Cloudflare WAF';
  if (headers['x-sucuri-id']) return 'Sucuri WAF';
  if (headers['x-powered-by-anquanbao']) return 'Anquanbao WAF';
  if (headers['x-wa-info']) return 'AWS WAF';
  if (headers['server']?.includes('Wordfence')) return 'Wordfence';
  if (headers['server']?.includes('BigIP') || headers['x-cnection']) return 'F5 BIG-IP';
  if (headers['x-denied-reason'] || headers['x-dotdefender-denied']) return 'dotDefender';
  if (body.includes('mod_security') || body.includes('ModSecurity')) return 'ModSecurity';
  if (body.includes('access denied') && body.includes('incapsula')) return 'Imperva Incapsula';
  if (headers['server']?.includes('AkamaiGHost')) return 'Akamai Ghost';
  if (headers['x-protected-by']?.includes('Sqreen')) return 'Sqreen';
  return null;
}

async function getFaviconHash(origin) {
  try {
    const resp = await fetchWithTimeout(`${origin}/favicon.ico`, {}, 5000);
    if (resp.status === 200) {
      const buffer = await resp.arrayBuffer();
      const b64 = Buffer.from(buffer).toString('base64');
      const hash = crypto.createHash('md5').update(b64).digest('hex');
      return hash;
    }
  } catch {}
  return null;
}

async function getTlsInfo(origin) {
  if (!origin.startsWith('https://')) return { secure: false };
  return { secure: true, protocol: 'TLS' };
}

async function vhostDiscovery(origin, baseSize, spinner) {
  const vhosts = ['dev', 'staging', 'internal', 'admin', 'api', 'test', 'beta', 'old', 'backup'];
  const hostname = new URL(origin).hostname;

  for (const vhost of vhosts) {
    try {
      const testHost = `${vhost}.${hostname}`;
      const resp = await fetchText(origin, {
        headers: { Host: testHost },
      }, 3000);

      if (resp.status === 200 && Math.abs(resp.body.length - baseSize) > 100) {
        addFinding(
          'MEDIUM',
          'Probe (httpx)',
          `Virtual host responds differently: ${testHost}`,
          `Host header ${testHost} returns different content (size diff: ${Math.abs(resp.body.length - baseSize)}B)`,
          'Virtual host may expose internal applications. Investigate further.'
        );
      }
    } catch {}
  }
}
