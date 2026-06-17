let proxyUrl = null;

export function setProxy(url) {
  proxyUrl = url;
}

export function getProxyAgent(protocol) {
  if (!proxyUrl) return undefined;

  try {
    const url = new URL(proxyUrl);
    if (protocol === 'http:') return new (require('http')).Agent({ host: url.hostname, port: url.port });
    if (protocol === 'https:') return new (require('https')).Agent({ host: url.hostname, port: url.port, rejectUnauthorized: false });
  } catch {}
  return undefined;
}

export function proxyFetchOptions() {
  if (!proxyUrl) return {};

  return {
    agent: (parsedURL) => getProxyAgent(parsedURL.protocol),
  };
}

export function getProxyUrl() {
  return proxyUrl;
}

export function isProxyActive() {
  return proxyUrl !== null;
}
