import https from 'https';
import http from 'http';

export async function fetchWithTimeout(url, options = {}, timeout = 10000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        'User-Agent': 'RedGun-Security-Scanner/1.0',
        ...options.headers,
      },
    });
    clearTimeout(timer);
    return response;
  } catch (error) {
    clearTimeout(timer);
    if (error.name === 'AbortError') {
      throw new Error(`Request timeout after ${timeout}ms: ${url}`);
    }
    throw error;
  }
}

export async function fetchText(url, options = {}) {
  const response = await fetchWithTimeout(url, options);
  return {
    status: response.status,
    headers: Object.fromEntries(response.headers.entries()),
    body: await response.text(),
    url: response.url,
  };
}

export async function fetchJson(url, options = {}) {
  const response = await fetchWithTimeout(url, options);
  return {
    status: response.status,
    headers: Object.fromEntries(response.headers.entries()),
    body: await response.json(),
    url: response.url,
  };
}

export async function checkUrl(url, timeout = 5000) {
  try {
    const response = await fetchWithTimeout(url, { method: 'HEAD' }, timeout);
    return { accessible: true, status: response.status };
  } catch {
    return { accessible: false, status: null };
  }
}
