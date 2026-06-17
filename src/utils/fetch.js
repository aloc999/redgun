import https from 'https';
import http from 'http';

import { getActiveSession } from '../core/session.js';
import { getProxyUrl } from '../core/proxy.js';

const RATE_LIMIT = 5;
let lastRequestTime = 0;

async function waitForSlot() {
  const now = Date.now();
  const minInterval = 1000 / RATE_LIMIT;
  const timeSinceLast = now - lastRequestTime;

  if (timeSinceLast < minInterval) {
    await new Promise((r) => setTimeout(r, minInterval - timeSinceLast));
  }

  lastRequestTime = Date.now();
}

function getAuthHeaders() {
  const session = getActiveSession();
  return session ? session.headers : {};
}

export async function fetchWithTimeout(url, options = {}, timeout = 10000) {
  await waitForSlot();

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  const authHeaders = getAuthHeaders();
  const proxy = getProxyUrl();

  try {
    const fetchOptions = {
      ...options,
      signal: controller.signal,
      headers: {
        'User-Agent': 'RedGun-Security-Scanner/1.0',
        ...authHeaders,
        ...options.headers,
      },
    };

    if (proxy) {
      const { HttpsProxyAgent } = await import('https-proxy-agent');
      fetchOptions.agent = new HttpsProxyAgent(proxy);
    }

    const response = await fetch(url, fetchOptions);
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
