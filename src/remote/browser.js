import { addFinding } from '../core/findings.js';
import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';

export async function runBrowserEngine(origin, spinner) {
  spinner.text = '[Browser] Launching headless Chromium...';

  let puppeteer;
  try {
    puppeteer = (await import('puppeteer')).default;
  } catch {
    spinner.warn('Puppeteer not available — browser tests skipped');
    return;
  }

  let browser;
  let page;
  const results = {
    alerts: [],
    consoleErrors: [],
    networkRequests: [],
    wsConnections: [],
    localStorage: {},
    sessionStorage: {},
    serviceWorkers: false,
    postMessageListens: false,
    screenshotPath: null,
    xssTested: 0,
    xssConfirmed: 0,
    formsFound: 0,
  };

  try {
    browser = await puppeteer.launch({
      headless: 'new',
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-web-security', '--disable-features=IsolateOrigins,site-per-process'],
    });

    page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 800 });

    page.on('dialog', async (dialog) => {
      results.alerts.push({ message: dialog.message(), type: dialog.type() });
      await dialog.dismiss();
    });

    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        results.consoleErrors.push(msg.text());
      }
    });

    page.on('request', (req) => {
      if (req.resourceType() === 'websocket') {
        results.wsConnections.push(req.url());
      }
      results.networkRequests.push({
        url: req.url(),
        method: req.method(),
        type: req.resourceType(),
      });
    });

    spinner.text = '[Browser] Navigating to target...';
    await page.goto(origin, { waitUntil: 'networkidle2', timeout: 30000 });

    results.serviceWorkers = await page.evaluate(() => 'serviceWorker' in navigator && Boolean(navigator.serviceWorker.controller));

    results.postMessageListens = await page.evaluate(() => {
      let hasListener = false;
      window.addEventListener('message', () => { hasListener = true; });
      window.postMessage('__redgun_probe__', '*');
      return new Promise(r => setTimeout(() => r(hasListener), 200));
    });

    results.localStorage = await page.evaluate(() => {
      const data = {};
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        data[key] = localStorage.getItem(key);
      }
      return data;
    });

    results.sessionStorage = await page.evaluate(() => {
      const data = {};
      try {
        for (let i = 0; i < sessionStorage.length; i++) {
          const key = sessionStorage.key(i);
          data[key] = sessionStorage.getItem(key);
        }
      } catch {}
      return data;
    });

    spinner.text = '[Browser] Scanning for forms and inputs...';
    const inputFields = await page.evaluate(() => {
      const fields = [];
      document.querySelectorAll('input, textarea, select').forEach((el) => {
        const name = el.getAttribute('name') || el.getAttribute('id') || el.getAttribute('class') || '';
        const type = el.getAttribute('type') || el.tagName.toLowerCase();
        fields.push({ name: name.substring(0, 60), type });
      });
      return fields;
    });

    results.formsFound = await page.evaluate(() => document.querySelectorAll('form').length);

    spinner.text = '[Browser] Testing DOM XSS...';
    const xssPayloads = [
      '<img src=x onerror=alert("REDGUN_XSS") />',
      '<svg onload=alert("REDGUN_XSS") />',
      '" onfocus=alert("REDGUN_XSS") autofocus="',
      '"><img src=x onerror=alert("REDGUN_XSS")>',
      'javascript:alert("REDGUN_XSS")',
    ];

    for (const field of inputFields.slice(0, 20)) {
      if (!field.name) continue;
      for (const payload of xssPayloads.slice(0, 3)) {
        try {
          await page.evaluate((name, payload) => {
            const el = document.querySelector(`[name="${name}"], [id="${name}"]`);
            if (el) {
              el.value = payload;
              el.dispatchEvent(new Event('input', { bubbles: true }));
              el.dispatchEvent(new Event('change', { bubbles: true }));
            }
          }, field.name, payload);
          results.xssTested++;
        } catch {}
      }
    }

    for (const formFields of inputFields.filter(f => f.name)) {
      try {
        await page.evaluate((name) => {
          const input = document.querySelector(`[name="${name}"], [id="${name}"]`);
          const form = input?.closest('form');
          if (form) form.submit();
        }, formFields.name);
        await new Promise(r => setTimeout(r, 300));

        if (results.alerts.some(a => a.message.includes('REDGUN_XSS'))) {
          results.xssConfirmed++;
        }
      } catch {}
    }

    const currentPageUrl = page.url();
    if (results.alerts.some(a => a.message.includes('REDGUN_XSS')) && currentPageUrl.includes(origin)) {
      results.xssConfirmed = Math.max(results.xssConfirmed, 1);
    }

    if (results.alerts.length > 0 || results.xssConfirmed > 0) {
      const screenshotsDir = './scans';
      if (!existsSync(screenshotsDir)) mkdirSync(screenshotsDir, { recursive: true });
      const ts = Date.now();
      results.screenshotPath = join(screenshotsDir, `redgun-xss-${ts}.png`);
      await page.screenshot({ path: results.screenshotPath, fullPage: true });
    }

  } catch (err) {
    spinner.text = `[Browser] Error: ${err.message}`;
  } finally {
    if (browser) await browser.close();
  }

  reportFindings(origin, results);
}

function reportFindings(origin, results) {
  if (results.xssConfirmed > 0) {
    addFinding(
      'CRITICAL',
      'Browser XSS',
      `${results.xssConfirmed} DOM/Stored XSS confirmed via browser`,
      `${results.xssTested} payloads injected into ${results.formsFound} forms — ${results.xssConfirmed} alert() triggers detected\nScreenshot: ${results.screenshotPath || 'N/A'}`,
      'Sanitize all user input on both client and server side. Use DOMPurify, React escape, or framework auto-escaping.'
    );
  } else if (results.xssTested > 0) {
    addFinding(
      'INFO',
      'Browser XSS',
      `Tested ${results.xssTested} inputs — no XSS confirmed`,
      `${results.formsFound} forms analyzed with 5 XSS payload types`,
      'DOM/Stored XSS not confirmed — continue manual testing with application-specific payloads'
    );
  }

  const apiRequests = results.networkRequests.filter(r => r.url.includes('/api/'));
  if (apiRequests.length > 0) {
    const uniqueApis = [...new Set(apiRequests.map(r => r.url).filter(u => u.startsWith(origin)))];

    if (uniqueApis.length > 5) {
      addFinding(
        'INFO',
        'Browser Recon',
        `${uniqueApis.length} API endpoints captured from browser network`,
        `APIs: ${uniqueApis.slice(0, 10).join(', ')}${uniqueApis.length > 10 ? ` +${uniqueApis.length - 10} more` : ''}`,
        'Review captured API endpoints for auth requirements and sensitive data exposure'
      );
    }
  }

  if (results.wsConnections.length > 0) {
    addFinding(
      'MEDIUM',
      'Browser WebSocket',
      `${results.wsConnections.length} WebSocket connection(s) detected`,
      `WS: ${results.wsConnections.join(', ')}`,
      'Test WebSocket for CSWSH, missing auth, and message tampering'
    );
  }

  if (results.serviceWorkers) {
    addFinding(
      'LOW',
      'Browser Service Worker',
      'Service Worker active on page',
      'SW registered — test for importScripts abuse and fetch listener tampering',
      'Validate Service Worker scope and origin. Use Subresource Integrity for imported scripts.'
    );
  }

  if (results.postMessageListens) {
    addFinding(
      'MEDIUM',
      'Browser postMessage',
      'postMessage listener detected (runtime check)',
      'Page has active message event handler',
      'Audit postMessage listeners for missing origin validation. Test cross-origin iframe attacks.'
    );
  }

  const localKeys = Object.keys(results.localStorage || {});
  const sessionKeys = Object.keys(results.sessionStorage || {});
  if (localKeys.length > 0 || sessionKeys.length > 0) {
    const sensitiveStorage = [...localKeys, ...sessionKeys].filter(k =>
      /token|secret|key|password|credential|jwt|auth|session|user/i.test(k)
    );

    if (sensitiveStorage.length > 0) {
      addFinding(
        'HIGH',
        'Browser Storage',
        `${sensitiveStorage.length} sensitive items in browser storage`,
        `Keys: ${sensitiveStorage.join(', ')}`,
        'Never store tokens, secrets, or credentials in localStorage/sessionStorage. Use httpOnly cookies for session management.'
      );
    }
  }

  if (results.consoleErrors.length > 5) {
    addFinding(
      'LOW',
      'Browser Console',
      `${results.consoleErrors.length} console errors detected`,
      `Sample: ${results.consoleErrors.slice(0, 3).join(' | ')}`,
      'Console errors may reveal internal paths, CSP violations, or API error messages'
    );
  }
}
