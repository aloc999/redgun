import { writeFileSync, readFileSync, existsSync, mkdirSync } from 'fs';
import { join } from 'path';

const PROFILES_DIR = '.redgun/profiles';
let activeSession = null;

export function getSessionDir() {
  if (!existsSync('.redgun')) mkdirSync('.redgun');
  if (!existsSync(PROFILES_DIR)) mkdirSync(PROFILES_DIR);
  return PROFILES_DIR;
}

export async function createSession(profile, spinner) {
  getSessionDir();

  spinner.text = 'Authenticating...';
  const jar = {};
  const headers = {};

  try {
    const { default: fetch } = await import('node-fetch');

    if (profile.method === 'form') {
      const loginResp = await fetch(profile.loginUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...profile.extraHeaders },
        body: JSON.stringify(profile.credentials),
        redirect: 'manual',
      });

      if (loginResp.status === 200 || loginResp.status === 302) {
        const setCookie = loginResp.headers.get('set-cookie');
        if (setCookie) {
          jar.cookies = setCookie;
          headers.Cookie = extractCookies(setCookie);
        }

        if (profile.tokenField) {
          try {
            const body = await loginResp.json();
            if (body[profile.tokenField]) {
              headers.Authorization = `Bearer ${body[profile.tokenField]}`;
            }
          } catch {}
        }
      }
    }

    if (profile.method === 'cookie') {
      headers.Cookie = profile.cookie;
      jar.cookies = profile.cookie;
    }

    if (profile.method === 'bearer') {
      headers.Authorization = `Bearer ${profile.token}`;
    }

    if (profile.method === 'basic') {
      headers.Authorization = `Basic ${Buffer.from(`${profile.username}:${profile.password}`).toString('base64')}`;
    }

    if (Object.keys(headers).length > 0) {
      activeSession = {
        profile: profile.name,
        headers,
        jar,
        loginUrl: profile.loginUrl,
        targetUrl: profile.targetUrl,
        authenticatedAt: new Date().toISOString(),
      };

      saveProfile(profile);
      spinner.succeed('Authenticated successfully');
      return { headers, jar };
    }
  } catch (err) {
    spinner.fail(`Auth failed: ${err.message}`);
    return null;
  }

  spinner.fail('No auth method configured');
  return null;
}

export function getActiveSession() {
  return activeSession;
}

export function saveProfile(profile) {
  getSessionDir();
  writeFileSync(join(PROFILES_DIR, `${profile.name}.json`), JSON.stringify(profile, null, 2));
}

export function loadProfile(name) {
  const path = join(PROFILES_DIR, `${name}.json`);
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, 'utf-8'));
}

export function listProfiles() {
  getSessionDir();
  try {
    const { readdirSync } = require('fs');
    return readdirSync(PROFILES_DIR).filter(f => f.endsWith('.json')).map(f => f.replace('.json', ''));
  } catch { return []; }
}

function extractCookies(setCookieHeader) {
  if (!setCookieHeader) return '';
  return setCookieHeader.split(',').map(c => c.split(';')[0]).join('; ');
}
