import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { addFinding } from '../core/findings.js';

const CONFIG_FILES = [
  'nuxt.config.js', 'nuxt.config.ts', 'next.config.js', 'next.config.mjs',
  'vercel.json', 'netlify.toml', '_headers', 'nginx.conf',
  'server.js', 'server.ts', 'app.js', 'app.ts', 'index.js', 'index.ts',
];

export async function auditHeadersConfig(projectPath, spinner) {
  spinner.text = 'Checking security headers configuration...';

  let foundCsp = false;
  let foundHsts = false;
  let foundXfo = false;

  for (const configFile of CONFIG_FILES) {
    const filePath = join(projectPath, configFile);
    if (!existsSync(filePath)) continue;

    try {
      const content = readFileSync(filePath, 'utf-8');

      if (/content-security-policy|contentSecurityPolicy|csp/i.test(content)) foundCsp = true;
      if (/strict-transport-security|hsts/i.test(content)) foundHsts = true;
      if (/x-frame-options|frameOptions/i.test(content)) foundXfo = true;

      if (/unsafe-inline|unsafe-eval/i.test(content)) {
        addFinding(
          'MEDIUM',
          'Headers Config',
          'CSP uses unsafe-inline or unsafe-eval',
          `File: ${configFile}`,
          'Remove unsafe-inline/unsafe-eval from CSP. Use nonce-based or hash-based CSP instead.'
        );
      }
    } catch {}
  }

  if (!foundCsp) {
    addFinding(
      'MEDIUM',
      'Headers Config',
      'No Content-Security-Policy configured',
      'CSP header not found in configuration files',
      'Add a strict CSP header to prevent XSS and data injection attacks'
    );
  }

  if (!foundHsts) {
    addFinding(
      'MEDIUM',
      'Headers Config',
      'No Strict-Transport-Security configured',
      'HSTS header not found in configuration files',
      'Add HSTS header with max-age=31536000; includeSubDomains; preload'
    );
  }

  if (!foundXfo) {
    addFinding(
      'LOW',
      'Headers Config',
      'No X-Frame-Options configured',
      'X-Frame-Options not found in configuration',
      'Add X-Frame-Options: DENY or use CSP frame-ancestors directive'
    );
  }
}
