import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join } from 'path';
import { addFinding } from './findings.js';
import { fetchText } from '../utils/fetch.js';

const CHECKPOINT_DIR = '.redgun/checkpoints';

export function saveCheckpoint(origin, moduleIndex, moduleName) {
  if (!existsSync(CHECKPOINT_DIR)) mkdirSync(CHECKPOINT_DIR, { recursive: true });
  const checkpoint = {
    origin,
    moduleIndex,
    moduleName,
    timestamp: new Date().toISOString(),
  };
  writeFileSync(join(CHECKPOINT_DIR, 'latest.json'), JSON.stringify(checkpoint, null, 2));
}

export function loadCheckpoint() {
  const path = join(CHECKPOINT_DIR, 'latest.json');
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, 'utf-8'));
}

export function clearCheckpoint() {
  const path = join(CHECKPOINT_DIR, 'latest.json');
  try { writeFileSync(path, '{}'); } catch {}
}

export async function diffScans(scanA, scanB, spinner) {
  spinner.text = 'Comparing scans...';
  let reportA, reportB;

  try {
    reportA = JSON.parse(readFileSync(scanA, 'utf-8'));
    reportB = JSON.parse(readFileSync(scanB, 'utf-8'));
  } catch {
    addFinding('INFO', 'Diff Mode', 'Could not load scan files', 'One or both scan files are missing/corrupt', 'Verify file paths');
    return;
  }

  const newFindings = reportB.findings.filter(b =>
    !reportA.findings.some(a => a.title === b.title && a.module === b.module)
  );

  const fixedFindings = reportA.findings.filter(a =>
    !reportB.findings.some(b => a.title === b.title && a.module === b.module)
  );

  const scoreDelta = reportB.score - reportA.score;

  if (newFindings.length > 0) {
    addFinding('INFO', 'Diff Mode', `${newFindings.length} new findings since last scan`,
      `New: ${newFindings.map(f => f.title).join(', ').substring(0, 200)}`,
      'Investigate new findings for recent regressions');
  }

  if (fixedFindings.length > 0) {
    addFinding('INFO', 'Diff Mode', `${fixedFindings.length} findings fixed since last scan`,
      `Fixed: ${fixedFindings.map(f => f.title).join(', ').substring(0, 200)}`,
      'Good work — these issues are no longer detected');
  }

  if (scoreDelta !== 0) {
    const sign = scoreDelta > 0 ? '+' : '';
    addFinding('INFO', 'Diff Mode', `Score delta: ${sign}${scoreDelta} (${reportA.score} → ${reportB.score})`,
      `Scan A: ${reportA.score}/100 | Scan B: ${reportB.score}/100`,
      scoreDelta > 0 ? 'Score improved — security posture is better' : 'Score decreased — investigate new findings');
  }

  if (newFindings.length === 0 && fixedFindings.length === 0) {
    addFinding('INFO', 'Diff Mode', 'No changes between scans', 'Identical findings in both scan reports', 'Security posture unchanged');
  }
}

export async function fuzzEndpoints(origin, spinner) {
  const wordlist = [
    'admin', 'api', 'backup', 'config', 'dashboard', 'debug', 'dev', 'login', 'register',
    'test', 'wp-admin', 'uploads', 'assets', 'static', 'css', 'js', 'images', 'img',
    'docs', 'documentation', 'downloads', 'logs', 'temp', 'tmp', 'cache', 'old',
    'backup.zip', 'backup.sql', 'dump.sql', 'database.sql', 'db.sql',
    'admin.php', 'login.php', 'config.php', 'info.php', 'test.php',
    'console', 'graphql', 'graphiql', 'swagger', 'api-docs', 'openapi',
    'actuator', 'actuator/health', 'actuator/env', 'actuator/mappings',
    'wp-json', 'wp-content', 'wp-includes', 'xmlrpc.php',
    '.env', '.env.backup', '.env.local', '.env.production',
    '.git/config', '.git/HEAD', '.DS_Store', '.htaccess',
    'phpmyadmin', 'phpinfo.php', 'server-status', 'server-info',
    'sitemap.xml', 'robots.txt', 'crossdomain.xml', 'security.txt',
    'web.config', 'package.json', 'package-lock.json', 'composer.json',
    '.well-known/security.txt', '.well-known/openid-configuration',
    'api/v1', 'api/v2', 'api/v3', 'api/auth', 'api/users', 'api/admin',
    'v1', 'v2', 'rest', 'rest/api', 'api/rest',
    'jenkins', 'gitlab', 'sonarqube', 'nexus', 'artifactory',
    'monitoring', 'metrics', 'health', 'status', 'healthcheck',
  ];

  let found = 0;
  for (let i = 0; i < wordlist.length; i++) {
    const path = wordlist[i];
    if (i % 5 === 0) spinner.text = `[Fuzzer] ${found} found — ${path}`;

    try {
      const resp = await fetchText(`${origin}/${path}`, {}, 3000);
      if (resp.status !== 404 && resp.status !== 500 && resp.body.length > 50) {
        found++;

        const severity = /\benv\b|\.git|backup\.sql|phpmyadmin|actuator|jenkins/i.test(path)
          ? 'HIGH' : /admin|config|debug|console/i.test(path) ? 'MEDIUM' : 'LOW';

        addFinding(severity, 'Fuzzer', `Discovered: /${path} (${resp.status})`,
          `${origin}/${path} returned ${resp.status} (${resp.body.length}B)`,
          /admin|config|backup/i.test(path) ? 'Restrict access to this path. Requires authentication.' : 'Review this path for sensitive information exposure');
      }
    } catch {}
  }

  spinner.text = `Fuzzer complete: ${found} endpoints found`;
  return found;
}

export function exportBurpXml(origin, findings, outputPath = './scans/burp-export.xml') {
  if (!existsSync('./scans')) mkdirSync('./scans', { recursive: true });

  let xml = '<?xml version="1.0" encoding="UTF-8"?>\n<issues>\n';
  for (const f of findings) {
    xml += `  <issue>
    <type>5245344</type>
    <name>${esc(f.module)}: ${esc(f.title)}</name>
    <host>${esc(origin)}</host>
    <path>/</path>
    <severity>${f.severity}</severity>
    <confidence>${f.confidence || 'Certain'}</confidence>
    <requestResponse>
      <request><![CDATA[]]></request>
      <response><![CDATA[]]></response>
    </requestResponse>
    <detail>${esc((f.details || '') + (f.validationNote ? '\nValidation: ' + f.validationNote : ''))}</detail>
    <remediation>${esc(f.fix || '')}</remediation>
  </issue>\n`;
  }
  xml += '</issues>';

  writeFileSync(outputPath, xml);
  return outputPath;
}

function esc(s) {
  if (!s) return '';
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
