import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';

const SCAN_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.py', '.rb', '.php', '.go', '.java'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '__pycache__', 'vendor'];

export async function auditCsrf(projectPath, spinner) {
  spinner.text = 'Analyzing CSRF token implementation...';
  const files = getFiles(projectPath);
  let hasCsrfLib = false;
  let hasSameSite = false;

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      if (/csurf|csrf|lusca|csrf-token|csrf_token/i.test(content)) hasCsrfLib = true;
      if (/sameSite\s*[:=]\s*['"](?:strict|lax)['"]/i.test(content)) hasSameSite = true;

      const patterns = [
        { pattern: /(?:csrf|_token).*\s*=\s*(?:Math\.random|Date\.now|uuid)/gi, name: 'CSRF token from predictable source', severity: 'HIGH' },
        { pattern: /(?:csrf|token).*\s*=\s*['"][a-zA-Z0-9]{1,8}['"]/gi, name: 'Short CSRF token (< 8 chars, brute-forceable)', severity: 'HIGH' },
        { pattern: /csrf\s*=\s*(?:null|undefined|false|skip|disabled?)/gi, name: 'CSRF protection disabled', severity: 'HIGH' },
        { pattern: /(?:bypass|ignore|skip).*csrf/gi, name: 'CSRF bypass condition', severity: 'MEDIUM' },
        { pattern: /csrf\s*\(\)\s*:\s*(?:false|disabled)/gi, name: 'CSRF middleware disabled', severity: 'HIGH' },
        { pattern: /sameSite\s*[:=]\s*['"]none['"]/gi, name: 'SameSite=None with Secure flag?', severity: 'LOW' },
        { pattern: /X-CSRF-Token|X-CSRFToken|X-XSRF-TOKEN/gi, name: 'CSRF token in custom header (SOP-safe)', severity: 'INFO' },
        { pattern: /csrf\s*:\s*false/gi, name: 'CSRF explicitly disabled', severity: 'CRITICAL' },
        { pattern: /csrf\s*\(\s*\)\s*\{[^}]*ignore:/gi, name: 'CSRF with ignore list', severity: 'MEDIUM' },
        { pattern: /csrf.*ignoreMethods\s*:\s*\[['"]GET['"]\s*,\s*['"]HEAD['"]/gi, name: 'CSRF ignores GET/HEAD (standard)', severity: 'INFO' },
      ];

      for (const { pattern, name, severity } of patterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          addFinding(
            severity,
            'CSRF Analysis',
            name,
            `File: ${relativePath}:${lineNum}\nCode: ${lines[lineNum - 1]?.trim().substring(0, 100)}`,
            'Use cryptographically secure random CSRF tokens (64+ bits). Use SameSite=Lax or Strict cookies. Send CSRF tokens in custom headers (not cookies). Use Double Submit Cookie pattern: match cookie & header token values.'
          );
        }
      }
    } catch {}
  }

  if (!hasCsrfLib) {
    addFinding('HIGH', 'CSRF Analysis', 'No CSRF library detected', 'No CSRF protection package (csurf, csrf, lusca) found in code', 'Install csurf/lusca and add CSRF middleware to all state-changing routes');
  }

  if (!hasSameSite) {
    addFinding('LOW', 'CSRF Analysis', 'No SameSite cookie attribute configured', 'SameSite not set on session cookies', 'Set SameSite=Lax or SameSite=Strict on session cookies');
  }
}

function getFiles(dir, files = []) {
  try {
    const entries = readdirSync(dir);
    for (const entry of entries) {
      if (IGNORE_DIRS.includes(entry) || entry.startsWith('.')) continue;
      const fullPath = join(dir, entry);
      try {
        const stat = statSync(fullPath);
        if (stat.isDirectory()) getFiles(fullPath, files);
        else if (SCAN_EXTENSIONS.includes(extname(entry).toLowerCase()) && stat.size < 512 * 1024) files.push(fullPath);
      } catch {}
    }
  } catch {}
  return files;
}
