import { readFileSync, existsSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';

const SCAN_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.py', '.rb', '.php'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '.next'];

export async function auditAuth(projectPath, spinner) {
  spinner.text = 'Checking auth & middleware configuration...';
  const files = getFiles(projectPath);
  let hasRateLimit = false;
  let hasCors = false;
  let hasCsrf = false;
  let hasHelmet = false;

  const packagePath = join(projectPath, 'package.json');
  if (existsSync(packagePath)) {
    try {
      const pkg = JSON.parse(readFileSync(packagePath, 'utf-8'));
      const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
      hasRateLimit = !!allDeps['express-rate-limit'] || !!allDeps['rate-limiter-flexible'];
      hasCors = !!allDeps['cors'];
      hasCsrf = !!allDeps['csurf'] || !!allDeps['csrf'] || !!allDeps['lusca'];
      hasHelmet = !!allDeps['helmet'];
    } catch {}
  }

  if (!hasRateLimit) {
    addFinding(
      'HIGH',
      'Auth & Middleware',
      'No rate limiting detected',
      'No rate-limit package found in dependencies',
      'Install express-rate-limit or rate-limiter-flexible to prevent brute-force attacks'
    );
  }

  if (!hasCsrf) {
    addFinding(
      'MEDIUM',
      'Auth & Middleware',
      'No CSRF protection detected',
      'No CSRF package found in dependencies',
      'Implement CSRF tokens using csurf or lusca middleware'
    );
  }

  if (!hasHelmet) {
    addFinding(
      'MEDIUM',
      'Auth & Middleware',
      'No helmet (security headers) detected',
      'Helmet package not found in dependencies',
      'Install helmet to set secure HTTP headers automatically'
    );
  }

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');

      if (/cors\(\s*\{\s*origin\s*:\s*['"`]\*['"`]/gi.test(content) || /cors\(\s*\)/g.test(content)) {
        addFinding(
          'MEDIUM',
          'Auth & Middleware',
          'CORS wildcard origin detected',
          `File: ${relativePath}`,
          'Restrict CORS origin to specific trusted domains instead of using wildcard *'
        );
      }

      if (/session\s*\(\s*\{[^}]*secret\s*:\s*['"][^'"]{1,8}['"]/gi.test(content)) {
        addFinding(
          'HIGH',
          'Auth & Middleware',
          'Weak session secret',
          `File: ${relativePath}`,
          'Use a strong, random session secret (at least 32 characters) from environment variables'
        );
      }

      if (/(?:expiresIn|exp)\s*:\s*['"]?\d{5,}['"]?/gi.test(content)) {
        addFinding(
          'LOW',
          'Auth & Middleware',
          'Long JWT/session expiration',
          `File: ${relativePath}`,
          'Consider shorter token expiration with refresh token rotation'
        );
      }

      const hardcodedPwdPattern = /(?:password|passwd)\s*(?:===?|!==?)\s*['"][^'"]+['"]/gi;
      if (hardcodedPwdPattern.test(content)) {
        addFinding(
          'CRITICAL',
          'Auth & Middleware',
          'Hardcoded password comparison',
          `File: ${relativePath}`,
          'Never hardcode passwords. Use bcrypt/argon2 hash comparison against stored hashes.'
        );
      }
    } catch {}
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
