import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';
import { JWT_PATTERNS } from '../utils/patterns.js';

const SCAN_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.py', '.rb', '.php', '.go', '.java'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '__pycache__', 'vendor'];

export async function auditJwt(projectPath, spinner) {
  spinner.text = 'Scanning for JWT vulnerabilities (HackTricks)...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      for (const pattern of JWT_PATTERNS) {
        const regex = new RegExp(pattern.source, pattern.flags);
        let match;
        while ((match = regex.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          const matchText = match[0];

          let severity = 'HIGH';
          let title = 'JWT security issue';

          if (/none/i.test(matchText)) {
            severity = 'CRITICAL';
            title = 'JWT algorithm "none" attack - signature bypass';
          } else if (/verify.*false/i.test(matchText)) {
            severity = 'CRITICAL';
            title = 'JWT verification disabled';
          } else if (/ignoreExpiration.*true/i.test(matchText)) {
            severity = 'HIGH';
            title = 'JWT expiration check disabled';
          } else if (/jwt\.decode/i.test(matchText)) {
            severity = 'MEDIUM';
            title = 'JWT decoded without verification';
          } else if (/HS256/i.test(matchText)) {
            severity = 'MEDIUM';
            title = 'JWT uses HS256 - vulnerable to key confusion if RS256 expected';
          }

          addFinding(
            severity,
            'JWT Attacks (HackTricks)',
            title,
            `File: ${relativePath}:${lineNum}\nCode: ${lines[lineNum - 1]?.trim().substring(0, 120)}`,
            'Always verify JWT signatures. Use RS256/ES256 for asymmetric signing. Never use algorithm "none". Set and enforce expiration. Use a well-tested JWT library.'
          );
        }
      }

      const weakSecret = /(?:jwt|token).*secret\s*[:=]\s*['"][^'"]{1,16}['"]/gi;
      let secretMatch;
      while ((secretMatch = weakSecret.exec(content)) !== null) {
        const lineNum = content.substring(0, secretMatch.index).split('\n').length;
        addFinding(
          'HIGH',
          'JWT Attacks (HackTricks)',
          'Weak JWT signing secret (< 16 chars)',
          `File: ${relativePath}:${lineNum}`,
          'Use a strong secret (256+ bits). Store in environment variable. Consider asymmetric signing (RS256).'
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
