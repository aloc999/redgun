import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';
import { SSRF_PATTERNS } from '../utils/patterns.js';

const SCAN_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.py', '.rb', '.php', '.go', '.java'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '.next', '__pycache__', 'vendor'];

export async function auditSsrf(projectPath, spinner) {
  spinner.text = 'Scanning for SSRF vulnerabilities (HackTricks)...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      for (const pattern of SSRF_PATTERNS) {
        const regex = new RegExp(pattern.source, pattern.flags);
        let match;
        while ((match = regex.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          addFinding(
            'CRITICAL',
            'SSRF (HackTricks)',
            'Server-Side Request Forgery - user-controlled URL',
            `File: ${relativePath}:${lineNum}\nCode: ${lines[lineNum - 1]?.trim().substring(0, 120)}`,
            'Validate and whitelist allowed URLs/domains. Block internal IPs (127.0.0.1, 10.x, 169.254.169.254). Use URL parsing to prevent bypasses like http://127.0.0.1@evil.com'
          );
        }
      }

      const urlFetchPatterns = [
        /(?:url|uri|link|href|src|endpoint|webhook|callback|redirect|proxy|forward)\s*=\s*(?:req|params|query|body)/gi,
        /(?:image|avatar|icon|logo|file)_?(?:url|uri)\s*=\s*(?:req|params|query|body)/gi,
      ];

      for (const pattern of urlFetchPatterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          addFinding(
            'HIGH',
            'SSRF (HackTricks)',
            'User-controlled URL parameter (potential SSRF)',
            `File: ${relativePath}:${lineNum}\nPattern: ${match[0].substring(0, 80)}`,
            'Implement URL validation: whitelist allowed protocols (http/https only), block private IP ranges, use DNS resolution checks, consider using a proxy with egress filtering.'
          );
        }
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
