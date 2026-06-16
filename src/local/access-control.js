import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';

const SCAN_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.py', '.rb', '.php', '.go', '.java'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '__pycache__', 'vendor'];

export async function auditAccessControl(projectPath, spinner) {
  spinner.text = 'Scanning for access control vulnerabilities (PortSwigger)...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      const patterns = [
        { pattern: /(?:req|request)\.(?:params|query|body)\.\s*(?:user_?id|userId|uid|owner_?id|account_?id)/gi, name: 'IDOR - user ID from request parameters', severity: 'HIGH' },
        { pattern: /(?:isAdmin|is_admin|role)\s*[:=]\s*(?:req|request|params|query|body)/gi, name: 'Role/privilege from user input', severity: 'CRITICAL' },
        { pattern: /(?:if|when)\s*\(\s*(?:req|request)\.(?:headers|query|params)\[?\s*['"]?(?:x-admin|admin|role|is[-_]?admin)/gi, name: 'Admin check via client-controlled header/param', severity: 'CRITICAL' },
        { pattern: /\.findById\s*\(\s*(?:req|params|query|body)\./gi, name: 'Direct object reference without ownership check', severity: 'HIGH' },
        { pattern: /\.findOne\s*\(\s*\{\s*(?:_id|id)\s*:\s*(?:req|params|query|body)\./gi, name: 'Database lookup by user-supplied ID (potential IDOR)', severity: 'HIGH' },
        { pattern: /\.delete\s*\(\s*['"`]\/[^'"`]*:id/gi, name: 'DELETE route with :id param (check authorization)', severity: 'MEDIUM' },
        { pattern: /\.put\s*\(\s*['"`]\/[^'"`]*:id/gi, name: 'PUT route with :id param (check authorization)', severity: 'MEDIUM' },
        { pattern: /(?:admin|dashboard|manage|internal).*(?:app\.get|router\.get|@app\.route)/gi, name: 'Admin route - verify middleware protection', severity: 'MEDIUM' },
        { pattern: /res\.json\s*\(\s*(?:users|accounts|orders|payments|transactions)/gi, name: 'Bulk data exposure without filtering', severity: 'MEDIUM' },
        { pattern: /X-Original-URL|X-Rewrite-URL/gi, name: 'URL override headers (access control bypass)', severity: 'HIGH' },
        { pattern: /referer\s*(?:===?|!==?|includes|match)/gi, name: 'Referer-based access control (easily spoofed)', severity: 'HIGH' },
        { pattern: /(?:hidden|type=['"]hidden['"])\s*.*(?:role|admin|privilege|permission)/gi, name: 'Hidden form field for access control', severity: 'HIGH' },
      ];

      for (const { pattern, name, severity } of patterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          addFinding(
            severity,
            'Access Control (PortSwigger)',
            name,
            `File: ${relativePath}:${lineNum}\nCode: ${lines[lineNum - 1]?.trim().substring(0, 120)}`,
            'Implement server-side authorization checks. Verify object ownership on every request. Use middleware for role-based access control. Never trust client-supplied IDs without verifying the requesting user owns that resource.'
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
