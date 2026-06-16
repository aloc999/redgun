import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';

const SCAN_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.py', '.rb', '.php', '.java', '.go', '.cs'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '__pycache__', 'vendor'];

export async function auditLdap(projectPath, spinner) {
  spinner.text = 'Scanning for LDAP injection...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      const patterns = [
        { pattern: /ldap\.(?:search|query|compare|modify)\s*\(\s*[^,]*,\s*(?:req|request|params|query|body|user|input|data)/gi, name: 'LDAP query with user input', severity: 'CRITICAL' },
        { pattern: /LDAP.*(?:filter|query)\s*[:=]\s*(?:req|request|params|query|body|user)\s*\+/gi, name: 'LDAP filter concatenation with user input', severity: 'CRITICAL' },
        { pattern: /ldap\.search\s*\(\s*[^,]*,\s*['"`][^'"`]*\$\{/gi, name: 'LDAP search with template literal user input', severity: 'CRITICAL' },
        { pattern: /ldap\.search\s*\(\s*[^,]*,\s*['"`][^'"`]*\+/gi, name: 'LDAP search with concatenated input', severity: 'CRITICAL' },
        { pattern: /(?:authenticate|ldap_auth|ldapauth|active.?directory)\s*\(\s*(?:req|request|params|query|body)/gi, name: 'LDAP auth with user-controlled filter', severity: 'CRITICAL' },
        { pattern: /ldap\.escape\s*\(\s*\)|ldap\.escapeFilter/gi, name: 'LDAP escaping used (good practice)', severity: 'INFO' },
        { pattern: /(?:ldap|AD|active.?directory).*(?:filter|query|search).*['"`]\s*\+/gi, name: 'LDAP filter concatenation detected', severity: 'HIGH' },
        { pattern: /(?:uid|cn|mail|samaccountname)\s*=\s*(?:req|request|params|query|body)/gi, name: 'LDAP attribute from user input', severity: 'HIGH' },
        { pattern: /ActiveDirectory\s*\(\s*\{/gi, name: 'Active Directory configuration', severity: 'INFO' },
        { pattern: /ldapjs|passport-ldap|ldapts|node-ldap/gi, name: 'LDAP library usage', severity: 'INFO' },
        { pattern: /(?:ldap|AD|active.?directory).*(?:URI|URL|host|server)\s*[:=]\s*['"][^'"]*['"]/gi, name: 'LDAP server config hardcoded', severity: 'LOW' },
        { pattern: /(?:ssl|tls|starttls|ldaps).*(?:false|disabled?|no|none)/gi, name: 'LDAP without TLS/SSL', severity: 'HIGH' },
      ];

      for (const { pattern, name, severity } of patterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          const line = lines[lineNum - 1]?.trim() || '';
          if (line.startsWith('//') || line.startsWith('#') || line.startsWith('*')) continue;

          addFinding(
            severity,
            'LDAP Injection',
            name,
            `File: ${relativePath}:${lineNum}\nCode: ${line.substring(0, 120)}`,
            'Never concatenate user input into LDAP filters. Use parameterized LDAP queries or a safe LDAP query builder. Escape special characters (*, (, ), \\, /, &, |, !, =, <, >, ~, #) with ldap.escapeFilter(). Use LDAPS (LDAP over TLS) instead of plain LDAP.'
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
