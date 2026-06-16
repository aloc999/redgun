import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';
import { XSS_PATTERNS, SQLI_PATTERNS } from '../utils/patterns.js';

const SCAN_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.vue', '.svelte', '.php', '.py', '.rb'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '.next', '.nuxt', '__pycache__', 'vendor', 'coverage'];

export async function auditCodeVulnerabilities(projectPath, spinner) {
  spinner.text = 'Scanning for code vulnerabilities (SQLi, XSS, eval)...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      for (const pattern of SQLI_PATTERNS) {
        const regex = new RegExp(pattern.source, pattern.flags);
        let match;
        while ((match = regex.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          addFinding(
            'CRITICAL',
            'Code Vulnerabilities',
            'SQL Injection - user input in query',
            `File: ${relativePath}:${lineNum}\nCode: ${lines[lineNum - 1]?.trim().substring(0, 100)}`,
            'Use parameterized queries or prepared statements. Never concatenate user input into SQL.'
          );
        }
      }

      for (const pattern of XSS_PATTERNS) {
        const regex = new RegExp(pattern.source, pattern.flags);
        let match;
        while ((match = regex.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          addFinding(
            'HIGH',
            'Code Vulnerabilities',
            'XSS - unsafe HTML rendering',
            `File: ${relativePath}:${lineNum}\nCode: ${lines[lineNum - 1]?.trim().substring(0, 100)}`,
            'Sanitize user input before rendering as HTML. Use DOMPurify or framework-native sanitization.'
          );
        }
      }

      const evalPattern = /\beval\s*\(\s*(?!['"`])/g;
      let evalMatch;
      while ((evalMatch = evalPattern.exec(content)) !== null) {
        const lineNum = content.substring(0, evalMatch.index).split('\n').length;
        addFinding(
          'HIGH',
          'Code Vulnerabilities',
          'Dangerous eval() with dynamic input',
          `File: ${relativePath}:${lineNum}`,
          'Avoid eval(). Use JSON.parse() for data, or Function constructor with strict validation.'
        );
      }

      const regexDosPattern = /new\s+RegExp\s*\(\s*(?:req|params|query|body|user)/gi;
      let regexMatch;
      while ((regexMatch = regexDosPattern.exec(content)) !== null) {
        const lineNum = content.substring(0, regexMatch.index).split('\n').length;
        addFinding(
          'MEDIUM',
          'Code Vulnerabilities',
          'ReDoS - user input in RegExp constructor',
          `File: ${relativePath}:${lineNum}`,
          'Never create regex from user input. If needed, use a safe-regex library to validate patterns.'
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
        else if (SCAN_EXTENSIONS.includes(extname(entry).toLowerCase()) && stat.size < 512 * 1024) {
          files.push(fullPath);
        }
      } catch {}
    }
  } catch {}
  return files;
}
