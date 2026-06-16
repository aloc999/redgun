import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';

const SCAN_EXTENSIONS = ['.js', '.ts', '.css', '.scss', '.less', '.html', '.htm', '.jsx', '.tsx', '.vue', '.svelte', '.astro'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '__pycache__', 'vendor'];

export async function auditCssInjection(projectPath, spinner) {
  spinner.text = 'Scanning for CSS injection/exfiltration vectors...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      const patterns = [
        { pattern: /style\s*=\s*(?:req|request|params|query|body|user|input)/gi, name: 'Inline style from user input', severity: 'HIGH' },
        { pattern: /(<style[^>]*>).*\$\{.*(?:req|params|body|input)/gi, name: 'Style tag with user input', severity: 'HIGH' },
        { pattern: /css\s*[(`]\$\{/gi, name: 'CSS template literal with user input', severity: 'MEDIUM' },
        { pattern: /(\[class(?:\^|\*|\$)?=(["']?)[^\]]*["']?\]|attr\(|content:\s*attr)/gi, name: 'CSS attribute selector (data exfiltration)', severity: 'MEDIUM' },
        { pattern: /@font-face\s*\{[^}]*src:\s*url\s*\(/gi, name: '@font-face with external URL (char-by-char exfil)', severity: 'HIGH' },
        { pattern: /@import\s+url\s*\(.*\);/gi, name: 'CSS @import (external CSS injection)', severity: 'MEDIUM' },
        { pattern: /background(?:-image)?:\s*url\s*\(/gi, name: 'CSS background-image (exfiltration channel)', severity: 'MEDIUM' },
        { pattern: /::?value|::-webkit-input-placeholder|::-moz-placeholder/gi, name: 'CSS pseudo-element selectors', severity: 'LOW' },
        { pattern: /unicode-range|U\+/gi, name: 'CSS unicode-range (char exfiltration via font)', severity: 'HIGH' },
        { pattern: /animation-name|keyframes|animation-duration/gi, name: 'CSS animations (timing-based exfiltration)', severity: 'LOW' },
        { pattern: /content\s*:\s*attr\s*\([^)]*\)/gi, name: 'CSS content: attr() (attribute exfiltration)', severity: 'HIGH' },
        { pattern: /input\[type=(["']?)password["']?\].*background-image|input\[type=(["']?)password["']?\].*@font-face/gi, name: 'CSS keylogger pattern (password exfiltration)', severity: 'CRITICAL' },
      ];

      for (const { pattern, name, severity } of patterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          const line = lines[lineNum - 1]?.trim() || '';
          if (line.startsWith('//') || line.startsWith('#') || line.startsWith('*')) continue;

          addFinding(
            severity,
            'CSS Injection/Exfiltration',
            name,
            `File: ${relativePath}:${lineNum}\nCode: ${line.substring(0, 120)}`,
            'Sanitize user input reflected in CSS/style attributes. Use strict CSP with nonce/hash (not unsafe-inline). For CSS exfiltration: limit input length, use content-based exfil detection, disable @font-face loading from external sources.'
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
