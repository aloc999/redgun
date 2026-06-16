import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';

const SCAN_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.html', '.htm', '.vue', '.svelte', '.astro'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '__pycache__', 'vendor'];

export async function auditPostMessage(projectPath, spinner) {
  spinner.text = 'Scanning for PostMessage/BroadcastChannel vulnerabilities...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      const patterns = [
        { pattern: /addEventListener\s*\(\s*['"]message['"]\s*(?!.*\.origin)/gi, name: 'message listener without origin check', severity: 'CRITICAL' },
        { pattern: /addEventListener\s*\(\s*['"]message['"]\s*,\s*\([^)]*\)\s*=>\s*\{(?!.*origin)/gi, name: 'postMessage handler arrow fn without origin validation', severity: 'CRITICAL' },
        { pattern: /postMessage\s*\(\s*[^,]*\s*,\s*['"]\*['"]/gi, name: 'postMessage with wildcard targetOrigin *', severity: 'HIGH' },
        { pattern: /event\.origin\s*\.includes|event\.origin\s*\.endsWith|event\.origin\s*\.startsWith/gi, name: 'origin check using includes/endsWith (substring bypass)', severity: 'HIGH' },
        { pattern: /event\.origin\s*===\s*['"]https:\/\/[^'"]*['"]/gi, name: 'Strict origin comparison (good)', severity: 'INFO' },
        { pattern: /eval\s*\(\s*event\.data|innerHTML\s*=\s*event\.data|document\.write\s*\(\s*event\.data/gi, name: 'postMessage data used dangerously', severity: 'CRITICAL' },
        { pattern: /new\s+BroadcastChannel\s*\(/gi, name: 'BroadcastChannel created (broadcast to all same-origin tabs)', severity: 'MEDIUM' },
        { pattern: /new\s+MessageChannel\s*\(/gi, name: 'MessageChannel created (check port1/port2 exposure)', severity: 'LOW' },
        { pattern: /window\.opener\.postMessage|parent\.postMessage|top\.postMessage/gi, name: 'Cross-window postMessage (check origin)', severity: 'MEDIUM' },
        { pattern: /iframe.*contentWindow\.postMessage|iframe.*\.src/gi, name: 'Iframe postMessage interaction', severity: 'MEDIUM' },
        { pattern: /window\.open\s*\(\s*['"`].*['"`]\s*\)/gi, name: 'window.open (tabnabbing if no opener policy)', severity: 'LOW' },
      ];

      for (const { pattern, name, severity } of patterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          const line = lines[lineNum - 1]?.trim() || '';
          if (line.startsWith('//') || line.startsWith('#') || line.startsWith('*')) continue;

          addFinding(
            severity,
            'PostMessage / BroadcastChannel',
            name,
            `File: ${relativePath}:${lineNum}\nCode: ${line.substring(0, 120)}`,
            'Always validate event.origin with strict equality. Use a whitelist, not includes/endsWith. Never evaluate event.data as code. Use BroadcastChannel with user validation. For window.open, set opener=null and use noopener/noreferrer.'
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
