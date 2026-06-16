import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';

const SCAN_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.html', '.htm'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '__pycache__', 'vendor'];

export async function auditServiceWorker(projectPath, spinner) {
  spinner.text = 'Scanning for Service Worker abuse vectors...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      const patterns = [
        { pattern: /navigator\.serviceWorker\.register\s*\(/gi, name: 'Service Worker registration', severity: 'INFO' },
        { pattern: /importScripts\s*\(/gi, name: 'Service Worker importScripts (XSS via sw)', severity: 'HIGH' },
        { pattern: /self\.addEventListener\s*\(\s*['"]fetch['"]/gi, name: 'Service Worker fetch listener', severity: 'INFO' },
        { pattern: /self\.addEventListener\s*\(\s*['"]message['"]/gi, name: 'Service Worker message listener (postMessage attack)', severity: 'MEDIUM' },
        { pattern: /respondWith\s*\(\s*fetch\s*\(\s*event\.request\s*\)/gi, name: 'SW passthrough fetch (check URL rewriting)', severity: 'MEDIUM' },
        { pattern: /event\.respondWith\s*\(\s*new\s+Response/gi, name: 'SW custom response (check for content injection)', severity: 'MEDIUM' },
        { pattern: /CacheStorage|self\.caches\s*\./gi, name: 'Cache API usage (cache poisoning via SW)', severity: 'LOW' },
        { pattern: /Clients\.claim\s*\(\s*\)|self\.clients\.claim/gi, name: 'Service Worker immediate claim (malicious takeover)', severity: 'HIGH' },
        { pattern: /self\.skipWaiting/gi, name: 'SW skipWaiting (immediate activation)', severity: 'MEDIUM' },
        { pattern: /navigator\.serviceWorker\.getRegistration|navigator\.serviceWorker\.controller/gi, name: 'SW control check', severity: 'INFO' },
        { pattern: /self\.registration\.unregister/gi, name: 'SW unregistration', severity: 'LOW' },
        { pattern: /PushManager|pushManager\.subscribe|showNotification/gi, name: 'Push notifications (notification spam vector)', severity: 'LOW' },
      ];

      for (const { pattern, name, severity } of patterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          addFinding(
            severity,
            'Service Worker / WebRTC',
            name,
            `File: ${relativePath}:${lineNum}\nCode: ${lines[lineNum - 1]?.trim().substring(0, 120)}`,
            'Restrict Service Worker scope (/). Use importScripts from same-origin only. Validate fetch events to prevent response tampering. Monitor dangerously overwritable headers. Limit Cache API usage to prevent storage exhaustion.'
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
