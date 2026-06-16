import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';
import { SECRET_PATTERNS } from '../utils/patterns.js';

const SCAN_EXTENSIONS = [
  '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs',
  '.py', '.rb', '.php', '.go', '.java', '.cs',
  '.vue', '.svelte', '.astro', '.html', '.yml', '.yaml',
  '.json', '.toml', '.cfg', '.conf', '.ini',
];

const IGNORE_DIRS = [
  'node_modules', '.git', 'dist', 'build', '.next', '.nuxt',
  '__pycache__', 'venv', '.venv', 'vendor', 'target',
  '.cache', 'coverage', '.output',
];

export async function auditSecrets(projectPath, spinner) {
  spinner.text = 'Scanning for hardcoded secrets...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const lines = content.split('\n');

      for (const [name, pattern] of Object.entries(SECRET_PATTERNS)) {
        const regex = new RegExp(pattern.source, pattern.flags);
        let match;
        while ((match = regex.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          const line = lines[lineNum - 1]?.trim() || '';

          if (isComment(line)) continue;
          if (isTestOrExample(file)) continue;

          const severity = getSeverity(name);
          const relativePath = file.replace(projectPath, '.');
          addFinding(
            severity,
            'Code Secrets',
            `${name} found in source code`,
            `File: ${relativePath}:${lineNum}\nValue: ${maskSecret(match[0])}`,
            `Move this secret to environment variables. Use .env files (not committed) and access via process.env.`
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
      if (IGNORE_DIRS.includes(entry)) continue;
      if (entry.startsWith('.') && entry !== '.env.example') continue;

      const fullPath = join(dir, entry);
      try {
        const stat = statSync(fullPath);
        if (stat.isDirectory()) {
          getFiles(fullPath, files);
        } else if (SCAN_EXTENSIONS.includes(extname(entry).toLowerCase())) {
          if (stat.size < 1024 * 1024) files.push(fullPath);
        }
      } catch {}
    }
  } catch {}
  return files;
}

function isComment(line) {
  return line.startsWith('//') || line.startsWith('#') || line.startsWith('*') || line.startsWith('/*');
}

function isTestOrExample(file) {
  return /\.(test|spec|example|sample|mock)\./i.test(file) || /__(tests?|mocks?)__/i.test(file);
}

function getSeverity(name) {
  if (/private key|service.role|secret.key|aws.secret/i.test(name)) return 'CRITICAL';
  if (/stripe|database|openai|anthropic/i.test(name)) return 'HIGH';
  if (/password|token/i.test(name)) return 'HIGH';
  return 'MEDIUM';
}

function maskSecret(value) {
  if (value.length <= 8) return '***';
  return value.substring(0, 4) + '...' + value.substring(value.length - 4);
}
