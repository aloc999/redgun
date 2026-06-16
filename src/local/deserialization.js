import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';
import { DESERIALIZATION_PATTERNS } from '../utils/patterns.js';

const SCAN_EXTENSIONS = ['.js', '.ts', '.py', '.rb', '.php', '.java', '.cs', '.go'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '__pycache__', 'vendor', 'target'];

export async function auditDeserialization(projectPath, spinner) {
  spinner.text = 'Scanning for insecure deserialization (HackTricks)...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      for (const pattern of DESERIALIZATION_PATTERNS) {
        const regex = new RegExp(pattern.source, pattern.flags);
        let match;
        while ((match = regex.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          const line = lines[lineNum - 1]?.trim() || '';
          addFinding(
            'CRITICAL',
            'Deserialization (HackTricks)',
            'Insecure deserialization detected',
            `File: ${relativePath}:${lineNum}\nCode: ${line.substring(0, 120)}\nPattern: ${match[0].substring(0, 60)}`,
            'Never deserialize untrusted data. Use safe alternatives: JSON for data exchange, validate/whitelist classes before deserializing. For Python: use json instead of pickle. For Java: use allowlist-based ObjectInputFilter. For PHP: use json_decode instead of unserialize.'
          );
        }
      }

      const yamlUnsafe = /yaml\.load\s*\([^)]*\)/g;
      let yamlMatch;
      while ((yamlMatch = yamlUnsafe.exec(content)) !== null) {
        if (!content.substring(yamlMatch.index, yamlMatch.index + 100).includes('SafeLoader')) {
          const lineNum = content.substring(0, yamlMatch.index).split('\n').length;
          addFinding(
            'HIGH',
            'Deserialization (HackTricks)',
            'YAML load without SafeLoader',
            `File: ${relativePath}:${lineNum}`,
            'Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader) to prevent arbitrary code execution.'
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
