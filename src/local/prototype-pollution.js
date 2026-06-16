import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';
import { PROTOTYPE_POLLUTION_PATTERNS } from '../utils/patterns.js';

const SCAN_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.mjs'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '.next'];

export async function auditPrototypePollution(projectPath, spinner) {
  spinner.text = 'Scanning for Prototype Pollution (HackTricks)...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      for (const pattern of PROTOTYPE_POLLUTION_PATTERNS) {
        const regex = new RegExp(pattern.source, pattern.flags);
        let match;
        while ((match = regex.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          addFinding(
            'HIGH',
            'Prototype Pollution (HackTricks)',
            'Potential prototype pollution vector',
            `File: ${relativePath}:${lineNum}\nCode: ${lines[lineNum - 1]?.trim().substring(0, 120)}`,
            'Sanitize object keys before merging. Block __proto__, constructor, prototype keys. Use Object.create(null) for dictionary objects. Freeze Object.prototype in critical paths.'
          );
        }
      }

      const recursiveMerge = /function\s+\w*[Mm]erge\s*\([^)]*\)\s*\{[^}]*for\s*\(/g;
      let mergeMatch;
      while ((mergeMatch = recursiveMerge.exec(content)) !== null) {
        const lineNum = content.substring(0, mergeMatch.index).split('\n').length;
        if (!content.substring(mergeMatch.index, mergeMatch.index + 500).includes('__proto__')) {
          addFinding(
            'MEDIUM',
            'Prototype Pollution (HackTricks)',
            'Custom merge function without __proto__ protection',
            `File: ${relativePath}:${lineNum}`,
            'Add __proto__ and constructor.prototype key filtering to custom merge/deep-clone functions.'
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
