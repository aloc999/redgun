import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';
import { PATH_TRAVERSAL_PATTERNS } from '../utils/patterns.js';

const SCAN_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.py', '.rb', '.php', '.go', '.java'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '__pycache__', 'vendor'];

export async function auditPathTraversal(projectPath, spinner) {
  spinner.text = 'Scanning for Path Traversal / LFI (HackTricks)...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      for (const pattern of PATH_TRAVERSAL_PATTERNS) {
        const regex = new RegExp(pattern.source, pattern.flags);
        let match;
        while ((match = regex.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          addFinding(
            'CRITICAL',
            'Path Traversal (HackTricks)',
            'Local File Inclusion - user input in file path',
            `File: ${relativePath}:${lineNum}\nCode: ${lines[lineNum - 1]?.trim().substring(0, 120)}`,
            'Never use user input directly in file paths. Use path.resolve() and verify the resolved path starts with the expected base directory. Strip ../ sequences. Use a whitelist of allowed filenames when possible.'
          );
        }
      }

      const includePatterns = [
        /(?:include|require|require_once|include_once)\s*\(\s*\$_(?:GET|POST|REQUEST)/gi,
        /(?:file_get_contents|fopen|readfile)\s*\(\s*\$_(?:GET|POST|REQUEST)/gi,
        /open\s*\(\s*(?:request\.args|request\.form)/gi,
      ];

      for (const pattern of includePatterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          addFinding(
            'CRITICAL',
            'Path Traversal (HackTricks)',
            'Remote/Local File Inclusion via user input',
            `File: ${relativePath}:${lineNum}`,
            'Never include files based on user input. If needed, use a strict whitelist mapping.'
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
