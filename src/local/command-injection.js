import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';
import { COMMAND_INJECTION_PATTERNS } from '../utils/patterns.js';

const SCAN_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.py', '.rb', '.php', '.go', '.java'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '__pycache__', 'vendor'];

export async function auditCommandInjection(projectPath, spinner) {
  spinner.text = 'Scanning for Command Injection (HackTricks)...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      for (const pattern of COMMAND_INJECTION_PATTERNS) {
        const regex = new RegExp(pattern.source, pattern.flags);
        let match;
        while ((match = regex.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          addFinding(
            'CRITICAL',
            'Command Injection (HackTricks)',
            'OS Command Injection - user input in system command',
            `File: ${relativePath}:${lineNum}\nCode: ${lines[lineNum - 1]?.trim().substring(0, 120)}`,
            'Never pass user input to shell commands. Use execFile/spawn with argument arrays instead of exec with string interpolation. Implement strict input validation with allowlists. Consider using libraries that don\'t invoke a shell.'
          );
        }
      }

      const shellPatterns = [
        /os\.system\s*\(\s*f?['"].*\{/gi,
        /subprocess\.(?:call|run|Popen)\s*\(\s*f?['"].*\{/gi,
        /subprocess\.(?:call|run|Popen)\s*\(\s*(?:request|input)/gi,
        /Runtime\.getRuntime\(\)\.exec\s*\(\s*(?:request|input)/gi,
        /Process\.Start\s*\(\s*(?:request|input)/gi,
        /\`[^`]*\$\{.*(?:req|params|query|body|user).*\}[^`]*\`/gi,
      ];

      for (const pattern of shellPatterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          addFinding(
            'CRITICAL',
            'Command Injection (HackTricks)',
            'Shell command with user-controlled input',
            `File: ${relativePath}:${lineNum}\nCode: ${lines[lineNum - 1]?.trim().substring(0, 120)}`,
            'Use parameterized command execution. In Node.js: use execFile() with argument array. In Python: use subprocess with shell=False and list args.'
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
