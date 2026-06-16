import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';
import { SSTI_PATTERNS } from '../utils/patterns.js';

const SCAN_EXTENSIONS = ['.js', '.ts', '.py', '.rb', '.php', '.java', '.go'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '__pycache__', 'vendor'];

export async function auditSsti(projectPath, spinner) {
  spinner.text = 'Scanning for Server-Side Template Injection (HackTricks)...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      for (const pattern of SSTI_PATTERNS) {
        const regex = new RegExp(pattern.source, pattern.flags);
        let match;
        while ((match = regex.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          addFinding(
            'CRITICAL',
            'SSTI (HackTricks)',
            'Server-Side Template Injection - user input in template',
            `File: ${relativePath}:${lineNum}\nCode: ${lines[lineNum - 1]?.trim().substring(0, 120)}`,
            'Never pass user input directly to template engines. Use template variables/context instead of string concatenation. Sandbox template execution if possible.'
          );
        }
      }

      const additionalPatterns = [
        { pattern: /render\s*\(\s*['"`].*\$\{.*\}.*['"`]/gi, name: 'Template string in render()' },
        { pattern: /Environment\s*\(\s*.*\)\s*.*from_string/gi, name: 'Jinja2 from_string()' },
        { pattern: /Handlebars\.compile\s*\(\s*(?:req|params|query|body)/gi, name: 'Handlebars user template' },
        { pattern: /ejs\.render\s*\(\s*(?:req|params|query|body)/gi, name: 'EJS user template' },
        { pattern: /Velocity\.evaluate/gi, name: 'Apache Velocity evaluate' },
        { pattern: /Freemarker.*\$\{/gi, name: 'Freemarker expression' },
        { pattern: /Thymeleaf.*th:text.*\$\{/gi, name: 'Thymeleaf expression' },
      ];

      for (const { pattern, name } of additionalPatterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          addFinding(
            'HIGH',
            'SSTI (HackTricks)',
            `Potential SSTI via ${name}`,
            `File: ${relativePath}:${lineNum}`,
            'Validate that user input is never used as template source. Use sandboxed environments and restrict template builtins.'
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
