import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';

const SCAN_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.html', '.htm'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '__pycache__', 'vendor'];

export async function auditClientProto(projectPath, spinner) {
  spinner.text = 'Scanning for client-side prototype pollution gadget chains...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      const patterns = [
        { pattern: /Object\.assign\s*\(\s*\{\}\s*,\s*(?:req|request|params|query|body|input|data)/gi, name: 'Object.assign with user data (proto sink)', severity: 'HIGH' },
        { pattern: /\{\s*\.\.\.(?:req|request|params|query|body|input|data)\s*\}/gi, name: 'Spread operator from user input (proto sink)', severity: 'HIGH' },
        { pattern: /lodash\.merge|_.merge|deepmerge|merge\(.*,\s*(?:req|request|params|body)/gi, name: 'Deep merge with user-controlled data (proto sink)', severity: 'CRITICAL' },
        { pattern: /\$\.extend\s*\(\s*true\s*,/gi, name: 'jQuery $.extend(deep=true) with user data', severity: 'HIGH' },
        { pattern: /angular\.merge|angular\.extend/gi, name: 'AngularJS merge/extend with user data', severity: 'HIGH' },
        { pattern: /Object\.create\s*\(\s*(?:req|request|params|query)/gi, name: 'Object.create with user-controlled prototype', severity: 'MEDIUM' },
        { pattern: /(?:ajax|xhr|fetch)\s*\.(?:response|send|data).*\.(?:extend|merge|assign)/gi, name: 'AJAX response merged into objects', severity: 'MEDIUM' },
        { pattern: /JSON\.parse\s*\([^)]*\)\s*\..*(?:extend|merge|assign)/gi, name: 'Parsed JSON merged into objects', severity: 'HIGH' },
        { pattern: /(?:location\.hash|location\.search|document\.cookie|window\.name)\s*.*(?:extend|merge|assign|parse)/gi, name: 'DOM source merged into objects (proto via URL/cookie)', severity: 'CRITICAL' },
        { pattern: /(?:window|global|self|globalThis)\.Object\.defineProperty/gi, name: 'Object.defineProperty on global (proto tamper)', severity: 'CRITICAL' },
        { pattern: /sanitize-html|dompurify|xss-filters/gi, name: 'XSS filter bypass via proto (gadget target)', severity: 'MEDIUM' },
        { pattern: /Object\.freeze\s*\(\s*Object\.prototype\s*\)/gi, name: 'Object.freeze on prototype (mitigation)', severity: 'INFO' },
      ];

      for (const { pattern, name, severity } of patterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          const line = lines[lineNum - 1]?.trim() || '';
          if (line.startsWith('//') || line.startsWith('#') || line.startsWith('*')) continue;

          addFinding(
            severity,
            'Client-Side Proto Pollution',
            name,
            `File: ${relativePath}:${lineNum}\nCode: ${line.substring(0, 120)}`,
            'Strip __proto__ and constructor.prototype properties before merging. Use Object.create(null) for dictionaries. Freeze Object.prototype if needing global protection. Use JSON schema validation instead of raw merging. Avoid deep merge from untrusted sources.'
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
