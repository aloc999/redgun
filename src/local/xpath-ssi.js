import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';

const SCAN_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.py', '.rb', '.php', '.go', '.java'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '__pycache__', 'vendor'];

export async function auditXpathSsi(projectPath, spinner) {
  spinner.text = 'Scanning for XPath & SSI injection...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      const patterns = [
        { pattern: /XPath\.evaluate\s*\(\s*(?:req|request|params|query|body|user)/gi, name: 'XPath evaluate with user input', severity: 'CRITICAL' },
        { pattern: /xpath\.select\s*\(\s*(?:req|request|params|query|body)/gi, name: 'XPath select with user input', severity: 'CRITICAL' },
        { pattern: /(?:find|query|select)\s*\(\s*['"`]\/\/(?:\w+::)?(\w+)\[.*\$\{/gi, name: 'XPath query with template literal', severity: 'CRITICAL' },
        { pattern: /(?:find|query|select)\s*\(\s*['"`]\/\/(?:\w+::)?(\w+)\[.*\+/gi, name: 'XPath query with concatenated input', severity: 'CRITICAL' },
        { pattern: /SimpleXMLElement.*xpath\s*\(\s*\$_(?:GET|POST|REQUEST)/gi, name: 'PHP SimpleXML xpath user input', severity: 'CRITICAL' },
        { pattern: /DOMXPath.*query\s*\(\s*\$_(?:GET|POST|REQUEST)/gi, name: 'PHP DOMXPath query user input', severity: 'CRITICAL' },
        { pattern: /xpath\.compile\s*\(\s*(?:req|request|input)/gi, name: 'XPath compile with user input', severity: 'HIGH' },
        { pattern: /<!--#\s*(?:include|exec|echo|fsize|flastmod|config)/gi, name: 'Server-Side Includes (SSI) in templates', severity: 'HIGH' },
        { pattern: /<!--#echo\s+var|<!--#include\s+(?:virtual|file)|<!--#exec/gi, name: 'SSI directives in source', severity: 'CRITICAL' },
        { pattern: /(?:shtml|stm|shtm)/gi, name: 'SSI file extension (.shtml)', severity: 'MEDIUM' },
        { pattern: /Options\s+\+Includes|AddHandler.*server-parsed/gi, name: 'Apache SSI enabled', severity: 'LOW' },
        { pattern: /(?:include|exec|echo)\s*\(\s*(?:req|request|params|input)/gi, name: 'Server include with user input', severity: 'CRITICAL' },
      ];

      for (const { pattern, name, severity } of patterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          const line = lines[lineNum - 1]?.trim() || '';
          if (line.startsWith('//') || line.startsWith('#') || line.startsWith('*')) continue;

          addFinding(
            severity,
            'XPath / SSI Injection',
            name,
            `File: ${relativePath}:${lineNum}\nCode: ${line.substring(0, 120)}`,
            'Use parameterized XPath queries. Sanitize input against special chars (, ), [, ], :, *, /, @, !, =, >, <. Disable SSI unless needed (Options -Includes). Never pass user input to SSI directives.'
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
