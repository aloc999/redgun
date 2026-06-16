import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';

const SCAN_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.py', '.rb', '.php', '.java', '.cs', '.go', '.xml', '.svg'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '__pycache__', 'vendor', 'target'];

export async function auditXxe(projectPath, spinner) {
  spinner.text = 'Scanning for XXE vulnerabilities (PortSwigger)...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      const xxePatterns = [
        { pattern: /DOMParser\s*\(\s*\)/gi, name: 'DOMParser without disabling entities', severity: 'HIGH' },
        { pattern: /parseString\s*\(\s*(?:req|params|query|body|user|data|input)/gi, name: 'XML parsing user input (xml2js)', severity: 'CRITICAL' },
        { pattern: /xml2js|fast-xml-parser|libxmljs|sax\s*\./gi, name: 'XML parser library usage', severity: 'INFO' },
        { pattern: /DocumentBuilderFactory/gi, name: 'Java XML DocumentBuilderFactory', severity: 'MEDIUM' },
        { pattern: /SAXParserFactory/gi, name: 'Java SAXParserFactory', severity: 'MEDIUM' },
        { pattern: /XMLReader/gi, name: 'XMLReader usage', severity: 'MEDIUM' },
        { pattern: /etree\.parse\s*\(\s*(?:req|request|data|input|file)/gi, name: 'Python lxml parse user input', severity: 'CRITICAL' },
        { pattern: /etree\.fromstring\s*\(\s*(?:req|request|data|input)/gi, name: 'Python lxml fromstring user input', severity: 'CRITICAL' },
        { pattern: /simplexml_load_string\s*\(\s*\$_(?:GET|POST|REQUEST)/gi, name: 'PHP simplexml_load_string user input', severity: 'CRITICAL' },
        { pattern: /DOMDocument.*loadXML\s*\(\s*\$_(?:GET|POST|REQUEST)/gi, name: 'PHP DOMDocument loadXML user input', severity: 'CRITICAL' },
        { pattern: /LIBXML_NOENT/gi, name: 'PHP LIBXML_NOENT (entity substitution enabled)', severity: 'HIGH' },
        { pattern: /resolve_entities\s*[:=]\s*true/gi, name: 'Entity resolution enabled', severity: 'HIGH' },
        { pattern: /external_entities\s*[:=]\s*true/gi, name: 'External entities enabled', severity: 'CRITICAL' },
        { pattern: /setFeature\s*\(\s*['"]http:\/\/xml\.org\/sax\/features\/external-general-entities['"]\s*,\s*true/gi, name: 'Java external entities enabled', severity: 'CRITICAL' },
        { pattern: /DOCTYPE|ENTITY|SYSTEM/g, name: 'DOCTYPE/ENTITY declaration in file', severity: 'LOW' },
      ];

      for (const { pattern, name, severity } of xxePatterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          const line = lines[lineNum - 1]?.trim() || '';
          if (isComment(line)) continue;

          addFinding(
            severity,
            'XXE (PortSwigger)',
            `${name}`,
            `File: ${relativePath}:${lineNum}\nCode: ${line.substring(0, 120)}`,
            'Disable external entity processing: set disallow-doctype-decl=true, external-general-entities=false. Use JSON instead of XML where possible. For Java: factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)'
          );
        }
      }
    } catch {}
  }
}

function isComment(line) {
  return line.startsWith('//') || line.startsWith('#') || line.startsWith('*') || line.startsWith('<!--');
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
