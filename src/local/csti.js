import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';

const SCAN_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.py', '.rb', '.php', '.go', '.java'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '__pycache__', 'vendor'];

export async function auditCsti(projectPath, spinner) {
  spinner.text = 'Scanning for client-side template injection...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      const patterns = [
        { pattern: /\{\{.+\}\}/g, name: 'AngularJS double-curly expression', severity: 'INFO' },
        { pattern: /ng-app|ng-controller|ng-bind-html|ng-non-bindable/gi, name: 'AngularJS bindings detected', severity: 'INFO' },
        { pattern: /\$sce\.trustAsHtml|\$sceProvider\.enabled\s*\(\s*false/gi, name: 'AngularJS SCE disabled/untrusted HTML', severity: 'HIGH' },
        { pattern: /ng-bind-html\s*=\s*(?:req|request|params|query|body)/gi, name: 'AngularJS ng-bind-html with user input', severity: 'HIGH' },
        { pattern: /angular\.module.*run\s*\(/gi, name: 'AngularJS module detected', severity: 'INFO' },
        { pattern: /v-html\s*=\s*(?:req|params|query|body)/gi, name: 'Vue v-html with user input', severity: 'HIGH' },
        { pattern: /v-bind:src|:src\s*=\s*['"`]\{\{/gi, name: 'Vue dynamic src binding', severity: 'MEDIUM' },
        { pattern: /Vue\.compile\s*\(|new\s+Vue\s*\(|createApp\s*\(/gi, name: 'Vue instance detected', severity: 'INFO' },
        { pattern: /React\.createElement|ReactDOM\.render|createRoot\s*\(/gi, name: 'React rendering detected', severity: 'INFO' },
        { pattern: /dangerouslySetInnerHTML\s*:\s*\{\s*__html\s*:\s*(?:req|params|query|body)/gi, name: 'React dangerouslySetInnerHTML with user input', severity: 'HIGH' },
        { pattern: /Svelte.*\$set|Svelte.*\$\$invalidate|Svelte.*dangerously/gi, name: 'Svelte dynamic updates', severity: 'MEDIUM' },
        { pattern: /TemplateRef|ViewContainerRef|ComponentFactoryResolver/gi, name: 'Angular dynamic component (XSS surface)', severity: 'MEDIUM' },
        { pattern: /bypassSecurityTrustHtml\s*\(/gi, name: 'Angular bypassSecurityTrustHtml', severity: 'HIGH' },
        { pattern: /bypassSecurityTrustScript|bypassSecurityTrustResourceUrl/gi, name: 'Angular bypassSecurityTrust (unsafe)', severity: 'HIGH' },
        { pattern: /ElementRef\.nativeElement\.innerHTML/gi, name: 'Angular ElementRef innerHTML', severity: 'MEDIUM' },
        { pattern: /sanitizeHtml|DOMPurify\.sanitize/gi, name: 'HTML sanitization used (good)', severity: 'INFO' },
      ];

      for (const { pattern, name, severity } of patterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          const line = lines[lineNum - 1]?.trim() || '';
          if (line.startsWith('//') || line.startsWith('#') || line.startsWith('*')) continue;

          addFinding(
            severity,
            'Client-Side Template Injection (CSTI)',
            name,
            `File: ${relativePath}:${lineNum}\nCode: ${line.substring(0, 120)}`,
            'Never bind user input to v-html/dangerouslySetInnerHTML/ng-bind-html. Use DOMPurify for sanitization. Avoid bypassSecurityTrust* APIs. Use Angular default sanitizer. For Vue, use v-text instead of v-html.'
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
