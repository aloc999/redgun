import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';

const SCAN_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.json', '.lock', '.toml'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '__pycache__', 'vendor'];

export async function auditSupplyChainAdvanced(projectPath, spinner) {
  spinner.text = 'Scanning for supply chain attacks (dep confusion, lockfile, post-install)...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      const patterns = [
        { pattern: /postinstall|preinstall|postuninstall|prepare|prepublishOnly/gi, name: 'npm lifecycle hook (check for abuse)', severity: 'MEDIUM' },
        { pattern: /"postinstall"\s*:\s*"([^"]+)"/gi, name: 'postinstall script detected', severity: 'HIGH' },
        { pattern: /"scripts"\s*:\s*\{[^}]*"(?:install|postinstall|preinstall)"/gi, name: 'Install script in package.json', severity: 'MEDIUM' },
        { pattern: /(?:eval|exec|child_process|spawn|require)\s*\(\s*['"`][^'"`]*(['"`]\s*\+\s*|['"`]\s*\+\s*['"`])/gi, name: 'Dynamic code execution in scripts', severity: 'CRITICAL' },
        { pattern: /npm_config_|process\.env\.npm_/gi, name: 'npm config env var usage (can be manipulated)', severity: 'MEDIUM' },
        { pattern: /(?:registry|publishConfig|_resolved)\s*:\s*"(?!https:\/\/registry\.npmjs\.org)/gi, name: 'Non-standard npm registry configured', severity: 'HIGH' },
        { pattern: /"dependencies"\s*:\s*\{[^}]*"(?!@[^"]+)":/gi, name: 'Unscoped dependency (dep confusion risk)', severity: 'MEDIUM' },
        { pattern: /"resolved"\s*:\s*"[^"]*(?:localhost|0\.0\.0\.0|127\.0\.0\.1|evil|hack|malware)/gi, name: 'Suspicious resolved URL in lockfile', severity: 'CRITICAL' },
        { pattern: /"version"\s*:\s*"0\.0\.\d+|"version"\s*:\s*"file:|\*"resolved"\s*"/gi, name: 'Zero-version or file: dependency (suspicious)', severity: 'HIGH' },
        { pattern: /gist\.githubusercontent\.com|raw\.githubusercontent\.com.*npm|npm\s*-?\s*i\s*-\s*g\s*http/i, name: 'Package from non-registry source', severity: 'HIGH' },
        { pattern: /(?:integrity|shasum|sha512|sha1)\s*:\s*""/gi, name: 'Empty integrity hash in lockfile (tampered)', severity: 'CRITICAL' },
        { pattern: /"hasInstallScript"\s*:\s*true/gi, name: 'Package has install scripts (audit)', severity: 'MEDIUM' },
        { pattern: /npmrc|\.npmrc.*token|npm.*config.*set.*auth/gi, name: 'npm registry auth config', severity: 'INFO' },
        { pattern: /(?:pip|pip3|pipx)\s+install\s+[-]+\s*(?!-r)/gi, name: 'pip install without requirements (dep confusion)', severity: 'MEDIUM' },
        { pattern: /curl\s+.*\|\s*(?:bash|sh|zsh)/gi, name: 'curl pipe to shell (remote code execution risk)', severity: 'CRITICAL' },
        { pattern: /wget\s+.*\|\s*(?:bash|sh|zsh)/gi, name: 'wget pipe to shell (remote code execution risk)', severity: 'CRITICAL' },
      ];

      for (const { pattern, name, severity } of patterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          const line = lines[lineNum - 1]?.trim() || '';
          if (line.startsWith('#') || line.startsWith('//')) continue;

          addFinding(
            severity,
            'Supply Chain Attacks',
            name,
            `File: ${relativePath}:${lineNum}\nCode: ${line.substring(0, 120)}`,
            'Use scoped packages (@org/pkg) to prevent dependency confusion. Audit postinstall scripts. Verify lockfile integrity. Use npm audit and npm vet. Avoid curl|bash patterns. Pin dependencies with exact versions and verify hashes. Use private registry for internal packages.'
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
