import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';

const SCAN_EXTENSIONS = ['.yml', '.yaml', '.js', '.ts', '.sh', '.bash'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '__pycache__', 'vendor'];

export async function auditCicd(projectPath, spinner) {
  spinner.text = 'Scanning for CI/CD pipeline vulnerabilities...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      const patterns = [
        { pattern: /pull_request_target/gi, name: 'pull_request_target event (injection risk)', severity: 'CRITICAL' },
        { pattern: /pull_request_target.*(?:checkout|run:|script:|exec|execute)/gi, name: 'pull_request_target with code execution', severity: 'CRITICAL' },
        { pattern: /on:\s*pull_request_target.*workflow_run/gi, name: 'workflow_run from fork PR (injection)', severity: 'CRITICAL' },
        { pattern: /\$\{\{\s*github\.event\.pull_request\.(?:title|body|head\.ref)\s*\}\}/gi, name: 'GitHub Actions - PR body/title used unsafely', severity: 'CRITICAL' },
        { pattern: /run:.*\${{.*github\.event\.|run:.*\${{.*inputs\./gi, name: 'GitHub Actions - user input in run step', severity: 'CRITICAL' },
        { pattern: /secrets\.\w+\s*:\s*\$\{\{\s*inputs\./gi, name: 'Secrets exposed via workflow inputs', severity: 'HIGH' },
        { pattern: /(?:ACCESS_TOKEN|API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIALS)\s*:\s*\$\{\{\s*secrets\./gi, name: 'Secrets in workflow environment', severity: 'INFO' },
        { pattern: /actions\/checkout@v\d\s*$|[^/]checkout\s*:/gi, name: 'Repository checkout', severity: 'INFO' },
        { pattern: /jenkins.*pipeline|Jenkinsfile/gi, name: 'Jenkins pipeline', severity: 'INFO' },
        { pattern: /stage\s*\(\s*['"]Deploy|publish|release/gi, name: 'CI deployment stage', severity: 'INFO' },
        { pattern: /docker.*build.*push|docker.*image|container.*registry/gi, name: 'Container build and push', severity: 'INFO' },
        { pattern: /gitlab-ci\.yml|\.gitlab-ci/gi, name: 'GitLab CI configuration', severity: 'INFO' },
        { pattern: /(?:npm|pip|maven|gradle|docker|helm)\s*(?:publish|push|deploy)/gi, name: 'Package/docker publish step', severity: 'INFO' },
        { pattern: /needs:\s*\[.*build.*\]\s*$|if:\s*github\.ref\s*==\s*'refs\/heads\/(?:main|master)'/gi, name: 'CI gate on main branch', severity: 'INFO' },
        { pattern: /write\s*:\s*\[\s*['"]id-token['"]\s*\]|id-token\s*:\s*write/gi, name: 'OIDC token write permission', severity: 'MEDIUM' },
        { pattern: /actions\s*:\s*read.*contents:\s*write|actions: write/gi, name: 'Elevated pipeline permissions', severity: 'HIGH' },
        { pattern: /(?:fetch-depth|filter)\s*:\s*0/gi, name: 'Full git history fetched', severity: 'LOW' },
      ];

      for (const { pattern, name, severity } of patterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          addFinding(
            severity,
            'CI/CD Pipeline',
            name,
            `File: ${relativePath}:${lineNum}\nCode: ${lines[lineNum - 1]?.trim().substring(0, 120)}`,
            'Never use pull_request_target with untrusted code execution. Sanitize all github.event fields used in scripts. Use OIDC instead of long-lived secrets. Apply least-privilege GitHub token permissions. Use environment protection rules for deployments.'
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
        else if (SCAN_EXTENSIONS.includes(extname(entry).toLowerCase()) && stat.size < 256 * 1024) files.push(fullPath);
      } catch {}
    }
  } catch {}
  return files;
}
