import { execSync } from 'child_process';
import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { addFinding } from '../core/findings.js';

export async function auditDependencies(projectPath, spinner) {
  spinner.text = 'Auditing dependencies for CVEs...';

  const packageJsonPath = join(projectPath, 'package.json');
  const packageLockPath = join(projectPath, 'package-lock.json');

  if (!existsSync(packageJsonPath)) return;

  try {
    const result = execSync('npm audit --json 2>/dev/null', {
      cwd: projectPath,
      encoding: 'utf-8',
      timeout: 30000,
    });

    const audit = JSON.parse(result);
    const vulnerabilities = audit.vulnerabilities || {};

    for (const [pkg, info] of Object.entries(vulnerabilities)) {
      const severity = mapSeverity(info.severity);
      addFinding(
        severity,
        'Dependencies',
        `${pkg} has known vulnerability`,
        `Severity: ${info.severity} | Via: ${info.via?.map(v => typeof v === 'string' ? v : v.title).join(', ') || 'unknown'}`,
        `Run: npm audit fix, or upgrade ${pkg} to a patched version`
      );
    }
  } catch (err) {
    try {
      const result = execSync('npm audit 2>&1', {
        cwd: projectPath,
        encoding: 'utf-8',
        timeout: 30000,
      });
      if (result.includes('found 0 vulnerabilities')) return;

      const critMatch = result.match(/(\d+)\s+critical/);
      const highMatch = result.match(/(\d+)\s+high/);
      const modMatch = result.match(/(\d+)\s+moderate/);

      if (critMatch) {
        addFinding('CRITICAL', 'Dependencies', `${critMatch[1]} critical vulnerabilities in dependencies`, 'Run npm audit for details', 'Run: npm audit fix --force');
      }
      if (highMatch) {
        addFinding('HIGH', 'Dependencies', `${highMatch[1]} high severity vulnerabilities in dependencies`, 'Run npm audit for details', 'Run: npm audit fix');
      }
      if (modMatch) {
        addFinding('MEDIUM', 'Dependencies', `${modMatch[1]} moderate vulnerabilities in dependencies`, 'Run npm audit for details', 'Run: npm audit fix');
      }
    } catch {}
  }

  if (existsSync(packageJsonPath)) {
    try {
      const pkg = JSON.parse(readFileSync(packageJsonPath, 'utf-8'));
      const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };

      const dangerousPkgs = ['event-stream', 'flatmap-stream', 'ua-parser-js', 'coa', 'rc'];
      for (const dangerous of dangerousPkgs) {
        if (allDeps[dangerous]) {
          addFinding(
            'HIGH',
            'Dependencies',
            `Potentially compromised package: ${dangerous}`,
            'This package has been involved in supply-chain attacks',
            `Review if ${dangerous} is necessary and check its version for known compromised versions`
          );
        }
      }
    } catch {}
  }
}

function mapSeverity(npmSeverity) {
  const map = { critical: 'CRITICAL', high: 'HIGH', moderate: 'MEDIUM', low: 'LOW', info: 'INFO' };
  return map[npmSeverity] || 'MEDIUM';
}
