import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';

const SCAN_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.py', '.rb', '.php', '.go', '.java'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '__pycache__', 'vendor'];

export async function auditWebauthn(projectPath, spinner) {
  spinner.text = 'Scanning for WebAuthn/Passkeys vulnerabilities...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      const patterns = [
        { pattern: /navigator\.credentials\.(?:create|get)\s*\(/gi, name: 'WebAuthn credential create/get', severity: 'INFO' },
        { pattern: /PublicKeyCredential|CredentialCreationOptions/gi, name: 'WebAuthn API usage', severity: 'INFO' },
        { pattern: /(?:webauthn|passkey|security.?key|biometric).*(?:auth|login|verify|register)/gi, name: 'Passkey/WebAuthn auth flow', severity: 'INFO' },
        { pattern: /(?:webauthn|passkey).*.*(?:relay|proxy|forward|redirect)/gi, name: 'WebAuthn relay attack surface', severity: 'HIGH' },
        { pattern: /challenge\s*[:=]\s*['"][a-zA-Z0-9]{1,16}['"]|challenge\s*[:=]\s*Bufffer\.from\s*\(/gi, name: 'Short/static WebAuthn challenge (relay vector)', severity: 'HIGH' },
        { pattern: /(?:challenge|nonce|serverChallenge).*(?:Math\.random|Date\.now|uuid)/gi, name: 'WebAuthn challenge from predictable source', severity: 'CRITICAL' },
        { pattern: /allowCredentials\s*:\s*\[\s*\]|allowCredentials\s*:\s*\[\s*\{\s*type\s*:\s*'public-key'\s*\}\s*\]/gi, name: 'WebAuthn empty allowCredentials (allowed all keys)', severity: 'HIGH' },
        { pattern: /userVerification\s*:\s*['"]discouraged['"]/gi, name: 'WebAuthn user verification discouraged', severity: 'MEDIUM' },
        { pattern: /attestation\s*:\s*['"]none['"]/gi, name: 'WebAuthn attestation disabled (no device verification)', severity: 'MEDIUM' },
        { pattern: /rp\.id\s*[:=]\s*['"][^'"]*['"]/gi, name: 'WebAuthn relying party ID', severity: 'INFO' },
        { pattern: /(?:webauthn|fido2|u2f).*(?:fallback|recovery|backup).*(?:password|sms|email)/gi, name: 'WebAuthn with weak fallback (bypass vector)', severity: 'HIGH' },
      ];

      for (const { pattern, name, severity } of patterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          const line = lines[lineNum - 1]?.trim() || '';
          if (line.startsWith('//') || line.startsWith('#') || line.startsWith('*')) continue;

          addFinding(
            severity,
            'WebAuthn / Passkeys',
            name,
            `File: ${relativePath}:${lineNum}\nCode: ${line.substring(0, 120)}`,
            'Use cryptographically random challenges (32+ bytes). Do not use predictable sources for challenges. Require userVerification for sensitive operations. Implement proper RP ID validation. Do not rely on WebAuthn alone; use as MFA factor.'
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
