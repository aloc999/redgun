import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';

const SCAN_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.py', '.rb', '.php', '.go', '.java'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '__pycache__', 'vendor'];

export async function auditAto(projectPath, spinner) {
  spinner.text = 'Scanning for Account Takeover patterns...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      const patterns = [
        { pattern: /(?:password|pwd).*reset.*token\s*=\s*(?:Math\.random|Date\.now|uuid|random)/gi, name: 'Password reset token from predictable source', severity: 'CRITICAL' },
        { pattern: /reset.*token\s*=\s*(?:hash|md5|sha1)\s*\(/gi, name: 'Reset token hashed with weak algorithm', severity: 'MEDIUM' },
        { pattern: /reset.*token\s*.*(?:url|link|href).*\$\{.*token/gi, name: 'Reset token exposed in URL (referer leakage)', severity: 'HIGH' },
        { pattern: /(?:email|phone)\s*.*\s*change.*\s*\((?!.*confirm|verify|reauth|password)/gi, name: 'Email/phone change without re-authentication', severity: 'HIGH' },
        { pattern: /logout\s*\([^)]*\)\s*\{[^}]*(?:session\.destroy|clearCookie|cookie.*clear)/gi, name: 'Logout implementation (check server-side invalidation)', severity: 'INFO' },
        { pattern: /(?:session|token|jwt)\s*.*\s*(?:invalidation|revoke|blacklist|expire|expiry)/gi, name: 'Session/token revocation', severity: 'INFO' },
        { pattern: /otp\s*.*generate.*\s*=\s*(?:Math\.floor|Math\.random|random)/gi, name: 'OTP from predictable source', severity: 'CRITICAL' },
        { pattern: /otp.*length\s*[<=]?\s*[0-5]/gi, name: 'Short OTP length (< 6 digits)', severity: 'HIGH' },
        { pattern: /otp.*(?:expir|ttl|validity|valid.*for).*[>=]?\s*(?:60\d|7\d|8\d|9\d)\d*/gi, name: 'Long OTP validity (> 10 min)', severity: 'MEDIUM' },
        { pattern: /(?:login|auth|signin)\s*.*\s*attempt.*\s*=\s*0/gi, name: 'Rate limit on login (good)', severity: 'INFO' },
        { pattern: /(?:password|credential|account|login).*(?:lock|throttle|attempt|brute|restrict|limit)/gi, name: 'Account lockout/throttling detected', severity: 'INFO' },
        { pattern: /(?:social|oauth|google|github|facebook).*(?:link|connect|attach).*(?!.*confirm|verify|reauth)/gi, name: 'Social account linking without re-auth', severity: 'HIGH' },
        { pattern: /(?:MFA|2FA|two.?factor|multi.?factor).*(?:skip|disabled?|bypass|false)/gi, name: 'MFA skip/bypass condition', severity: 'CRITICAL' },
        { pattern: /(?:MFA|2FA).*\..*secret.*\s*=.*['"][a-zA-Z0-9]{10,}['"]/gi, name: 'MFA secret hardcoded', severity: 'CRITICAL' },
        { pattern: /(?:register|signup|create).*(?:duplicate|exist|unique).*email|username/gi, name: 'User enumeration via register endpoint', severity: 'MEDIUM' },
        { pattern: /(?:login|signin).*(?:incorrect|wrong|invalid|not found).*(?:password|email)/gi, name: 'User enumeration via verbose login errors', severity: 'MEDIUM' },
        { pattern: /res\.sendStatus\s*\(\s*401|res\.json.*invalid.*credentials/gi, name: 'Generic error handling (good for preventing enumeration)', severity: 'INFO' },
      ];

      for (const { pattern, name, severity } of patterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          const line = lines[lineNum - 1]?.trim() || '';
          if (line.startsWith('//') || line.startsWith('#') || line.startsWith('*')) continue;

          addFinding(
            severity,
            'Account Takeover (ATO)',
            name,
            `File: ${relativePath}:${lineNum}\nCode: ${line.substring(0, 120)}`,
            'Use crypto.randomBytes for reset tokens. Expire tokens quickly (< 15 min). Require current password to change email/password or link social accounts. Use TOTP-based MFA (not SMS). Use generic error messages. Implement proper rate limiting and account lockout (not just IP-based).'
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
