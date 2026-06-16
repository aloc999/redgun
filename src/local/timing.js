import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';

const SCAN_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.py', '.rb', '.php', '.go', '.java'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '__pycache__', 'vendor'];

export async function auditTiming(projectPath, spinner) {
  spinner.text = 'Scanning for timing side-channel vulnerabilities...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      const patterns = [
        { pattern: /(?:password|secret|token|key|hash|pin).*\s*={2,3}\s*(?:req|request|params|body|input)/gi, name: 'String comparison with user input (timing leak)', severity: 'HIGH' },
        { pattern: /(?:password|secret|token|key|hash|pin)\s*===\s*/gi, name: 'Strict comparison used (good for timing)', severity: 'INFO' },
        { pattern: /crypto\.timingSafeEqual|timingsafe\b/gi, name: 'Timing-safe comparison used (good)', severity: 'INFO' },
        { pattern: /\b(?:sleep|delay|wait|setTimeout|setInterval)\s*\(\s*(?:req|request|params|query|body)/gi, name: 'User-controlled delay/sleep (potential timing oracle)', severity: 'MEDIUM' },
        { pattern: /(?:if|when)\s*\([^)]*(?:req|request|params|query|body)[^)]*\)\s*(?:\{|\n)\s*(?:sleep|delay|setTimeout)/gi, name: 'Conditional sleep based on user input', severity: 'HIGH' },
        { pattern: /(?:login|auth|signin).*select.*password.*(?:req|request|params)/gi, name: 'Password DB lookup (check for timing leak on user-not-found)', severity: 'MEDIUM' },
        { pattern: /bcrypt\.compare|bcrypt\.compareSync|argon2\.verify/gi, name: 'bcrypt/argon2 verification (timing-safe)', severity: 'INFO' },
        { pattern: /(?:hash|digest|hmac)\s*\(\s*['"]?(?:md5|sha1|sha256|sha512)['"]?\s*,/gi, name: 'Hash function usage (check HMAC timing)', severity: 'LOW' },
        { pattern: /(?:for|while)\s*\([^)]*(?:req|request|params|query|body)[^)]*\)/gi, name: 'Loop iteration from user input (DoS + timing oracle)', severity: 'MEDIUM' },
        { pattern: /(?:username|email|user).*exists|(?:findOne|findUser)\s*\(\s*\{.*username/gi, name: 'User existence check (potential oracle)', severity: 'LOW' },
        { pattern: /PasswordResetListener|SentMessage|mail.*send.*token/gi, name: 'Email sending after reset request (timing oracle on user existence)', severity: 'LOW' },
      ];

      for (const { pattern, name, severity } of patterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          const line = lines[lineNum - 1]?.trim() || '';
          if (line.startsWith('//') || line.startsWith('#') || line.startsWith('*')) continue;

          addFinding(
            severity,
            'Timing Side-Channels',
            name,
            `File: ${relativePath}:${lineNum}\nCode: ${line.substring(0, 120)}`,
            'Use constant-time comparison (timingSafeEqual) for secrets. Ensure login returns identical responses regardless of user existence. Add random jitter to email sending. Never use sleep/delay from user input.'
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
