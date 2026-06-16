import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';

const SCAN_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.py', '.rb', '.php', '.go', '.java', '.json', '.env'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '__pycache__', 'vendor'];

export async function auditJwtAdvanced(projectPath, spinner) {
  spinner.text = 'Scanning for advanced JWT attacks (kid, JWK, jku)...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      const patterns = [
        { pattern: /(?:kid|keyId|key_id)\s*[:=]\s*(?:req|request|params|query|body|input)/gi, name: 'Key ID (kid) from user input - path traversal/LFI attack', severity: 'CRITICAL' },
        { pattern: /jwk\s*[:=]\s*(?:req|request|params|query|body)/gi, name: 'JWK from user input - key injection', severity: 'CRITICAL' },
        { pattern: /jku\s*[:=]\s*(?:req|request|params|query|body)/gi, name: 'jku (JWK Set URL) from user input - SSRF', severity: 'CRITICAL' },
        { pattern: /x5u\s*[:=]\s*(?:req|request|params|query|body)/gi, name: 'x5u URL from user input', severity: 'CRITICAL' },
        { pattern: /x5c\s*[:=]\s*(?:req|request|params|query|body)/gi, name: 'x5c certificate from user input', severity: 'CRITICAL' },
        { pattern: /algorithm\s*[:=]\s*['"]none['"]|alg\s*:\s*['"]none['"]/gi, name: 'Algorithm "none" accepted', severity: 'CRITICAL' },
        { pattern: /algorithms\s*:\s*\[.*['"]HS256['"].*\]|algorithm\s*:\s*['"]HS256['"]/gi, name: 'HS256 algorithm (key confusion vector)', severity: 'HIGH' },
        { pattern: /(?:verify|validate)\s*\(\s*(?:token|jwt)\s*,\s*(?:secret|key)\s*,?\s*\{[^}]*algorithms?\s*:\s*\[/gi, name: 'JWT verify with algorithm whitelist', severity: 'INFO' },
        { pattern: /jwt\.(?:decode|sign|verify).*complete\s*:\s*true/gi, name: 'jwt.io format (complete decode)', severity: 'LOW' },
        { pattern: /jsonwebtoken|jose|jwk-to-pem|jwt-simple|njwt/gi, name: 'JWT library usage', severity: 'INFO' },
        { pattern: /(?:publicKey|public_key|pubkey)\s*[:=]\s*(?:req|request|params|query|body)/gi, name: 'Public key from user input (key confusion)', severity: 'CRITICAL' },
        { pattern: /(?:jwt|token|bearer).*(?:header|payload)\s*.*(?:decode|parse|split|extract)\s*\(/gi, name: 'JWT header/payload parsing (check algorithm handling)', severity: 'MEDIUM' },
        { pattern: /jwt\.sign\s*\(\s*[^,]*,\s*['"][a-zA-Z0-9]{1,16}['"]/gi, name: 'Weak JWT signing secret (<16 chars)', severity: 'HIGH' },
        { pattern: /(?:secret|jwtSecret|JWT_SECRET)\s*=\s*['"]?[a-zA-Z0-9]{1,24}['"]?/gi, name: 'Short JWT secret in code', severity: 'HIGH' },
        { pattern: /crypto\.createPublicKey|crypto\.createPrivateKey/gi, name: 'crypto key creation (check source)', severity: 'INFO' },
      ];

      for (const { pattern, name, severity } of patterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          const line = lines[lineNum - 1]?.trim() || '';
          if (line.startsWith('//') || line.startsWith('#') || line.startsWith('*')) continue;

          addFinding(
            severity,
            'JWT Advanced Attacks',
            name,
            `File: ${relativePath}:${lineNum}\nCode: ${line.substring(0, 120)}`,
            'Whitelist allowed algorithms (e.g., ["RS256"]). Never use "none" algorithm. Do not accept kid/jwk/jku/x5u from untrusted input. Use asymmetric signing (RS256/ES256). Validate kid against a trusted key store, not a file path. Check for key confusion: if using RS256 ensure public key is not accepted as HMAC secret.'
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
