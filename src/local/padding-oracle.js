import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';

const SCAN_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.py', '.rb', '.php', '.go', '.java', '.c', '.cpp', '.cs'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '__pycache__', 'vendor'];

export async function auditPaddingOracle(projectPath, spinner) {
  spinner.text = 'Scanning for padding/comression oracle vulnerabilities...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      const patterns = [
        { pattern: /(?:decrypt|decipher|unpad)\s*\([^)]*\)\s*(?:catch|if.*error)/gi, name: 'Decryption with error handling (padding oracle)', severity: 'HIGH' },
        { pattern: /(?:padding|decrypt)\s*(?:bad|invalid|wrong|error|fail)/gi, name: 'Decryption error message (padding oracle indicator)', severity: 'HIGH' },
        { pattern: /CBC|cipher\.final|cipher\.update/gi, name: 'CBC mode encryption (padding oracle vector)', severity: 'MEDIUM' },
        { pattern: /createDecipheriv\s*\(\s*['"](?:aes|des)-.*-(?:cbc|ecb)/gi, name: 'CBC/ECB mode decrypt (potential padding oracle)', severity: 'MEDIUM' },
        { pattern: /(?:error|exception|err)\s*\(\s*['"](?:bad|invalid|wrong) (?:padding|decrypt|cipher)/gi, name: 'Padding error in response', severity: 'HIGH' },
        { pattern: /OAEP|RSASSA-PSS|RSAES-OAEP/gi, name: 'RSA OAEP padding (good)', severity: 'INFO' },
        { pattern: /PKCS|pkcs/i, name: 'PKCS padding reference', severity: 'INFO' },
        { pattern: /gzip|deflate|compress|zlib|Content-Encoding/gi, name: 'Compression usage (CRIME/BREACH vector)', severity: 'LOW' },
        { pattern: /(?:token|session|cookie|jwt).*(?:compress|gzip|deflate)/gi, name: 'Compression of secrets/tokens (CRIME/BREACH)', severity: 'MEDIUM' },
        { pattern: /(?:https|tls|ssl).*(?:compress|gzip|deflate)/gi, name: 'TLS compression reference (CRIME)', severity: 'MEDIUM' },
        { pattern: /\bcrypto\.createDecipheriv\b/gi, name: 'Node.js createDecipheriv (check error handling)', severity: 'MEDIUM' },
      ];

      for (const { pattern, name, severity } of patterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          const line = lines[lineNum - 1]?.trim() || '';
          if (line.startsWith('//') || line.startsWith('#') || line.startsWith('*')) continue;

          addFinding(
            severity,
            'Padding / Compression Oracle',
            name,
            `File: ${relativePath}:${lineNum}\nCode: ${line.substring(0, 120)}`,
            'Use authenticated encryption (AES-GCM, ChaCha20-Poly1305) instead of CBC. Never leak decryption errors to clients. Add random MAC before encrypting. Disable TLS compression. Avoid compressing response bodies that contain secrets or CSRF tokens.'
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
