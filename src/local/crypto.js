import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';

const SCAN_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.py', '.rb', '.php', '.go', '.java', '.cs'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '__pycache__', 'vendor'];

export async function auditCrypto(projectPath, spinner) {
  spinner.text = 'Scanning for weak cryptography (HackTricks)...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      const weakAlgorithms = [
        { pattern: /createHash\s*\(\s*['"]md5['"]\)/gi, algo: 'MD5', severity: 'HIGH' },
        { pattern: /createHash\s*\(\s*['"]sha1['"]\)/gi, algo: 'SHA1', severity: 'MEDIUM' },
        { pattern: /hashlib\.md5/gi, algo: 'MD5', severity: 'HIGH' },
        { pattern: /hashlib\.sha1/gi, algo: 'SHA1', severity: 'MEDIUM' },
        { pattern: /MessageDigest\.getInstance\s*\(\s*['"]MD5['"]\)/gi, algo: 'MD5', severity: 'HIGH' },
        { pattern: /MessageDigest\.getInstance\s*\(\s*['"]SHA-?1['"]\)/gi, algo: 'SHA1', severity: 'MEDIUM' },
        { pattern: /DES|3DES|RC4|RC2|Blowfish/gi, algo: 'Weak cipher', severity: 'HIGH' },
        { pattern: /createCipheriv\s*\(\s*['"](?:des|rc4|aes-128-ecb)['"]/gi, algo: 'Weak cipher mode', severity: 'HIGH' },
        { pattern: /ECB/g, algo: 'ECB mode', severity: 'HIGH' },
        { pattern: /Math\.random\s*\(\s*\)/g, algo: 'Math.random() for crypto', severity: 'MEDIUM' },
        { pattern: /random\.random\s*\(\s*\)/g, algo: 'random.random() for crypto', severity: 'MEDIUM' },
      ];

      for (const { pattern, algo, severity } of weakAlgorithms) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          const line = lines[lineNum - 1]?.trim() || '';

          if (isComment(line)) continue;

          addFinding(
            severity,
            'Weak Cryptography (HackTricks)',
            `Weak cryptographic algorithm: ${algo}`,
            `File: ${relativePath}:${lineNum}\nCode: ${line.substring(0, 100)}`,
            `Replace ${algo} with strong alternatives: SHA-256/SHA-3 for hashing, AES-256-GCM for encryption, crypto.randomBytes()/secrets module for random generation.`
          );
        }
      }

      const hardcodedIv = /(?:iv|nonce)\s*[:=]\s*(?:Buffer\.from|new Uint8Array)\s*\(\s*['"][^'"]+['"]\)/gi;
      let ivMatch;
      while ((ivMatch = hardcodedIv.exec(content)) !== null) {
        const lineNum = content.substring(0, ivMatch.index).split('\n').length;
        addFinding(
          'HIGH',
          'Weak Cryptography (HackTricks)',
          'Hardcoded IV/nonce detected',
          `File: ${relativePath}:${lineNum}`,
          'Never hardcode IVs/nonces. Generate a new random IV for each encryption operation using crypto.randomBytes().'
        );
      }

      const hardcodedKey = /(?:encryption|cipher|crypto).*key\s*[:=]\s*['"][A-Za-z0-9+/=]{16,}['"]/gi;
      let keyMatch;
      while ((keyMatch = hardcodedKey.exec(content)) !== null) {
        const lineNum = content.substring(0, keyMatch.index).split('\n').length;
        addFinding(
          'CRITICAL',
          'Weak Cryptography (HackTricks)',
          'Hardcoded encryption key',
          `File: ${relativePath}:${lineNum}`,
          'Store encryption keys in a key management system (KMS) or environment variables. Never hardcode cryptographic keys.'
        );
      }
    } catch {}
  }
}

function isComment(line) {
  return line.startsWith('//') || line.startsWith('#') || line.startsWith('*');
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
