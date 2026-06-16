import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';

const SCAN_EXTENSIONS = ['.sol', '.rs', '.js', '.ts', '.jsx', '.tsx', '.py', '.vy', '.move'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '__pycache__', 'vendor', 'out'];

export async function auditWeb3(projectPath, spinner) {
  spinner.text = 'Scanning for Web3/smart contract vulnerabilities...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      const patterns = [
        { pattern: /reentrancy|re-?entrant|nonReentrant/gi, name: 'Reentrancy guard pattern', severity: 'INFO' },
        { pattern: /\.call\s*\(\s*\{\s*value:|\.transfer\s*\(|\.send\s*\(/gi, name: 'ETH transfer method (check reentrancy)', severity: 'HIGH' },
        { pattern: /(?:transfer|send)\s*\(\s*(?:msg\.value|address\(this\)\.balance)/gi, name: 'Full balance transfer (reentrancy risk)', severity: 'CRITICAL' },
        { pattern: /(?:balances?|mapping).*\s*\[.*\s*\]\s*[-+]=?\s*/gi, name: 'Balance update (check CEI pattern)', severity: 'MEDIUM' },
        { pattern: /delegatecall|delegatecall\s*\(/gi, name: 'delegatecall usage (storage collision risk)', severity: 'CRITICAL' },
        { pattern: /selfdestruct|suicide\s*\(/gi, name: 'selfdestruct usage', severity: 'HIGH' },
        { pattern: /tx\.origin\s*={2,3}|require\s*\(\s*tx\.origin/gi, name: 'tx.origin used for auth (phishing risk)', severity: 'CRITICAL' },
        { pattern: /block\.timestamp.*==|block\.timestamp.*<=|block\.timestamp.*>=/gi, name: 'block.timestamp in strict comparison', severity: 'MEDIUM' },
        { pattern: /blockhash\s*\(|block\.blockhash/gi, name: 'Blockhash usage (predictable in multi-block context)', severity: 'MEDIUM' },
        { pattern: /onlyOwner|Ownable|owner\s*=\s*msg\.sender/gi, name: 'Ownable pattern (single point of failure)', severity: 'MEDIUM' },
        { pattern: /mint\s*\(\s*.*address|_mint\s*\(/gi, name: 'Mint function (check access control)', severity: 'HIGH' },
        { pattern: /proxy|implementation|upgrade|initialize/gi, name: 'Upgradeable/proxy pattern', severity: 'INFO' },
        { pattern: /storage\s+|assembly\s*\{.*sload|sstore/gi, name: 'Inline assembly with storage access', severity: 'HIGH' },
        { pattern: /unchecked\s*\{|unchecked\s*\(/gi, name: 'unchecked block (integer overflow risk)', severity: 'MEDIUM' },
        { pattern: /uint\d+\s*\+\s*|uint\d+\s*-\s*|uint\d+\s*\*\s*/gi, name: 'Integer arithmetic (check overflow/underflow if Solidity < 0.8)', severity: 'MEDIUM' },
        { pattern: /msg\.value\s*>=\s*0|msg\.value\s*==\s*0/gi, name: 'msg.value comparison (check edge cases)', severity: 'LOW' },
        { pattern: /(?:constructor|init)\s*\([^)]*(?:_proxy|_impl|_implementation)/gi, name: 'Proxy initialization (check for double-init)', severity: 'HIGH' },
        { pattern: /(?:deadline|expiry|expires).*(?:require|if|assert)\s*\(/gi, name: 'Deadline check (frontrunning protection)', severity: 'MEDIUM' },
      ];

      for (const { pattern, name, severity } of patterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          const line = lines[lineNum - 1]?.trim() || '';
          if (line.startsWith('//') || line.startsWith('#') || line.startsWith('*')) continue;

          addFinding(
            severity,
            'Web3 / Smart Contracts',
            name,
            `File: ${relativePath}:${lineNum}\nCode: ${line.substring(0, 120)}`,
            'Use Checks-Effects-Interactions pattern. Use ReentrancyGuard from OpenZeppelin. Verify proxy initializer is only called once. Use msg.sender instead of tx.origin for auth. Use block.timestamp >= for time comparisons. Run slither/aderyn for deeper analysis.'
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
