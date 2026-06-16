import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';

const SCAN_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.py', '.rb', '.php', '.go', '.java'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '__pycache__', 'vendor'];

export async function auditBusinessLogic(projectPath, spinner) {
  spinner.text = 'Scanning for business logic flaws (PortSwigger)...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      const patterns = [
        { pattern: /(?:price|amount|total|cost|quantity|qty)\s*[:=]\s*(?:req|params|query|body|request)\./gi, name: 'Price/amount from client input (price manipulation)', severity: 'CRITICAL' },
        { pattern: /(?:discount|coupon|promo|voucher).*(?:apply|use|redeem)/gi, name: 'Discount/coupon logic (test for race conditions & reuse)', severity: 'MEDIUM' },
        { pattern: /(?:quantity|qty)\s*[:=]\s*(?:parseInt|Number)\s*\(\s*(?:req|body)/gi, name: 'Quantity from user input (negative quantity attack)', severity: 'HIGH' },
        { pattern: /(?:transfer|withdraw|send)\s*.*(?:amount|value)\s*[:=]/gi, name: 'Financial transfer logic (check for negative amounts, overflow)', severity: 'HIGH' },
        { pattern: /(?:limit|max|threshold)\s*.*(?:parseInt|Number|parseFloat)\s*\(\s*(?:req|body|query)/gi, name: 'Limit/threshold from user input', severity: 'MEDIUM' },
        { pattern: /(?:step|stage|phase|state)\s*[:=]\s*(?:req|params|query|body)/gi, name: 'Workflow step from user input (step skipping)', severity: 'HIGH' },
        { pattern: /(?:if|when).*(?:balance|credits?|points?)\s*(?:>=?|<=?|>|<)\s*(?:0|amount|price)/gi, name: 'Balance check (test for race conditions)', severity: 'MEDIUM' },
        { pattern: /(?:verify|validate|check).*(?:email|phone|identity)\s*.*(?:skip|bypass|false)/gi, name: 'Verification bypass flag', severity: 'HIGH' },
        { pattern: /(?:free[-_]?trial|trial[-_]?period).*(?:extend|reset|create)/gi, name: 'Trial logic (test for unlimited trial abuse)', severity: 'MEDIUM' },
        { pattern: /(?:referral|invite|bonus).*(?:credit|reward|points)/gi, name: 'Referral/bonus logic (test for self-referral abuse)', severity: 'MEDIUM' },
        { pattern: /parseInt\s*\(\s*(?:req|body|query).*10\s*\)|Number\s*\(\s*(?:req|body|query)/gi, name: 'Numeric input parsing (test integer overflow, NaN, Infinity)', severity: 'LOW' },
        { pattern: /(?:vote|like|upvote|rate|review).*(?:req|body|params)/gi, name: 'Voting/rating logic (test for multiple votes)', severity: 'MEDIUM' },
      ];

      for (const { pattern, name, severity } of patterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          const line = lines[lineNum - 1]?.trim() || '';
          if (line.startsWith('//') || line.startsWith('#')) continue;

          addFinding(
            severity,
            'Business Logic (PortSwigger)',
            name,
            `File: ${relativePath}:${lineNum}\nCode: ${line.substring(0, 120)}`,
            'Never trust client-supplied values for prices, quantities, or workflow states. Validate all business rules server-side. Use database transactions with proper isolation levels for financial operations. Implement idempotency keys to prevent double-processing.'
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
