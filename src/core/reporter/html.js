import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';
import { getFindings, getSeverityCounts } from '../findings.js';
import { calculateScore, getGrade, getGradeColor } from '../score.js';

export function exportHtml(outputDir = './scans') {
  if (!existsSync(outputDir)) {
    mkdirSync(outputDir, { recursive: true });
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filepath = join(outputDir, `redgun-${timestamp}.html`);

  const score = calculateScore();
  const grade = getGrade(score);
  const gradeColor = getGradeColor(grade);
  const counts = getSeverityCounts();
  const findings = getFindings();

  const grouped = {};
  for (const f of findings) {
    if (!grouped[f.severity]) grouped[f.severity] = [];
    grouped[f.severity].push(f);
  }

  const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  const severityColors = {
    CRITICAL: '#f44336',
    HIGH: '#ff5722',
    MEDIUM: '#ff9800',
    LOW: '#2196f3',
    INFO: '#9e9e9e',
  };

  let findingsHtml = '';
  for (const sev of severityOrder) {
    if (!grouped[sev] || grouped[sev].length === 0) continue;
    findingsHtml += `<h3 style="color:${severityColors[sev]}">${sev} (${grouped[sev].length})</h3>`;
    for (const f of grouped[sev]) {
      findingsHtml += `
        <div class="finding" style="border-left:4px solid ${severityColors[sev]}">
          <strong>[${f.module}]</strong> ${escapeHtml(f.title)}
          ${f.details ? `<p class="details">${escapeHtml(f.details)}</p>` : ''}
          ${f.fix ? `<p class="fix"><strong>Fix:</strong> ${escapeHtml(f.fix)}</p>` : ''}
        </div>`;
    }
  }

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>RedGun Security Report</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; }
    .container { max-width: 900px; margin: 0 auto; }
    h1 { color: #ff4444; font-size: 2rem; margin-bottom: 0.5rem; }
    h2 { color: #58a6ff; margin: 1.5rem 0 1rem; }
    h3 { margin: 1.5rem 0 0.5rem; }
    .score-card { background: #161b22; border-radius: 12px; padding: 2rem; margin: 1.5rem 0; text-align: center; }
    .score { font-size: 4rem; font-weight: bold; color: ${gradeColor}; }
    .grade { font-size: 1.5rem; color: ${gradeColor}; }
    .counts { display: flex; justify-content: center; gap: 1.5rem; margin-top: 1rem; flex-wrap: wrap; }
    .count-item { text-align: center; }
    .count-num { font-size: 1.5rem; font-weight: bold; }
    .finding { background: #161b22; border-radius: 8px; padding: 1rem; margin: 0.5rem 0; }
    .details { color: #8b949e; margin-top: 0.5rem; font-size: 0.9rem; }
    .fix { color: #3fb950; margin-top: 0.5rem; font-size: 0.9rem; }
    .footer { text-align: center; margin-top: 3rem; color: #484f58; }
  </style>
</head>
<body>
  <div class="container">
    <h1>RedGun Security Report</h1>
    <p style="color:#8b949e">Generated: ${new Date().toLocaleString()}</p>
    <div class="score-card">
      <div class="score">${score}/100</div>
      <div class="grade">Grade: ${grade}</div>
      <div class="counts">
        <div class="count-item"><div class="count-num" style="color:#f44336">${counts.critical}</div>Critical</div>
        <div class="count-item"><div class="count-num" style="color:#ff5722">${counts.high}</div>High</div>
        <div class="count-item"><div class="count-num" style="color:#ff9800">${counts.medium}</div>Medium</div>
        <div class="count-item"><div class="count-num" style="color:#2196f3">${counts.low}</div>Low</div>
        <div class="count-item"><div class="count-num" style="color:#9e9e9e">${counts.info}</div>Info</div>
      </div>
    </div>
    <h2>Findings (${findings.length} total)</h2>
    ${findingsHtml}
    <div class="footer">
      <p>RedGun Security Scanner v1.1.0 | Enhanced</p>
    </div>
  </div>
</body>
</html>`;

  writeFileSync(filepath, html);
  return filepath;
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
