import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';
import { getFindings, getSeverityCounts, getValidationStats } from '../findings.js';
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
  const vstats = getValidationStats();
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
      const vBadge = f.validated
        ? (f.exploitability === 'confirmed' ? '<span style="background:#238636;color:#fff;padding:1px 6px;border-radius:3px;font-size:0.8em">CONFIRMED</span>'
          : f.exploitability === 'rejected' ? '<span style="background:#da3633;color:#fff;padding:1px 6px;border-radius:3px;font-size:0.8em">REJECTED</span>'
          : '<span style="background:#d29922;color:#fff;padding:1px 6px;border-radius:3px;font-size:0.8em">INCONCLUSIVE</span>')
        : '';
      const confidenceBar = f.validated && f.confidence > 0
        ? `<div style="margin:4px 0;background:#21262d;border-radius:4px;height:6px"><div style="width:${f.confidence}%;height:6px;border-radius:4px;background:${f.confidence >= 70 ? '#238636' : f.confidence >= 40 ? '#d29922' : '#da3633'}"></div></div><span style="font-size:0.8em;color:#8b949e">Confidence: ${f.confidence}%</span>`
        : '';
      findingsHtml += `
        <div class="finding" style="border-left:4px solid ${severityColors[sev]}">
          <strong>[${f.module}]</strong> ${escapeHtml(f.title)} ${vBadge}
          ${confidenceBar}
          ${f.details ? `<p class="details">${escapeHtml(f.details)}</p>` : ''}
          ${f.validationNote && f.validated ? `<p class="valnote" style="color:#d2a8ff;font-size:0.9em">Validation: ${escapeHtml(f.validationNote)}</p>` : ''}
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
    ${vstats.validated > 0 ? `
    <div style="background:#161b22;border-radius:12px;padding:1rem;margin:1rem 0;text-align:center">
      <strong style="color:#58a6ff">Validation Results</strong>
      <div class="counts" style="margin-top:0.5rem">
        <div class="count-item"><div class="count-num" style="color:#238636">${vstats.confirmed}</div>Confirmed</div>
        <div class="count-item"><div class="count-num" style="color:#d29922">${vstats.inconclusive}</div>Inconclusive</div>
        <div class="count-item"><div class="count-num" style="color:#da3633">${vstats.rejected}</div>Rejected</div>
      </div>
    </div>` : ''}
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
