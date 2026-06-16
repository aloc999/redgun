import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';
import { getFindings, getSeverityCounts } from '../findings.js';
import { calculateScore, getGrade } from '../score.js';

export function exportJson(outputDir = './scans') {
  if (!existsSync(outputDir)) {
    mkdirSync(outputDir, { recursive: true });
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `redgun-${timestamp}.json`;
  const filepath = join(outputDir, filename);

  const report = {
    tool: 'RedGun Security Scanner',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    score: calculateScore(),
    grade: getGrade(calculateScore()),
    summary: getSeverityCounts(),
    totalFindings: getFindings().length,
    findings: getFindings(),
  };

  writeFileSync(filepath, JSON.stringify(report, null, 2));
  return filepath;
}

export function exportSarif(outputDir = './scans') {
  if (!existsSync(outputDir)) {
    mkdirSync(outputDir, { recursive: true });
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filepath = join(outputDir, `redgun-${timestamp}.sarif`);

  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'RedGun',
          version: '1.0.0',
          informationUri: 'https://github.com/aloc999/redgun',
          rules: [],
        },
      },
      results: getFindings().map((f, i) => ({
        ruleId: `REDGUN-${String(i + 1).padStart(3, '0')}`,
        level: f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'error' : f.severity === 'MEDIUM' ? 'warning' : 'note',
        message: { text: `[${f.module}] ${f.title}: ${f.details || ''}` },
        locations: f.file ? [{
          physicalLocation: {
            artifactLocation: { uri: f.file },
            region: f.line ? { startLine: f.line } : undefined,
          },
        }] : [],
      })),
    }],
  };

  writeFileSync(filepath, JSON.stringify(sarif, null, 2));
  return filepath;
}
