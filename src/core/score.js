import { getFindings } from './findings.js';

const SEVERITY_WEIGHTS = {
  CRITICAL: -15,
  HIGH: -8,
  MEDIUM: -3,
  LOW: -1,
  INFO: 0,
};

export function calculateScore() {
  const findings = getFindings();
  let score = 100;

  for (const finding of findings) {
    score += SEVERITY_WEIGHTS[finding.severity] || 0;
  }

  return Math.max(0, Math.min(100, score));
}

export function getGrade(score) {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  if (score >= 50) return 'E';
  return 'F';
}

export function getGradeColor(grade) {
  const colors = {
    A: '#4caf50',
    B: '#8bc34a',
    C: '#ffeb3b',
    D: '#ff9800',
    E: '#ff5722',
    F: '#f44336',
  };
  return colors[grade] || '#f44336';
}
