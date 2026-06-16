const findings = [];

export function addFinding(severity, module, title, details, fix) {
  findings.push({
    severity: severity.toUpperCase(),
    module,
    title,
    details,
    fix,
    timestamp: new Date().toISOString(),
    validated: false,
    confidence: 0,
    exploitability: null,
    validationNote: null,
  });
}

export function updateFinding(index, updates) {
  if (findings[index]) {
    Object.assign(findings[index], updates);
  }
}

export function getFindings() {
  return [...findings];
}

export function clearFindings() {
  findings.length = 0;
}

export function getFindingsBySeverity(severity) {
  return findings.filter((f) => f.severity === severity.toUpperCase());
}

export function getFindingsByModule(module) {
  return findings.filter((f) => f.module === module);
}

export function removeFalsePositives() {
  for (let i = findings.length - 1; i >= 0; i--) {
    if (findings[i].validated && findings[i].confidence < 30) {
      findings.splice(i, 1);
    }
  }
}

export function getSeverityCounts() {
  return {
    critical: findings.filter((f) => f.severity === 'CRITICAL').length,
    high: findings.filter((f) => f.severity === 'HIGH').length,
    medium: findings.filter((f) => f.severity === 'MEDIUM').length,
    low: findings.filter((f) => f.severity === 'LOW').length,
    info: findings.filter((f) => f.severity === 'INFO').length,
  };
}

export function getValidationStats() {
  const total = findings.length;
  const validated = findings.filter((f) => f.validated).length;
  const confirmed = findings.filter((f) => f.validated && f.exploitability === 'confirmed').length;
  const inconclusive = findings.filter((f) => f.validated && f.exploitability === 'inconclusive').length;
  const rejected = findings.filter((f) => f.validated && f.exploitability === 'rejected').length;
  return { total, validated, confirmed, inconclusive, rejected };
}
