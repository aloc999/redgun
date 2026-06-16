const findings = [];

export function addFinding(severity, module, title, details, fix) {
  findings.push({
    severity: severity.toUpperCase(),
    module,
    title,
    details,
    fix,
    timestamp: new Date().toISOString(),
  });
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

export function getSeverityCounts() {
  return {
    critical: findings.filter((f) => f.severity === 'CRITICAL').length,
    high: findings.filter((f) => f.severity === 'HIGH').length,
    medium: findings.filter((f) => f.severity === 'MEDIUM').length,
    low: findings.filter((f) => f.severity === 'LOW').length,
    info: findings.filter((f) => f.severity === 'INFO').length,
  };
}
