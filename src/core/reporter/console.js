import chalk from 'chalk';
import { getFindings, getSeverityCounts } from '../findings.js';
import { calculateScore, getGrade } from '../score.js';

const SEVERITY_COLORS = {
  CRITICAL: chalk.bgRed.white.bold,
  HIGH: chalk.red.bold,
  MEDIUM: chalk.yellow.bold,
  LOW: chalk.blue,
  INFO: chalk.gray,
};

export function printBanner() {
  console.log(chalk.red(`
  ██████╗ ███████╗██████╗  ██████╗ ██╗   ██╗███╗   ██╗
  ██╔══██╗██╔════╝██╔══██╗██╔════╝ ██║   ██║████╗  ██║
  ██████╔╝█████╗  ██║  ██║██║  ███╗██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║  ██║██║   ██║██║   ██║██║╚██╗██║
  ██║  ██║███████╗██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝
  `));
  console.log(chalk.gray('  Black-box & white-box security auditor | Enhanced\n'));
}

export function printResults() {
  const findings = getFindings();
  const score = calculateScore();
  const grade = getGrade(score);
  const counts = getSeverityCounts();

  console.log('\n' + chalk.bold('═══════════════════════════════════════════════════════'));
  console.log(chalk.bold('  SCAN RESULTS'));
  console.log(chalk.bold('═══════════════════════════════════════════════════════\n'));

  const gradeColor = score >= 80 ? chalk.green : score >= 60 ? chalk.yellow : chalk.red;
  console.log(`  Score: ${gradeColor.bold(score + '/100')} (Grade: ${gradeColor.bold(grade)})\n`);

  console.log(`  ${SEVERITY_COLORS.CRITICAL(' CRITICAL ')} ${counts.critical}`);
  console.log(`  ${SEVERITY_COLORS.HIGH(' HIGH ')} ${counts.high}`);
  console.log(`  ${SEVERITY_COLORS.MEDIUM(' MEDIUM ')} ${counts.medium}`);
  console.log(`  ${SEVERITY_COLORS.LOW(' LOW ')} ${counts.low}`);
  console.log(`  ${SEVERITY_COLORS.INFO(' INFO ')} ${counts.info}`);
  console.log('');

  const grouped = {};
  for (const finding of findings) {
    if (!grouped[finding.module]) grouped[finding.module] = [];
    grouped[finding.module].push(finding);
  }

  for (const [module, moduleFindings] of Object.entries(grouped)) {
    console.log(chalk.bold(`\n  ┌─ ${module}`));
    for (const f of moduleFindings) {
      const color = SEVERITY_COLORS[f.severity] || chalk.white;
      console.log(`  │ ${color(`[${f.severity}]`)} ${f.title}`);
      if (f.details) console.log(`  │   ${chalk.gray(f.details.substring(0, 120))}`);
      if (f.fix) console.log(`  │   ${chalk.green('Fix:')} ${f.fix.substring(0, 120)}`);
    }
    console.log('  └─');
  }

  console.log('\n' + chalk.bold('═══════════════════════════════════════════════════════\n'));
  return { score, grade, findings: findings.length };
}
