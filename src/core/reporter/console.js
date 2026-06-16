import chalk from 'chalk';
import { getFindings, getSeverityCounts, getValidationStats } from '../findings.js';
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
  console.log(chalk.gray('  Developed by @aloc999 (Hashemi)\n'));
}

export function printResults() {
  const findings = getFindings();
  const score = calculateScore();
  const grade = getGrade(score);
  const counts = getSeverityCounts();
  const vstats = getValidationStats();

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

  if (vstats.validated > 0) {
    console.log(chalk.bold('  VALIDATION RESULTS'));
    console.log(`  ${chalk.green('✓ Confirmed')}: ${vstats.confirmed}  ` +
      `${chalk.yellow('? Inconclusive')}: ${vstats.inconclusive}  ` +
      `${chalk.red('✗ Rejected')}: ${vstats.rejected}`);
    console.log(`  ${chalk.gray('False positives eliminated:')} ${vstats.total - findings.length}`);
    if (vstats.rejected > 0) {
      console.log(`  ${chalk.red.bold('  ' + vstats.rejected + ' findings downgraded/removed after validation')}`);
    }
    console.log('');
  }

  const grouped = {};
  for (const finding of findings) {
    if (!grouped[finding.module]) grouped[finding.module] = [];
    grouped[finding.module].push(finding);
  }

  for (const [module, moduleFindings] of Object.entries(grouped)) {
    console.log(chalk.bold(`\n  ┌─ ${module}`));
    for (const f of moduleFindings) {
      const color = SEVERITY_COLORS[f.severity] || chalk.white;
      let confidenceBar = '';
      if (f.validated && f.confidence > 0) {
        const barWidth = Math.round(f.confidence / 10);
        const barColor = f.confidence >= 70 ? chalk.green : f.confidence >= 40 ? chalk.yellow : chalk.red;
        confidenceBar = `  ${barColor('█'.repeat(barWidth) + '░'.repeat(10 - barWidth))} ${f.confidence}%`;
      }
      const badge = f.validated
        ? (f.exploitability === 'confirmed' ? chalk.green.bold(' ✓CONFIRMED') :
           f.exploitability === 'rejected' ? chalk.red.bold(' ✗REJECTED') : chalk.yellow.bold(' ?INCONCLUSIVE'))
        : chalk.gray(' UNVERIFIED');
      console.log(`  │ ${color(`[${f.severity}]`)} ${f.title}${badge}`);
      if (confidenceBar) console.log(`  │  ${confidenceBar}`);
      if (f.details) console.log(`  │   ${chalk.gray(f.details.substring(0, 120))}`);
      if (f.validationNote && f.validated) {
        console.log(`  │   ${chalk.magenta('Validation:')} ${f.validationNote.substring(0, 120)}`);
      }
      if (f.fix) console.log(`  │   ${chalk.green('Fix:')} ${f.fix.substring(0, 120)}`);
    }
    console.log('  └─');
  }

  console.log('\n' + chalk.bold('═══════════════════════════════════════════════════════\n'));
  return { score, grade, findings: findings.length };
}
