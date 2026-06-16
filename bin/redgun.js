#!/usr/bin/env node

import { Command } from 'commander';
import inquirer from 'inquirer';
import ora from 'ora';
import chalk from 'chalk';
import { resolve } from 'path';
import { existsSync } from 'fs';

import { clearFindings } from '../src/core/findings.js';
import { calculateScore, getGrade } from '../src/core/score.js';
import { printBanner, printResults } from '../src/core/reporter/console.js';
import { exportJson, exportSarif } from '../src/core/reporter/json.js';
import { exportHtml } from '../src/core/reporter/html.js';
import { runLocalAudit, LOCAL_MODULES } from '../src/local/index.js';
import { runRemoteScan } from '../scan.js';

const program = new Command();

program
  .name('redgun')
  .description('Black-box & white-box security auditor for web applications (HackTricks Enhanced)')
  .version('1.0.0');

program
  .command('scan')
  .description('Remote scan (black-box) - give it a URL')
  .argument('[url]', 'Target URL to scan')
  .option('--modules <modules>', 'Comma-separated list of modules to run')
  .action(async (url, options) => {
    printBanner();
    showDisclaimer();

    if (!url) {
      const answers = await inquirer.prompt([{
        type: 'input',
        name: 'url',
        message: 'Target URL:',
        validate: (v) => v.startsWith('http') ? true : 'Must start with http:// or https://',
      }]);
      url = answers.url;
    }

    if (!url.startsWith('http')) url = `https://${url}`;

    clearFindings();
    const spinner = ora('Starting remote scan...').start();

    try {
      const modules = options.modules ? options.modules.split(',') : null;
      await runRemoteScan(url, spinner, modules);
      spinner.succeed('Remote scan complete');
    } catch (err) {
      spinner.fail(`Scan error: ${err.message}`);
    }

    const { score, grade } = printResults();
    const jsonPath = exportJson();
    const htmlPath = exportHtml();
    console.log(chalk.gray(`  Reports saved: ${jsonPath}`));
    console.log(chalk.gray(`  HTML report: ${htmlPath}\n`));
  });

program
  .command('audit')
  .description('Local audit (white-box) - point it at your project')
  .argument('[path]', 'Project path to audit', '.')
  .option('--ci', 'CI mode - exit 1 if score below threshold')
  .option('--min-score <score>', 'Minimum score (default: 70)', '70')
  .option('--modules <modules>', 'Comma-separated list of modules to run')
  .option('--json', 'Output JSON report')
  .option('--html', 'Output HTML report')
  .option('--sarif', 'Output SARIF report')
  .action(async (projectPath, options) => {
    printBanner();

    const absPath = resolve(projectPath);
    if (!existsSync(absPath)) {
      console.error(chalk.red(`Error: Path does not exist: ${absPath}`));
      process.exit(1);
    }

    clearFindings();
    const spinner = ora('Starting local audit...').start();

    try {
      const modules = options.modules ? options.modules.split(',') : null;
      await runLocalAudit(absPath, spinner, modules);
      spinner.succeed('Local audit complete');
    } catch (err) {
      spinner.fail(`Audit error: ${err.message}`);
    }

    const { score, grade } = printResults();

    const jsonPath = exportJson();
    console.log(chalk.gray(`  JSON report: ${jsonPath}`));

    if (options.html || !options.ci) {
      const htmlPath = exportHtml();
      console.log(chalk.gray(`  HTML report: ${htmlPath}`));
    }

    if (options.sarif) {
      const sarifPath = exportSarif();
      console.log(chalk.gray(`  SARIF report: ${sarifPath}`));
    }

    console.log('');

    if (options.ci) {
      const minScore = parseInt(options.minScore, 10);
      if (score < minScore) {
        console.error(chalk.red(`  FAILED: Score ${score} is below minimum ${minScore}`));
        process.exit(1);
      } else {
        console.log(chalk.green(`  PASSED: Score ${score} meets minimum ${minScore}`));
      }
    }
  });

program
  .command('history')
  .description('View saved scan reports')
  .action(async () => {
    const { readdirSync } = await import('fs');
    const { join } = await import('path');
    const scansDir = './scans';

    if (!existsSync(scansDir)) {
      console.log(chalk.yellow('No scan history found.'));
      return;
    }

    const files = readdirSync(scansDir).filter((f) => f.endsWith('.json')).sort().reverse();
    if (files.length === 0) {
      console.log(chalk.yellow('No scan history found.'));
      return;
    }

    console.log(chalk.bold('\n  Scan History:\n'));
    for (const file of files.slice(0, 20)) {
      console.log(`  ${chalk.gray('•')} ${file}`);
    }
    console.log('');
  });

program
  .command('modules')
  .description('List available scan modules')
  .action(() => {
    printBanner();
    console.log(chalk.bold('\n  Local Audit Modules (White-box):\n'));
    for (const mod of LOCAL_MODULES) {
      console.log(`  ${chalk.green('•')} ${mod.name} ${chalk.gray(`[${mod.value}]`)}`);
    }
    console.log(chalk.bold('\n  Remote Scan Modules (Black-box):\n'));
    const remoteModules = [
      'headers', 'files', 'secrets', 'xss', 'sqli', 'cors', 'redirect',
      'ssrf', 'hostheader', 'smuggling', 'crlf', 'graphql', 'clickjack',
      'cookies', 'methods', 'subdomains', 'dns', 'tech', 'api', 'ssl',
      'lfi', 'nosqli', 'websocket', 'cache', 'race',
    ];
    for (const mod of remoteModules) {
      console.log(`  ${chalk.red('•')} ${mod}`);
    }
    console.log('');
  });

if (process.argv.length <= 2) {
  printBanner();
  inquirer.prompt([{
    type: 'list',
    name: 'mode',
    message: 'What would you like to do?',
    choices: [
      { name: 'Remote scan (black-box) - scan a URL', value: 'scan' },
      { name: 'Local audit (white-box) - audit source code', value: 'audit' },
      { name: 'View scan history', value: 'history' },
      { name: 'List modules', value: 'modules' },
    ],
  }]).then((answers) => {
    const args = ['node', 'redgun', answers.mode];
    if (answers.mode === 'audit') args.push('.');
    program.parse(args);
  });
} else {
  program.parse();
}

function showDisclaimer() {
  console.log(chalk.yellow.bold('  ⚠ DISCLAIMER'));
  console.log(chalk.yellow('  This tool is for authorized security testing only.'));
  console.log(chalk.yellow('  You are responsible for how you use it.\n'));
}
