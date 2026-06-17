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
import { createSession, listProfiles, loadProfile } from '../src/core/session.js';
import { setProxy } from '../src/core/proxy.js';
import { diffScans, exportBurpXml, setLogLevel, setCustomWordlist, setWebhook, generatePdf, sendWebhook, log } from '../src/core/advanced-features.js';
import { setRateLimit } from '../src/utils/fetch.js';
import { getFindings } from '../src/core/findings.js';

const program = new Command();

program
  .name('redgun')
  .description('Black-box & white-box security auditor for web applications (Enhanced)')
  .version('2.2.0');

program
  .command('scan')
  .description('Remote scan (black-box) - give it a URL')
  .argument('[url]', 'Target URL to scan')
  .option('--modules <modules>', 'Comma-separated list of modules to run')
  .option('--proxy <url>', 'HTTP proxy (e.g. http://127.0.0.1:8080 for Burp/Zap)')
  .option('--auth <name>', 'Use saved auth profile')
  .option('--auth-method <method>', 'Auth method: form/cookie/bearer/basic')
  .option('--auth-login <url>', 'Login URL for form auth')
  .option('--auth-user <user>', 'Username/email')
  .option('--auth-pass <pass>', 'Password')
  .option('--auth-token <token>', 'Bearer token or cookie value')
  .option('--auth-token-field <field>', 'JSON field for token extraction')
  .option('--scope <file>', 'File with URLs to scan (one per line)')
  .option('--fuzz', 'Enable wordlist fuzzing')
  .option('--burp', 'Export findings as Burp XML')
  .option('--resume', 'Resume last interrupted scan')
  .option('--rate <rps>', 'Requests per second (default: 5)')
  .option('--wordlist <file>', 'Custom wordlist for fuzzer')
  .option('--webhook <url>', 'Discord/Slack webhook for notifications')
  .option('--log-level <level>', 'Log level: debug, info, warn, error, quiet')
  .option('--pdf', 'Generate PDF report')
  .action(async (url, options) => {
    printBanner();
    showDisclaimer();

    if (options.proxy) {
      setProxy(options.proxy);
      console.log(chalk.gray(`  Proxy: ${options.proxy}`));
    }

    if (options.rate) {
      setRateLimit(parseInt(options.rate, 10));
      console.log(chalk.gray(`  Rate limit: ${options.rate} req/s`));
    }

    if (options.wordlist) {
      setCustomWordlist(options.wordlist);
      console.log(chalk.gray(`  Wordlist: ${options.wordlist}`));
    }

    if (options.webhook) {
      setWebhook(options.webhook);
      console.log(chalk.gray(`  Webhook: configured`));
    }

    if (options.logLevel) {
      setLogLevel(options.logLevel);
    }

    const spinner = ora('Preparing...').start();

    if (options.auth || options.authMethod) {
      const profile = options.auth ? loadProfile(options.auth) : null;
      const authConfig = profile || {
        name: options.auth || 'default',
        method: options.authMethod || 'form',
        loginUrl: options.authLogin,
        targetUrl: url,
        credentials: { email: options.authUser, password: options.authPass },
        token: options.authToken,
        cookie: options.authToken,
        tokenField: options.authTokenField,
        extraHeaders: {},
      };
      await createSession(authConfig, spinner);
    }

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
    spinner.text = 'Starting remote scan...';

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
    console.log(chalk.gray(`  HTML report: ${htmlPath}`));

    if (options.burp) {
      console.log(chalk.gray(`  Burp export: ./scans/burp-export.xml`));
    }

    if (options.pdf) {
      const pdfPath = await generatePdf(
        { score, grade, totalFindings: getFindings().length, findings: getFindings(), url },
        `./scans/redgun-report-${Date.now()}.pdf`
      );
      console.log(chalk.gray(`  PDF report: ${pdfPath}`));
    }

    if (options.webhook) {
      await sendWebhook({
        url, score, grade, totalFindings: getFindings().length,
        critical: getFindings().filter(f => f.severity === 'CRITICAL').length,
      });
      console.log(chalk.gray('  Webhook notification sent'));
    }

    console.log('');
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

program
  .command('diff')
  .description('Diff two scan reports')
  .argument('<fileA>', 'First scan JSON')
  .argument('<fileB>', 'Second scan JSON')
  .action(async (fileA, fileB) => {
    printBanner();
    clearFindings();
    const spinner = ora('Comparing scans...').start();
    await diffScans(fileA, fileB, spinner);
    spinner.succeed('Diff complete');
    printResults();
  });

program
  .command('auth')
  .description('Manage auth profiles')
  .argument('[action]', 'Action: add, list, remove')
  .option('--name <name>', 'Profile name')
  .option('--method <method>', 'Auth method: form/cookie/bearer/basic')
  .option('--login <url>', 'Login URL')
  .option('--user <user>', 'Username')
  .option('--pass <pass>', 'Password')
  .option('--token <token>', 'Token or cookie')
  .action(async (action, opts) => {
    const { writeFileSync, unlinkSync, existsSync } = await import('fs');
    const { join } = await import('path');
    const PROFILES_DIR = '.redgun/profiles';

    if (action === 'list') {
      const profiles = listProfiles();
      console.log(profiles.length > 0
        ? chalk.bold('\n  Auth Profiles:\n') + profiles.map(p => `  ${chalk.green('•')} ${p}`).join('\n') + '\n'
        : chalk.yellow('\n  No profiles saved.\n'));
    } else if (action === 'add' && opts.name) {
      if (!existsSync(PROFILES_DIR)) {
        const { mkdirSync } = await import('fs');
        mkdirSync(PROFILES_DIR, { recursive: true });
      }
      writeFileSync(join(PROFILES_DIR, `${opts.name}.json`), JSON.stringify({
        name: opts.name, method: opts.method || 'bearer',
        loginUrl: opts.login, credentials: { email: opts.user, password: opts.pass },
        token: opts.token, tokenField: 'token',
        targetUrl: '', extraHeaders: {},
      }, null, 2));
      console.log(chalk.green(`\n  Profile '${opts.name}' saved.\n`));
    } else if (action === 'remove' && opts.name) {
      const path = join(PROFILES_DIR, `${opts.name}.json`);
      if (existsSync(path)) { unlinkSync(path); console.log(chalk.green(`\n  Profile '${opts.name}' removed.\n`)); }
      else { console.log(chalk.red(`\n  Profile '${opts.name}' not found.\n`)); }
    } else {
      console.log(chalk.gray('\n  Usage: redgun auth [add|list|remove] --name <profile>\n'));
    }
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
