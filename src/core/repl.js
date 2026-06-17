import { createInterface } from 'readline';
import { fetchText } from '../utils/fetch.js';
import { getFindings, addFinding } from './findings.js';

let currentOrigin = '';

export async function startRepl(origin = '') {
  currentOrigin = origin;
  const rl = createInterface({ input: process.stdin, output: process.stdout, prompt: 'redgun> ' });
  console.log('\n  RedGun REPL — type commands or raw HTTP requests\n  Commands: get <url>, post <url> <body>, xss <param>, sqli <param>, findings, score, exit\n');

  rl.prompt();

  for await (const line of rl) {
    const cmd = line.trim();
    if (!cmd) { rl.prompt(); continue; }
    if (cmd === 'exit') break;

    try {
      if (cmd === 'findings') {
        const findings = getFindings();
        console.log(findings.length === 0 ? '  No findings yet.' : findings.map(f => `  [${f.severity}] ${f.module}: ${f.title}`).join('\n'));
      } else if (cmd === 'score') {
        const { calculateScore, getGrade } = await import('./score.js');
        const s = calculateScore();
        console.log(`  Score: ${s}/100 (${getGrade(s)})`);
      } else if (cmd.startsWith('get ')) {
        const url = cmd.slice(4).trim();
        const resp = await fetchText(url.startsWith('http') ? url : `${currentOrigin}${url}`, {}, 10000);
        console.log(`  Status: ${resp.status}\n  Size: ${resp.body.length}B\n  Headers: ${JSON.stringify(resp.headers).substring(0, 200)}`);
      } else if (cmd.startsWith('post ')) {
        const parts = cmd.slice(5).split(' ');
        const url = parts[0];
        const body = parts.slice(1).join(' ');
        const resp = await fetchText(url.startsWith('http') ? url : `${currentOrigin}${url}`, { method: 'POST', body }, 10000);
        console.log(`  Status: ${resp.status}\n  Body: ${resp.body.substring(0, 500)}`);
      } else if (cmd.startsWith('xss ')) {
        const param = cmd.slice(4).trim();
        const payload = '<script>alert(1)</script>';
        const resp = await fetchText(`${currentOrigin}/?${param}=${encodeURIComponent(payload)}`, {}, 5000);
        const reflected = resp.body.includes(payload);
        console.log(`  Reflected: ${reflected ? 'YES ⚠' : 'No'}\n  Status: ${resp.status}`);
        if (reflected) addFinding('HIGH', 'REPL XSS', `XSS via ?${param}=`, `Reflected: ${payload.substring(0, 30)}`, 'Sanitize output');
      } else if (cmd.startsWith('sqli ')) {
        const param = cmd.slice(5).trim();
        const resp = await fetchText(`${currentOrigin}/?${param}=${encodeURIComponent("'")}`, {}, 5000);
        const error = /sql|syntax|mysql|postgresql/i.test(resp.body);
        console.log(`  SQL error: ${error ? 'YES ⚠' : 'No'}\n  Status: ${resp.status}`);
        if (error) addFinding('HIGH', 'REPL SQLi', `SQLi via ?${param}=`, 'SQL error in response', 'Use parameterized queries');
      } else if (cmd.startsWith('set ')) {
        currentOrigin = cmd.slice(4).trim();
        console.log(`  Origin set to: ${currentOrigin}`);
      } else {
        console.log('  Unknown command. Try: get, post, xss, sqli, findings, score, set, exit');
      }
    } catch (e) {
      console.log(`  Error: ${e.message}`);
    }
    rl.prompt();
  }

  rl.close();
}
