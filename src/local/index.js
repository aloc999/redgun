import { auditSecrets } from './secrets.js';
import { auditEnv } from './env.js';
import { auditDependencies } from './dependencies.js';
import { auditCodeVulnerabilities } from './code-vulnerabilities.js';
import { auditAuth } from './auth.js';
import { auditHeadersConfig } from './headers-config.js';
import { auditSsrf } from './ssrf.js';
import { auditSsti } from './ssti.js';
import { auditDeserialization } from './deserialization.js';
import { auditPrototypePollution } from './prototype-pollution.js';
import { auditJwt } from './jwt.js';
import { auditPathTraversal } from './path-traversal.js';
import { auditCommandInjection } from './command-injection.js';
import { auditCrypto } from './crypto.js';
import { auditXxe } from './xxe.js';
import { auditAccessControl } from './access-control.js';
import { auditOauth } from './oauth.js';
import { auditBusinessLogic } from './business-logic.js';

export const LOCAL_MODULES = [
  { name: 'Code Secrets', value: 'secrets', fn: auditSecrets },
  { name: 'Environment Files', value: 'env', fn: auditEnv },
  { name: 'Dependencies (npm audit)', value: 'deps', fn: auditDependencies },
  { name: 'Code Vulnerabilities (SQLi, XSS)', value: 'codevuln', fn: auditCodeVulnerabilities },
  { name: 'Auth & Middleware', value: 'auth', fn: auditAuth },
  { name: 'Headers Config (CSP/HSTS)', value: 'headers', fn: auditHeadersConfig },
  { name: 'SSRF Detection (HackTricks)', value: 'ssrf', fn: auditSsrf },
  { name: 'SSTI Detection (HackTricks)', value: 'ssti', fn: auditSsti },
  { name: 'Insecure Deserialization (HackTricks)', value: 'deser', fn: auditDeserialization },
  { name: 'Prototype Pollution (HackTricks)', value: 'proto', fn: auditPrototypePollution },
  { name: 'JWT Vulnerabilities (HackTricks)', value: 'jwt', fn: auditJwt },
  { name: 'Path Traversal / LFI (HackTricks)', value: 'lfi', fn: auditPathTraversal },
  { name: 'Command Injection (HackTricks)', value: 'cmdi', fn: auditCommandInjection },
  { name: 'Weak Cryptography (HackTricks)', value: 'crypto', fn: auditCrypto },
  { name: 'XXE - XML External Entity (PortSwigger)', value: 'xxe', fn: auditXxe },
  { name: 'Access Control / IDOR (PortSwigger)', value: 'idor', fn: auditAccessControl },
  { name: 'OAuth / OIDC Flaws (PortSwigger)', value: 'oauth', fn: auditOauth },
  { name: 'Business Logic Flaws (PortSwigger)', value: 'bizlogic', fn: auditBusinessLogic },
];

export async function runLocalAudit(projectPath, spinner, modules = null) {
  const toRun = modules
    ? LOCAL_MODULES.filter((m) => modules.includes(m.value))
    : LOCAL_MODULES;

  for (const mod of toRun) {
    try {
      spinner.text = `Running: ${mod.name}...`;
      await mod.fn(projectPath, spinner);
    } catch (err) {
      spinner.text = `Error in ${mod.name}: ${err.message}`;
    }
  }
}
