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
import { auditSaml } from './saml.js';
import { auditLdap } from './ldap.js';
import { auditCsrf } from './csrf.js';
import { auditAto } from './ato.js';
import { auditCloud } from './cloud.js';
import { auditCicd } from './cicd.js';
import { auditMobile } from './mobile.js';
import { auditWeb3 } from './web3.js';
import { auditXpathSsi } from './xpath-ssi.js';
import { auditTiming } from './timing.js';
import { auditJwtAdvanced } from './jwt-advanced.js';
import { auditCsti } from './csti.js';
import { auditServiceWorker } from './service-worker.js';
import { auditPaddingOracle } from './padding-oracle.js';
import { auditLlmAi } from './llm-ai.js';
import { auditCssInjection } from './css-injection.js';
import { auditPostMessage } from './postmessage.js';
import { auditElectron } from './electron.js';
import { auditWebauthn } from './webauthn.js';
import { auditSupplyChainAdvanced } from './supply-chain-advanced.js';
import { auditClientProto } from './client-proto.js';
import { auditRemainingVulns } from './remaining-vulns.js';

export const LOCAL_MODULES = [
  { name: 'Code Secrets', value: 'secrets', fn: auditSecrets },
  { name: 'Environment Files', value: 'env', fn: auditEnv },
  { name: 'Dependencies (npm audit)', value: 'deps', fn: auditDependencies },
  { name: 'Code Vulnerabilities (SQLi, XSS)', value: 'codevuln', fn: auditCodeVulnerabilities },
  { name: 'Auth & Middleware', value: 'auth', fn: auditAuth },
  { name: 'Headers Config (CSP/HSTS)', value: 'headers', fn: auditHeadersConfig },
  { name: 'SSRF Detection', value: 'ssrf', fn: auditSsrf },
  { name: 'SSTI Detection', value: 'ssti', fn: auditSsti },
  { name: 'Insecure Deserialization', value: 'deser', fn: auditDeserialization },
  { name: 'Prototype Pollution', value: 'proto', fn: auditPrototypePollution },
  { name: 'JWT Vulnerabilities', value: 'jwt', fn: auditJwt },
  { name: 'Path Traversal / LFI', value: 'lfi', fn: auditPathTraversal },
  { name: 'Command Injection', value: 'cmdi', fn: auditCommandInjection },
  { name: 'Weak Cryptography', value: 'crypto', fn: auditCrypto },
  { name: 'XXE - XML External Entity (PortSwigger)', value: 'xxe', fn: auditXxe },
  { name: 'Access Control / IDOR (PortSwigger)', value: 'idor', fn: auditAccessControl },
  { name: 'OAuth / OIDC Flaws (PortSwigger)', value: 'oauth', fn: auditOauth },
  { name: 'Business Logic Flaws (PortSwigger)', value: 'bizlogic', fn: auditBusinessLogic },
  { name: 'SAML / SSO Attacks', value: 'saml', fn: auditSaml },
  { name: 'LDAP Injection', value: 'ldap', fn: auditLdap },
  { name: 'CSRF Token Analysis', value: 'csrf', fn: auditCsrf },
  { name: 'Account Takeover (ATO)', value: 'ato', fn: auditAto },
  { name: 'Cloud Misconfig (S3/IAM)', value: 'cloud', fn: auditCloud },
  { name: 'CI/CD Pipeline', value: 'cicd', fn: auditCicd },
  { name: 'Mobile Security', value: 'mobile', fn: auditMobile },
  { name: 'Web3 / Smart Contracts', value: 'web3', fn: auditWeb3 },
  { name: 'XPath / SSI Injection', value: 'xpath', fn: auditXpathSsi },
  { name: 'Timing Side-Channels', value: 'timing', fn: auditTiming },
  { name: 'JWT Advanced (kid, JWK, jku)', value: 'jwtadv', fn: auditJwtAdvanced },
  { name: 'Client-Side Template Injection (CSTI)', value: 'csti', fn: auditCsti },
  { name: 'Service Worker / WebRTC', value: 'sworker', fn: auditServiceWorker },
  { name: 'Padding / Compression Oracle', value: 'padding', fn: auditPaddingOracle },
  { name: 'AI/LLM Prompt Injection', value: 'llmai', fn: auditLlmAi },
  { name: 'CSS Injection/Exfiltration', value: 'css', fn: auditCssInjection },
  { name: 'PostMessage / BroadcastChannel', value: 'postmsg', fn: auditPostMessage },
  { name: 'Electron / React Native', value: 'electron', fn: auditElectron },
  { name: 'WebAuthn / Passkeys', value: 'passkey', fn: auditWebauthn },
  { name: 'Supply Chain (dep confusion, lockfile)', value: 'supply', fn: auditSupplyChainAdvanced },
  { name: 'Client-Side Proto Pollution Gadgets', value: 'cproto', fn: auditClientProto },
  { name: 'Mass Assignment, XSSI, Tabnabbing, Cookie Tossing, Type Confusion, Response Splitting, SQL Trunc, SRI, OG Injection', value: 'remaining', fn: auditRemainingVulns },
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
