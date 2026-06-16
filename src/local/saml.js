import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';

const SCAN_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.py', '.rb', '.php', '.java', '.go', '.xml', '.env', '.conf', '.yml', '.yaml'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '__pycache__', 'vendor'];

export async function auditSaml(projectPath, spinner) {
  spinner.text = 'Scanning for SAML/SSO vulnerabilities...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      const patterns = [
        { pattern: /signature\s*.*(?:skip|disabled?|false|none)/gi, name: 'SAML signature validation disabled/skipped', severity: 'CRITICAL' },
        { pattern: /(?:validate|verify|check).*signature\s*.*(?:false|null|undefined|skip)/gi, name: 'Signature verification disabled', severity: 'CRITICAL' },
        { pattern: /wantAssertionsSigned\s*[:=]\s*false/gi, name: 'Assertions signing not required', severity: 'HIGH' },
        { pattern: /wantAuthnRequestsSigned\s*[:=]\s*false/gi, name: 'AuthnRequest signing not required', severity: 'HIGH' },
        { pattern: /(?:IDP|idp|identityProvider).*(?:metadata|config|cert|certificate).*url\s*=.*(?:http:\/\/|request)/gi, name: 'IdP metadata from dynamic/untrusted URL', severity: 'HIGH' },
        { pattern: /saml2\.validatePostResponse\s*\(/gi, name: 'SAML response validation (check for XSW)', severity: 'MEDIUM' },
        { pattern: /saml2\.validateRedirect\s*\(/gi, name: 'SAML redirect binding', severity: 'INFO' },
        { pattern: /(?:audience|AudienceRestriction)\s*.*(?:skip|disabled?|false)/gi, name: 'Audience restriction disabled', severity: 'HIGH' },
        { pattern: /(?:entityID|issuer)\s*.*(?:check|validate)\s*.*(?:false|skip)/gi, name: 'Entity ID validation skipped', severity: 'MEDIUM' },
        { pattern: /(?:notBefore|NotOnOrAfter|notOnOrAfter|clockSkew|skew)\s*[:=]\s*\d{4,}/gi, name: 'Large SAML clock skew (replay risk)', severity: 'LOW' },
        { pattern: /NameID\s*.*(?:req|request|input|body|query|params|user)/gi, name: 'NameID from user input', severity: 'CRITICAL' },
        { pattern: /(?:attributes?|AttributeStatement)\s*.*(?:req|request|input|body)/gi, name: 'SAML attributes from user input', severity: 'CRITICAL' },
        { pattern: /InResponseTo\s*.*(?:skip|disabled?|false|null)/gi, name: 'InResponseTo validation skipped', severity: 'HIGH' },
        { pattern: /(?:SP|serviceProvider|SAML).*(?:cert|certificate)\s*[:=]\s*['"]/gi, name: 'SAML certificate hardcoded in code', severity: 'LOW' },
        { pattern: /XMLSignature\s*\(\s*\)/gi, name: 'XML signature object (check for XSW bypass)', severity: 'MEDIUM' },
        { pattern: /(?:find|query|select)(?:Selector)?\s*\(\s*['"]\/*\/(?:\w+:)?Assertion['"]\s*\)/gi, name: 'XPath query for Assertion (XSW vulnerability)', severity: 'HIGH' },
        { pattern: /(?:find|query|select)(?:Selector)?\s*\(\s*['"](?:\w+:)?(?:AttributeStatement|NameID|Subject)['"]\s*\)/gi, name: 'XPath query for SAML elements (check for XSW)', severity: 'MEDIUM' },
      ];

      for (const { pattern, name, severity } of patterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          const line = lines[lineNum - 1]?.trim() || '';
          if (line.startsWith('//') || line.startsWith('#') || line.startsWith('*')) continue;

          addFinding(
            severity,
            'SAML/SSO Attacks',
            name,
            `File: ${relativePath}:${lineNum}\nCode: ${line.substring(0, 120)}`,
            'Validate SAML signatures with trusted Identity Provider certificates. Never accept unsigned assertions. Use XML Signature Wrapping (XSW) defenses: validate the exact XPath of signed elements. Always enforce audience restriction and InResponseTo. Do not accept NameID or attributes from user input.'
          );
        }
      }
    } catch {}
  }
}

function getFiles(dir, files = []) {
  try {
    const entries = readdirSync(dir);
    for (const entry of entries) {
      if (IGNORE_DIRS.includes(entry) || entry.startsWith('.')) continue;
      const fullPath = join(dir, entry);
      try {
        const stat = statSync(fullPath);
        if (stat.isDirectory()) getFiles(fullPath, files);
        else if (SCAN_EXTENSIONS.includes(extname(entry).toLowerCase()) && stat.size < 1024 * 1024) files.push(fullPath);
      } catch {}
    }
  } catch {}
  return files;
}
