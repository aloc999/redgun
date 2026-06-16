import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';

const SCAN_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.py', '.rb', '.php', '.go', '.java', '.env'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '__pycache__', 'vendor'];

export async function auditOauth(projectPath, spinner) {
  spinner.text = 'Scanning for OAuth/OIDC vulnerabilities (PortSwigger)...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      const patterns = [
        { pattern: /redirect_uri\s*[:=]\s*(?:req|params|query|body|request)/gi, name: 'OAuth redirect_uri from user input (open redirect → token theft)', severity: 'CRITICAL' },
        { pattern: /state\s*[:=]\s*(?:null|undefined|''|"")|(?:!state|state\s*===?\s*(?:null|undefined))/gi, name: 'OAuth state parameter missing/null (CSRF)', severity: 'HIGH' },
        { pattern: /response_type\s*[:=]\s*['"]token['"]/gi, name: 'OAuth implicit flow (token in URL fragment)', severity: 'MEDIUM' },
        { pattern: /client_secret\s*[:=]\s*['"][^'"]{5,}['"]/gi, name: 'OAuth client_secret hardcoded', severity: 'HIGH' },
        { pattern: /grant_type\s*[:=]\s*['"]password['"]/gi, name: 'OAuth Resource Owner Password grant (insecure)', severity: 'MEDIUM' },
        { pattern: /(?:GOOGLE|GITHUB|FACEBOOK|TWITTER|OAUTH)_CLIENT_SECRET\s*=\s*['"]?[A-Za-z0-9_-]{10,}/gi, name: 'OAuth provider secret in source', severity: 'HIGH' },
        { pattern: /(?:openid|oauth|oidc).*(?:nonce|at_hash)\s*.*(?:skip|ignore|false)/gi, name: 'OAuth nonce/at_hash validation disabled', severity: 'HIGH' },
        { pattern: /(?:verify|validate).*(?:state|nonce)\s*.*(?:false|skip|disabled)/gi, name: 'OAuth state/nonce verification disabled', severity: 'CRITICAL' },
        { pattern: /scope\s*[:=]\s*['"].*(?:admin|write|delete|manage)/gi, name: 'OAuth requesting elevated scopes', severity: 'LOW' },
        { pattern: /token_endpoint_auth_method\s*[:=]\s*['"]none['"]/gi, name: 'OAuth no client authentication', severity: 'HIGH' },
        { pattern: /id_token.*(?:decode|parse).*(?:!verify|verify\s*[:=]\s*false)/gi, name: 'OIDC id_token not verified', severity: 'CRITICAL' },
        { pattern: /(?:access_token|refresh_token)\s*[:=].*(?:localStorage|sessionStorage)/gi, name: 'OAuth tokens stored in browser storage (XSS theft)', severity: 'HIGH' },
        { pattern: /PKCE|code_challenge|code_verifier/gi, name: 'PKCE usage detected (good practice)', severity: 'INFO' },
      ];

      for (const { pattern, name, severity } of patterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          const line = lines[lineNum - 1]?.trim() || '';
          if (line.startsWith('//') || line.startsWith('#')) continue;

          addFinding(
            severity,
            'OAuth/OIDC (PortSwigger)',
            name,
            `File: ${relativePath}:${lineNum}\nCode: ${line.substring(0, 120)}`,
            'Use Authorization Code flow with PKCE. Validate state parameter to prevent CSRF. Whitelist redirect_uris server-side. Never expose client_secret in client-side code. Store tokens in httpOnly cookies, not localStorage.'
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
        else if (SCAN_EXTENSIONS.includes(extname(entry).toLowerCase()) && stat.size < 512 * 1024) files.push(fullPath);
      } catch {}
    }
  } catch {}
  return files;
}
