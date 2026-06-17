import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';

const SCAN_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.py', '.rb', '.php', '.go', '.java', '.html', '.htm'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '__pycache__', 'vendor'];

export async function auditRemainingVulns(projectPath, spinner) {
  spinner.text = 'Mass assignment, XSSI, tabnabbing, cookie tossing, type confusion...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      const patterns = [
        { name: 'Mass assignment - Object.assign with req.body', pattern: /Object\.assign\s*\(\s*(?:new\s+)?\w+\([^)]*\)\s*,\s*(?:req|request)\.body/gi, severity: 'HIGH', module: 'Mass Assignment', fix: 'Whitelist allowed fields. Never pass req.body directly to model constructors. Use safe extraction: {name, email} = req.body' },
        { name: 'Mass assignment - Model.create/update with req.body', pattern: /\.(?:create|update(?:One|Many)?|findOneAndUpdate|insert(?:One|Many)?|save)\s*\(\s*(?:req|request)\.body/gi, severity: 'CRITICAL', module: 'Mass Assignment', fix: 'Explicitly whitelist or sanitize fields before passing to database operations' },
        { name: 'Mass assignment - Sequelize bulkCreate with body', pattern: /\.(?:bulkCreate|findOrCreate|upsert)\s*\(\s*(?:req|request)\.body/gi, severity: 'HIGH', module: 'Mass Assignment', fix: 'Use fields: option in Sequelize queries or whitelist allowed params' },
        { name: 'Mass assignment - Active Record mass assignment', pattern: /\.(?:update_attributes|update_all|create!|new)\s*\(\s*params/gi, severity: 'HIGH', module: 'Mass Assignment', fix: 'Use strong_params in Rails: params.require(:user).permit(:name, :email)' },
        { name: 'Mass assignment - ORM save with spread body', pattern: /\{\s*\.\.\.(?:req|request)\.(?:body|query|params)\s*\}/gi, severity: 'HIGH', module: 'Mass Assignment', fix: 'Avoid spread operator from request body. Destructure only needed fields.' },

        { name: 'XSSI - JSON with sensitive data in script tag', pattern: /<script[^>]*>\s*(?:const|var|let)\s+\w+\s*=\s*\{\{/gi, severity: 'MEDIUM', module: 'XSSI / Script Inclusion', fix: 'Prefix JSON responses with while(1); or {\" to prevent script inclusion. Use X-Content-Type-Options: nosniff.' },
        { name: 'XSSI - Script src loading user data', pattern: /<script[^>]*src\s*=\s*['"][^'"]*\b(?:json|data|user|account|profile|config)/gi, severity: 'MEDIUM', module: 'XSSI / Script Inclusion', fix: 'Serve JSON with proper Content-Type. Add CSRF token requirement to API endpoints.' },
        { name: 'XSSI - AngularJS JSON hijacking', pattern: /ng-init.*=(?:req|request|body|input)/gi, severity: 'MEDIUM', module: 'XSSI / Script Inclusion', fix: 'Use AngularJS v1.6+. Set pre-interpolate prefix with $interpolateProvider.startSymbol/endSymbol.' },

        { name: 'Tabnabbing - window.open without noopener', pattern: /window\.open\s*\(|target\s*=\s*['"]_blank['"](?!.*noopener)(?!.*noreferrer)/gi, severity: 'MEDIUM', module: 'Tabnabbing', fix: 'Add rel="noopener noreferrer" to target=_blank links. Set window.opener = null after window.open().' },
        { name: 'Reverse tabnabbing - window.opener access', pattern: /window\.opener\.(?:location|postMessage|document)/gi, severity: 'HIGH', module: 'Tabnabbing', fix: 'If the opened page is untrusted, the parent should set opener=null. Do not expose window.opener to untrusted targets.' },

        { name: 'Cookie tossing - Set-Cookie from user input', pattern: /Set-Cookie|cookie\.split|cookie\.match|cookie\s*\+=/gi, severity: 'MEDIUM', module: 'Cookie Tossing', fix: 'Validate cookie path/domain. Use HttpOnly + Secure. Do not set cookies from user controllable headers.' },
        { name: 'Cookie tossing - document.cookie write from input', pattern: /document\.cookie\s*\+?=\s*(?:req|params|body|input|query|location|hash)/gi, severity: 'HIGH', module: 'Cookie Tossing', fix: 'Never write user input to document.cookie. Sanitize cookie name and value.' },

        { name: 'Type confusion - PHP loose comparison', pattern: /\s*==\s*(?!\s*[\d']|\s*true|\s*false|\s*null)/gi, severity: 'MEDIUM', module: 'Type Confusion', fix: 'Use strict comparison (===) in PHP. Be aware: "0e12345" == "0e67890" is true (MD5). Use hash_equals() for comparisons.' },
        { name: 'Type confusion - PHP strcmp vulnerability', pattern: /strcmp\s*\([^,]*,\s*(?:req|request|params|body|input)/gi, severity: 'HIGH', module: 'Type Confusion', fix: 'strcmp returns NULL on array input (NULL==0 bypass). Use === or is_string() before strcmp().' },
        { name: 'Type confusion - in_array without strict', pattern: /in_array\s*\([^,]*,.*(?!true)[^)]*\)/gi, severity: 'MEDIUM', module: 'Type Confusion', fix: 'Use in_array($needle, $haystack, true) for strict type checking.' },
        { name: 'Type confusion - JS implicit coercion', pattern: /\+\s*['"`].*['"`]|['"`].*['"`]\s*\*|\s*==\s*(?!\s*[\d']|\s*true|\s*false|\s*null)/gi, severity: 'LOW', module: 'Type Confusion', fix: 'Use === in JS. Avoid unary + for type coercion. Use Number() or parseInt() explicitly.' },

        { name: 'HTTP Response Splitting - CRLF in header value', pattern: /(?:setHeader|set\(|header\()\s*\([^,]*,\s*(?:req|request|params|body|input|user)/gi, severity: 'CRITICAL', module: 'Response Splitting', fix: 'Sanitize CRLF (\r\n) from all user-supplied header values before setting.' },
        { name: 'HTTP Response Splitting - res.writeHead user input', pattern: /(?:writeHead|setHeader|write)\s*\(\s*\d+\s*,\s*(?:req|request|params|body)/gi, severity: 'HIGH', module: 'Response Splitting', fix: 'Never use user-supplied data in response headers. Encode line breaks.' },

        { name: 'SQL truncation - VARCHAR field for passwords', pattern: /VARCHAR\s*\(\s*(?:1[0-2]|[2-9])\d\)|varchar\s*\(\s*(?:1[0-2]|[2-9])\d\)|String\s*\(\s*(?:1[0-2]|[2-9])\d\)/gi, severity: 'LOW', module: 'SQL Truncation', fix: 'VARCHAR fields for passwords should be large (255+). Use TEXT/BLOB for hashes. Prevent truncation-based user impersonation: admin@target.com + 40 spaces + [padding].' },
        { name: 'SQL truncation - Short unique column', pattern: /unique.*varchar\s*\(\s*[2-9]\d\)|varchar\s*\(\s*[2-9]\d\).*unique/gi, severity: 'LOW', module: 'SQL Truncation', fix: 'Ensure unique columns (username/email) have sufficient width. Use UNIQUE constraints with proper length validation.' },

        { name: 'SRI - External script without integrity', pattern: /<script[^>]*src\s*=\s*['"](https?:)?\/\/(?!.*integrity)/gi, severity: 'MEDIUM', module: 'Subresource Integrity', fix: 'Add integrity="sha384-..." attribute to external script tags. Use SRI hash generator tools.' },
        { name: 'SRI - External stylesheet without integrity', pattern: /<link[^>]*rel\s*=\s*['"]stylesheet['"][^>]*href\s*=\s*['"](https?:)?\/\/(?!.*integrity)/gi, severity: 'LOW', module: 'Subresource Integrity', fix: 'Add integrity and crossorigin="anonymous" to external CSS links.' },
        { name: 'SRI - Missing crossorigin for SRI', pattern: /integrity\s*=\s*['"][^'"]*['"](?!.*crossorigin)/gi, severity: 'LOW', module: 'Subresource Integrity', fix: 'Add crossorigin="anonymous" to elements with integrity checks.' },

        { name: 'Open Graph - User-controlled og:title', pattern: /(?:og|twitter):(?:title|description|image|url).*\$\{|(?:og|twitter):(?:title|description).*=.*req\.body/gi, severity: 'MEDIUM', module: 'Open Graph Injection', fix: 'Sanitize user input in meta tags. Extract text only, no HTML. Validate image URLs to prevent SSRF via og:image.' },
        { name: 'Open Graph - Meta tag injection vector', pattern: /<meta[^>]*(?:property|name)\s*=\s*['"](?:og|twitter):[^'"]*['"][^>]*content\s*=\s*(?:req|request|params|body)/gi, severity: 'HIGH', module: 'Open Graph Injection', fix: 'OG tag content should be server-generated, not user-supplied. If needed, strip all tags and validate with strict allowlist.' },
      ];

      for (const { name, pattern, severity, module, fix } of patterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          const line = lines[lineNum - 1]?.trim() || '';
          if (line.startsWith('//') || line.startsWith('#') || line.startsWith('*')) continue;

          addFinding(severity, module, name, `File: ${relativePath}:${lineNum}\nCode: ${line.substring(0, 120)}`, fix);
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
