import { getFindings, addFinding } from './findings.js';

const CHAIN_TEMPLATES = [
  { primitives: ['mass assignment', 'idor'], chain: 'Mass Assignment → Role Elevation → IDOR → Full Admin Access', impact: 'CRITICAL', desc: '1) Exploit mass assignment to set role=admin\n2) Use elevated role to access restricted endpoints\n3) Exploit IDOR to read/write any user data' },
  { primitives: ['response splitting', 'xss'], chain: 'Response Splitting → Header Injection → Stored XSS → Session Hijack', impact: 'CRITICAL', desc: '1) Exploit HTTP response splitting\n2) Inject Set-Cookie header to fixate session\n3) Chain with XSS to steal session from admin' },
  { primitives: ['ssrf', 'lfi'], chain: 'SSRF → Internal Service → LFI → Source Code Leak', impact: 'CRITICAL', desc: '1) SSRF to reach internal web servers\n2) Exploit LFI on internal service to read source\n3) Extract secrets/DB credentials from source' },
  { primitives: ['sqli', 'ssrf'], chain: 'SQLi → File Write → SSRF → Internal Network Pivot', impact: 'CRITICAL', desc: '1) SQLi with INTO OUTFILE to write webshell\n2) SSRF from webshell to internal network\n3) Pivot to internal databases/services' },
  { primitives: ['cookie tossing', 'csrf'], chain: 'Cookie Tossing → CSRF Token Fixation → CSRF → Privilege Escalation', impact: 'HIGH', desc: '1) Toss cookie on subdomain with specific path\n2) Fixate CSRF token via cookie\n3) Execute CSRF with known token to change admin settings' },
  { primitives: ['tabnabbing', 'oauth'], chain: 'Tabnabbing → Phishing → OAuth Token Theft → ATO', impact: 'CRITICAL', desc: '1) Open target page via window.open\n2) Reverse tabnabbing: redirect original tab to fake login\n3) User authenticates via OAuth — attacker steals token' },
  { primitives: ['type confusion', 'jwt'], chain: 'Type Confusion → JWT Key Confusion → Token Forge → Admin Access', impact: 'CRITICAL', desc: '1) Exploit PHP type juggling to bypass auth\n2) Access JWT signing endpoint\n3) Use key confusion (RS256 pubkey as HS256 secret) to forge tokens' },
  { primitives: ['xssi', 'cors'], chain: 'XSSI → Cross-Origin Data Theft → CORS Credential Export', impact: 'HIGH', desc: '1) Exploit XSSI: include JSON array as script src\n2) Override Array constructor to exfiltrate data\n3) If CORS misconfig, send data cross-origin to attacker domain' },
  { primitives: ['graphql', 'idor'], chain: 'GraphQL Introspection → IDOR via node() Query → Cross-Tenant Data', impact: 'HIGH', desc: '1) Introspect GraphQL to discover node() queries\n2) Use global node IDs to access other users data\n3) Mass extract PII across all tenants' },
  { primitives: ['file upload', 'xss'], chain: 'File Upload → SVG XSS → Stored XSS → Cookie Theft', impact: 'CRITICAL', desc: '1) Upload SVG file with embedded <script> tag\n2) SVG renders inline — XSS executes\n3) Steal session cookies from anyone viewing the image' },
  { primitives: ['nosql', 'mass assignment'], chain: 'NoSQLi → Auth Bypass → Mass Assignment → Admin Role', impact: 'CRITICAL', desc: '1) NoSQL injection to bypass authentication\n2) Mass assignment on profile update: set role=admin\n3) Gain full administrative access' },
  { primitives: ['ssrf', 'cloud'], chain: 'SSRF → Cloud Metadata → IAM Credential → Lateral Movement', impact: 'CRITICAL', desc: '1) SSRF to 169.254.169.254\n2) Extract IAM role credentials\n3) Use credentials to enumerate S3, RDS, Lambda\n4) Pivot to other AWS services' },
  { primitives: ['csti', 'xss'], chain: 'AngularJS CSTI → Sandbox Escape → DOM XSS → Data Theft', impact: 'HIGH', desc: '1) CSP bypass via AngularJS expression injection\n2) Angular sandbox escape (pre-1.6)\n3) Execute arbitrary XSS in app context' },
  { primitives: ['host header', 'password reset'], chain: 'Host Header Injection → Password Reset Poisoning → ATO', impact: 'CRITICAL', desc: '1) Inject Host: evil.com into password reset request\n2) Reset link generated with attacker host\n3) Victim clicks link → token sent to attacker domain\n4) Attacker resets password → full account takeover' },
  { primitives: ['jwt', 'idor'], chain: 'JWT kid Injection → Path Traversal → Read Private Key → Forge Admin Token → IDOR Data Dump', impact: 'CRITICAL', desc: '1) Inject kid=../../private.key in JWT header\n2) Server reads private key and signs token\n3) Forge admin JWT\n4) Use admin session for IDOR: iterate all user IDs' },
];

export async function discoverAiChains(origin, spinner) {
  const findings = getFindings();
  const confirmed = findings.filter(f => f.validated && f.exploitability === 'confirmed');
  const all = [...confirmed, ...findings.filter(f => !f.validated)];

  const vulnKeywords = all.map(f => `${f.title.toLowerCase()} ${f.module.toLowerCase()}`).join(' ');
  let chainsFound = 0;

  for (const template of CHAIN_TEMPLATES) {
    const matches = template.primitives.filter(prim =>
      vulnKeywords.includes(prim.toLowerCase())
    );

    if (matches.length >= 2) {
      chainsFound++;
      const confidence = matches.length === template.primitives.length
        ? (confirmed.length > 0 ? 75 : 50)
        : Math.floor((matches.length / template.primitives.length) * 70);

      addFinding(
        template.impact,
        'AI Chain Discovery',
        template.chain,
        `Primitives detected: ${matches.join(' + ')}\n\n${template.desc}\n\nConfidence: ${confidence}% (${matches.length}/${template.primitives.length} primitives confirmed)`,
        'Test this attack chain manually to confirm exploitability. Chain attacks often qualify for higher bounty payouts.'
      );
    }
  }

  if (confirmed.length >= 3) {
    const critical = confirmed.filter(f => f.severity === 'CRITICAL');
    const high = confirmed.filter(f => f.severity === 'HIGH');

    if (critical.length >= 1 && high.length >= 1) {
      addFinding('CRITICAL', 'AI Chain Discovery', `Meta-chain: ${critical.length} critical + ${high.length} high = full compromise likely`,
        `Critical findings: ${critical.map(f => f.title).join('; ')}\nHigh findings: ${high.map(f => f.title).join('; ')}`,
        'Multiple confirmed findings indicate systemic security issues. Report as combined vulnerability with higher severity.');
      chainsFound++;
    }
  }

  spinner.text = `AI Chains: ${chainsFound} chains discovered`;
  return chainsFound;
}
