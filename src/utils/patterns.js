export const SECRET_PATTERNS = {
  'AWS Access Key': /AKIA[0-9A-Z]{16}/g,
  'AWS Secret Key': /(?:aws_secret_access_key|aws_secret)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
  'GitHub Token': /gh[pousr]_[A-Za-z0-9_]{36,255}/g,
  'GitHub OAuth': /gho_[A-Za-z0-9_]{36,255}/g,
  'Google API Key': /AIza[0-9A-Za-z\-_]{35}/g,
  'Firebase Key': /AIza[0-9A-Za-z\-_]{35}/g,
  'Stripe Secret Key': /sk_live_[0-9a-zA-Z]{24,}/g,
  'Stripe Publishable Key': /pk_live_[0-9a-zA-Z]{24,}/g,
  'Supabase Service Role': /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,
  'Slack Token': /xox[baprs]-[0-9a-zA-Z-]{10,}/g,
  'Slack Webhook': /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[a-zA-Z0-9]+/g,
  'Twilio API Key': /SK[0-9a-fA-F]{32}/g,
  'SendGrid Key': /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g,
  'Mailgun Key': /key-[0-9a-zA-Z]{32}/g,
  'Heroku API Key': /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g,
  'Private Key': /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g,
  'JWT Token': /eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/g,
  'Generic Password': /(?:password|passwd|pwd|secret)\s*[=:]\s*['"][^'"]{8,}['"]/gi,
  'Database URL': /(?:mongodb|postgres|mysql|redis):\/\/[^\s'"]+/gi,
  'OpenAI Key': /sk-[a-zA-Z0-9]{48}/g,
  'Anthropic Key': /sk-ant-[a-zA-Z0-9_-]{40,}/g,
  'Discord Token': /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}/g,
  'Telegram Bot Token': /[0-9]{8,10}:[a-zA-Z0-9_-]{35}/g,
  'Azure Storage Key': /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}/g,
  'Cloudflare API Key': /[0-9a-f]{37}/g,
  'DigitalOcean Token': /dop_v1_[a-f0-9]{64}/g,
  'npm Token': /npm_[A-Za-z0-9]{36}/g,
};

export const XSS_PATTERNS = [
  /v-html\s*=/g,
  /dangerouslySetInnerHTML/g,
  /innerHTML\s*=/g,
  /document\.write\s*\(/g,
  /\.html\s*\(\s*[^)]*\+/g,
  /\$\{[^}]*\}\s*(?:<!--|\<)/g,
  /outerHTML\s*=/g,
  /insertAdjacentHTML/g,
];

export const SQLI_PATTERNS = [
  /`[^`]*\$\{[^}]*\}[^`]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|JOIN)/gi,
  /['"][^'"]*\+\s*(?:req\.|params\.|query\.|body\.)/gi,
  /(?:query|execute|raw)\s*\(\s*['"`][^'"`]*\$\{/gi,
  /(?:query|execute|raw)\s*\(\s*['"`][^'"`]*\+\s*(?:req|params|query|body)/gi,
  /String\.format\s*\(\s*['"][^'"]*(?:SELECT|INSERT|UPDATE|DELETE)/gi,
  /f['"](?:SELECT|INSERT|UPDATE|DELETE)[^'"]*\{/gi,
];

export const COMMAND_INJECTION_PATTERNS = [
  /exec\s*\(\s*['"`][^'"`]*\$\{/gi,
  /exec\s*\(\s*['"`][^'"`]*\+\s*(?:req|params|query|body|user)/gi,
  /spawn\s*\(\s*['"`][^'"`]*\$\{/gi,
  /child_process/gi,
  /eval\s*\(\s*(?:req|params|query|body|user)/gi,
  /Function\s*\(\s*(?:req|params|query|body|user)/gi,
  /execSync\s*\(\s*['"`][^'"`]*\$\{/gi,
  /system\s*\(\s*['"`][^'"`]*\$\{/gi,
];

export const SSRF_PATTERNS = [
  /fetch\s*\(\s*(?:req|params|query|body|user)/gi,
  /axios\s*\.\s*(?:get|post|put|delete)\s*\(\s*(?:req|params|query|body|user)/gi,
  /request\s*\(\s*(?:req|params|query|body|user)/gi,
  /urllib\.request\.urlopen\s*\(\s*(?:req|params|query|body|user)/gi,
  /http\.get\s*\(\s*(?:req|params|query|body|user)/gi,
  /new\s+URL\s*\(\s*(?:req|params|query|body|user)/gi,
];

export const SSTI_PATTERNS = [
  /render_template_string\s*\(\s*(?:req|params|query|body|user)/gi,
  /Template\s*\(\s*(?:req|params|query|body|user)/gi,
  /Jinja2\s*.*\s*render\s*\(\s*(?:req|params|query|body|user)/gi,
  /nunjucks\s*.*\s*renderString\s*\(\s*(?:req|params|query|body|user)/gi,
  /pug\s*.*\s*render\s*\(\s*(?:req|params|query|body|user)/gi,
  /ejs\s*.*\s*render\s*\(\s*['"`][^'"`]*<%/gi,
];

export const DESERIALIZATION_PATTERNS = [
  /pickle\.loads?\s*\(/gi,
  /yaml\.load\s*\(\s*[^)]*Loader\s*=\s*yaml\.(?:Unsafe|Full)Loader/gi,
  /yaml\.load\s*\(\s*[^)]*(?!Loader)/gi,
  /unserialize\s*\(/gi,
  /ObjectInputStream/gi,
  /Marshal\.load/gi,
  /JSON\.parse\s*\(\s*(?:req|params|query|body)/gi,
  /readObject\s*\(\s*\)/gi,
  /BinaryFormatter/gi,
];

export const PROTOTYPE_POLLUTION_PATTERNS = [
  /Object\.assign\s*\(\s*\{\}/gi,
  /\.\.\.\s*(?:req|params|query|body)/gi,
  /merge\s*\(\s*[^,]+,\s*(?:req|params|query|body)/gi,
  /deepmerge|lodash\.merge|_.merge/gi,
  /__proto__/g,
  /constructor\s*\[\s*['"]prototype['"]\s*\]/gi,
];

export const PATH_TRAVERSAL_PATTERNS = [
  /path\.join\s*\(\s*[^,]+,\s*(?:req|params|query|body)/gi,
  /readFile(?:Sync)?\s*\(\s*(?:req|params|query|body)/gi,
  /createReadStream\s*\(\s*(?:req|params|query|body)/gi,
  /sendFile\s*\(\s*(?:req|params|query|body)/gi,
  /res\.download\s*\(\s*(?:req|params|query|body)/gi,
  /open\s*\(\s*(?:req|params|query|body)/gi,
];

export const JWT_PATTERNS = [
  /algorithm\s*:\s*['"]none['"]/gi,
  /verify\s*:\s*false/gi,
  /algorithms\s*:\s*\[\s*['"]HS256['"]/gi,
  /jwt\.decode\s*\(/gi,
  /ignoreExpiration\s*:\s*true/gi,
];

export const HEADER_CHECKS = [
  'content-security-policy',
  'strict-transport-security',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
  'x-xss-protection',
  'cross-origin-opener-policy',
  'cross-origin-resource-policy',
  'cross-origin-embedder-policy',
];

export const EXPOSED_FILES = [
  '/.env',
  '/.env.local',
  '/.env.production',
  '/.git/config',
  '/.git/HEAD',
  '/.gitignore',
  '/package.json',
  '/package-lock.json',
  '/composer.json',
  '/composer.lock',
  '/.DS_Store',
  '/wp-config.php',
  '/web.config',
  '/server-status',
  '/server-info',
  '/.htaccess',
  '/.htpasswd',
  '/phpinfo.php',
  '/info.php',
  '/debug',
  '/_debug',
  '/trace',
  '/actuator',
  '/actuator/health',
  '/actuator/env',
  '/actuator/heapdump',
  '/graphql',
  '/graphiql',
  '/.well-known/security.txt',
  '/robots.txt',
  '/sitemap.xml',
  '/crossdomain.xml',
  '/clientaccesspolicy.xml',
  '/elmah.axd',
  '/trace.axd',
  '/swagger.json',
  '/swagger-ui.html',
  '/api-docs',
  '/openapi.json',
  '/v1/api-docs',
  '/v2/api-docs',
  '/v3/api-docs',
  '/.dockerenv',
  '/Dockerfile',
  '/docker-compose.yml',
  '/backup.sql',
  '/database.sql',
  '/dump.sql',
  '/adminer.php',
  '/phpmyadmin',
  '/_profiler',
  '/telescope',
  '/horizon',
];

export const COMMON_SUBDOMAINS = [
  'admin', 'api', 'app', 'auth', 'beta', 'blog', 'cdn', 'ci',
  'cms', 'cpanel', 'dashboard', 'db', 'debug', 'dev', 'docker',
  'docs', 'email', 'ftp', 'git', 'grafana', 'graphql', 'help',
  'internal', 'jenkins', 'jira', 'k8s', 'kibana', 'login', 'mail',
  'manage', 'monitor', 'mysql', 'ns1', 'ns2', 'old', 'panel',
  'phpmyadmin', 'portal', 'postgres', 'prometheus', 'proxy', 'queue',
  'rabbitmq', 'redis', 'registry', 'remote', 'sentry', 'sftp',
  'shop', 'smtp', 'sonar', 'sso', 'stage', 'staging', 'status',
  'storage', 'store', 'support', 'test', 'testing', 'traefik',
  'vault', 'vpn', 'webmail', 'wiki', 'www', 'ws',
];

export const COMMON_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
  1433, 1521, 2049, 2375, 2376, 3000, 3306, 3389, 4443,
  5000, 5432, 5900, 6379, 6443, 8000, 8080, 8443, 8888,
  9000, 9090, 9200, 9300, 27017, 27018, 50000,
];
