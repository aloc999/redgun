import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';

const SCAN_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.py', '.rb', '.tf', '.hcl', '.yml', '.yaml', '.json'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '__pycache__', 'vendor'];

export async function auditCloud(projectPath, spinner) {
  spinner.text = 'Scanning for cloud misconfigurations...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      const patterns = [
        { pattern: /"Effect"\s*:\s*"Allow"\s*,\s*"Principal"\s*:\s*"\*"/gi, name: 'S3 bucket policy - public access (Principal: *)', severity: 'CRITICAL' },
        { pattern: /"Effect"\s*:\s*"Allow"\s*,\s*"Principal"\s*:\s*{?\s*"AWS"\s*:\s*"\*"/gi, name: 'AWS IAM policy - public access', severity: 'CRITICAL' },
        { pattern: /s3:GetObject.*Principal.*\*/gi, name: 'S3 GetObject public access', severity: 'CRITICAL' },
        { pattern: /s3:PutObject.*Principal.*\*/gi, name: 'S3 PutObject public access (critical!)', severity: 'CRITICAL' },
        { pattern: /block_public_acls\s*=\s*false|blockPublicPolicy\s*:\s*false/gi, name: 'S3 public access block disabled', severity: 'CRITICAL' },
        { pattern: /access_key\s*=\s*['"][A-Za-z0-9+\/=]{20}['"]/gi, name: 'AWS access key in config', severity: 'CRITICAL' },
        { pattern: /secret_key\s*=\s*['"][A-Za-z0-9+\/=]{40}['"]/gi, name: 'AWS secret key in config', severity: 'CRITICAL' },
        { pattern: /primary_access_key|primary_secret_key/gi, name: 'Cloud access keys in source', severity: 'CRITICAL' },
        { pattern: /metadata.*169\.254|instance.?metadata/gi, name: 'Cloud metadata endpoint reference', severity: 'INFO' },
        { pattern: /"Action"\s*:\s*"\*:"\s*,\s*"Resource"\s*:\s*"\*"/gi, name: 'IAM policy - wildcard action + resource', severity: 'CRITICAL' },
        { pattern: /"NotAction"|"NotResource"/gi, name: 'IAM NotAction/NotResource (check for over-permissiveness)', severity: 'MEDIUM' },
        { pattern: /GCP_CREDENTIALS|GOOGLE_APPLICATION_CREDENTIALS|gcp\.json|service\.account/gi, name: 'GCP service account credentials', severity: 'CRITICAL' },
        { pattern: /AZURE_STORAGE_CONNECTION_STRING|AZURE_CLIENT_SECRET|ARM_CLIENT_SECRET/gi, name: 'Azure credentials in source', severity: 'CRITICAL' },
        { pattern: /terraform\.tfstate|backend\.tf/gi, name: 'Terraform state reference', severity: 'HIGH' },
        { pattern: /(?:bucket|container)\s*.*acl\s*.*public-read/gi, name: 'Storage bucket with public-read ACL', severity: 'CRITICAL' },
        { pattern: /(?:lambda|function_url).*auth_type\s*=\s*"NONE"/gi, name: 'AWS Lambda function URL without auth', severity: 'HIGH' },
        { pattern: /(?:publicly_readable|publicly_writable)\s*=\s*true/gi, name: 'GCP bucket publicly accessible', severity: 'CRITICAL' },
        { pattern: /(?:monitoring|logging|audit.?log)\s*.*(?:disabled?|false)/gi, name: 'Cloud logging/monitoring disabled', severity: 'MEDIUM' },
      ];

      for (const { pattern, name, severity } of patterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          const line = lines[lineNum - 1]?.trim() || '';
          if (line.startsWith('//') || line.startsWith('#') || line.startsWith('*')) continue;

          addFinding(
            severity,
            'Cloud Misconfig (S3/IAM)',
            name,
            `File: ${relativePath}:${lineNum}\nCode: ${line.substring(0, 120)}`,
            'Follow least privilege principle. Never use wildcard (*) for IAM actions/resources. Block all public S3 bucket access by default. Use IAM roles, not access keys. Enable CloudTrail logging. Store secrets in AWS Secrets Manager / GCP Secret Manager / Azure Key Vault.'
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
