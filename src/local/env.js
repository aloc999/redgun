import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { addFinding } from '../core/findings.js';

export async function auditEnv(projectPath, spinner) {
  spinner.text = 'Checking environment file security...';

  const gitignorePath = join(projectPath, '.gitignore');
  const hasGitignore = existsSync(gitignorePath);
  let gitignoreContent = '';

  if (hasGitignore) {
    gitignoreContent = readFileSync(gitignorePath, 'utf-8');
  }

  const envFiles = ['.env', '.env.local', '.env.production', '.env.development'];

  for (const envFile of envFiles) {
    const envPath = join(projectPath, envFile);
    if (!existsSync(envPath)) continue;

    if (!hasGitignore || !gitignoreContent.includes('.env')) {
      addFinding(
        'CRITICAL',
        'Environment Files',
        `${envFile} may not be in .gitignore`,
        `File ${envFile} exists but .gitignore does not exclude .env files`,
        'Add .env* to your .gitignore file immediately'
      );
    }

    try {
      const content = readFileSync(envPath, 'utf-8');
      const lines = content.split('\n');

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line || line.startsWith('#')) continue;

        const [key] = line.split('=');
        if (!key) continue;

        if (/(?:SECRET|PASSWORD|PRIVATE|TOKEN|KEY|API_KEY)(?:_|$)/i.test(key)) {
          const value = line.split('=').slice(1).join('=').trim().replace(/['"]/g, '');
          if (value && value !== '' && !value.startsWith('${') && value !== 'changeme' && value !== 'your-key-here') {
            addFinding(
              'HIGH',
              'Environment Files',
              `Real secret in ${envFile}`,
              `${key} contains a real value (line ${i + 1})`,
              'Ensure this file is never committed. Use a secrets manager for production.'
            );
          }
        }
      }
    } catch {}
  }

  const exampleEnv = join(projectPath, '.env.example');
  if (existsSync(exampleEnv)) {
    try {
      const content = readFileSync(exampleEnv, 'utf-8');
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line || line.startsWith('#')) continue;
        const value = line.split('=').slice(1).join('=').trim().replace(/['"]/g, '');
        if (value && value.length > 20 && !/^(your|example|changeme|placeholder|xxx)/i.test(value)) {
          addFinding(
            'MEDIUM',
            'Environment Files',
            'Possible real secret in .env.example',
            `Line ${i + 1}: ${line.split('=')[0]}=*** (value looks real, not placeholder)`,
            'Replace with a placeholder value like "your-api-key-here"'
          );
        }
      }
    } catch {}
  }
}
