import { readFileSync, existsSync } from 'fs';
import { addFinding } from './findings.js';

export function parseH1Scope(filePath) {
  if (!existsSync(filePath)) {
    addFinding('INFO', 'H1 Scope', 'Scope file not found', filePath, 'Provide valid HackerOne scope JSON');
    return { inScope: [], outScope: [], assets: [] };
  }

  try {
    const data = JSON.parse(readFileSync(filePath, 'utf-8'));
    const inScope = [];
    const outScope = [];
    const assets = [];

    if (data.targets?.in_scope) {
      for (const item of data.targets.in_scope) {
        const rule = item.asset_identifier || item.asset_type || item;
        if (typeof rule === 'string') inScope.push(rule);
        else inScope.push(rule.identifier || JSON.stringify(rule));
      }
    }

    if (data.targets?.out_of_scope) {
      for (const item of data.targets.out_of_scope) {
        outScope.push(item.asset_identifier || item.asset_type || item);
      }
    }

    if (data.assets) assets.push(...data.assets);
    if (data.structured_scoping) {
      for (const entry of data.structured_scoping) {
        if (entry.asset_identifier) assets.push(entry.asset_identifier);
        if (entry.asset_type === 'URL' && entry.eligible_for_bounty) inScope.push(entry.asset_identifier);
      }
    }

    addFinding('INFO', 'H1 Scope', `Parsed ${inScope.length} in-scope + ${outScope.length} out-of-scope targets`,
      `In-scope: ${inScope.slice(0, 5).join(', ')}${inScope.length > 5 ? '...' : ''}\nOut-scope: ${outScope.slice(0, 3).join(', ')}`,
      'Review scope carefully. Only test in-scope assets.');

    return { inScope, outScope, assets };
  } catch (err) {
    addFinding('INFO', 'H1 Scope', 'Failed to parse scope file', err.message, 'Check JSON format');
    return { inScope: [], outScope: [], assets: [] };
  }
}

export function isInScope(url, scope) {
  if (!scope.inScope.length) return true;
  const hostname = new URL(url).hostname;

  const inScopeMatch = scope.inScope.some((rule) => {
    if (rule === '*' || rule === '*.*') return true;
    if (rule.startsWith('*.')) return hostname.endsWith(rule.slice(1));
    if (rule.includes('*')) return new RegExp('^' + rule.replace(/\*/g, '.*') + '$').test(hostname);
    return hostname === rule || hostname.endsWith('.' + rule);
  });

  if (!inScopeMatch) return false;

  const outScopeMatch = scope.outScope.some((rule) => {
    if (rule === '*') return true;
    if (rule.startsWith('*.')) return hostname.endsWith(rule.slice(1));
    return hostname === rule || hostname.endsWith('.' + rule);
  });

  return !outScopeMatch;
}
