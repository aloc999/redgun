import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join } from 'path';
import { addFinding } from './findings.js';

const DETECTORS_FILE = '.redgun/custom-detectors.json';

export function loadDetectors() {
  if (!existsSync(DETECTORS_FILE)) return [];
  return JSON.parse(readFileSync(DETECTORS_FILE, 'utf-8'));
}

function saveDetectors(detectors) {
  if (!existsSync('.redgun')) mkdirSync('.redgun', { recursive: true });
  writeFileSync(DETECTORS_FILE, JSON.stringify(detectors, null, 2));
}

export function addDetector(name, pattern, severity, module, fix) {
  const detectors = loadDetectors();
  detectors.push({ name, pattern, severity: severity.toUpperCase(), module: module || 'Custom Detector', fix: fix || 'Review manually' });
  saveDetectors(detectors);
  return detectors.length;
}

export function removeDetector(name) {
  const detectors = loadDetectors().filter(d => d.name !== name);
  saveDetectors(detectors);
  return detectors.length;
}

export function listDetectors() {
  return loadDetectors();
}

export function runCustomDetectors(projectPath, spinner) {
  const detectors = loadDetectors();
  if (detectors.length === 0) return;

  spinner.text = `Running ${detectors.length} custom detectors...`;
  const { readdirSync, statSync } = require('fs');
  const { join: pJoin } = require('path');

  const getFiles = (dir, files = []) => {
    try {
      readdirSync(dir).forEach(entry => {
        if (['node_modules', '.git', 'dist', 'build'].includes(entry) || entry.startsWith('.')) return;
        const p = pJoin(dir, entry);
        try {
          if (statSync(p).isDirectory()) getFiles(p, files);
          else if (statSync(p).size < 512 * 1024) files.push(p);
        } catch {}
      });
    } catch {}
    return files;
  };

  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      for (const det of detectors) {
        const regex = new RegExp(det.pattern, 'g');
        const matches = [...content.matchAll(regex)];
        for (const match of matches.slice(0, 3)) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          addFinding(det.severity, det.module, det.name,
            `File: ${file.replace(projectPath, '.')}:${lineNum}`, det.fix);
        }
      }
    } catch {}
  }
}

export async function runTaintAnalysis(projectPath, spinner) {
  spinner.text = 'Running taint analysis...';
  const { readdirSync, statSync, readFileSync: rf } = require('fs');

  const sources = ['req.body', 'req.query', 'req.params', 'request.body', 'request.query', 'params[:', '$_GET', '$_POST', '$_REQUEST'];
  const sinks = [
    { pattern: /\beval\s*\(/, name: 'eval() RCE' },
    { pattern: /\bexec\s*\(/, name: 'exec() RCE' },
    { pattern: /\bspawn\s*\(/, name: 'spawn() RCE' },
    { pattern: /\.innerHTML\s*=/, name: 'innerHTML XSS' },
    { pattern: /document\.write\s*\(/, name: 'document.write XSS' },
    { pattern: /\.query\s*\(/, name: 'DB query SQLi' },
    { pattern: /\.send\s*\(/, name: 'res.send XSS' },
    { pattern: /\bfetch\s*\(/, name: 'fetch() SSRF' },
    { pattern: /\.render\s*\(/, name: 'Template SSTI' },
    { pattern: /require\s*\(/, name: 'require() path injection' },
  ];

  const getFiles = (dir, files = []) => {
    try {
      readdirSync(dir).forEach(entry => {
        if (['node_modules', '.git', 'dist', 'build', '__pycache__'].includes(entry)) return;
        const p = join(dir, entry);
        try { if (statSync(p).isDirectory()) getFiles(p, files); else if (statSync(p).size < 256 * 1024) files.push(p); } catch {}
      });
    } catch {}
    return files;
  };

  const files = getFiles(projectPath);
  let taintPaths = 0;

  for (const file of files) {
    try {
      const content = rf(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      for (const sink of sinks) {
        const sinkMatches = [...content.matchAll(sink.pattern)];
        for (const sinkMatch of sinkMatches.slice(0, 5)) {
          const sinkLine = content.substring(0, sinkMatch.index).split('\n').length;
          const contextBefore = content.substring(Math.max(0, sinkMatch.index - 2000), sinkMatch.index);

          for (const source of sources) {
            if (contextBefore.includes(source)) {
              taintPaths++;
              addFinding('CRITICAL', 'Taint Analysis', `${source} → ${sink.name} in ${relativePath}:${sinkLine}`,
                `Tainted data flow detected:\nSource line: contains '${source}'\nSink line: ${lines[sinkLine - 1]?.trim().substring(0, 120)}`,
                'Validate/sanitize user input before it reaches this sink. Use parameterized queries, escaping, or strict input validation.');
              break;
            }
          }
        }
      }
    } catch {}
  }

  spinner.text = `Taint analysis: ${taintPaths} tainted paths found`;
  return taintPaths;
}
