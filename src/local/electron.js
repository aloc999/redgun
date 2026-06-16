import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';

const SCAN_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.html', '.htm', '.json', '.env'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '__pycache__', 'vendor'];

export async function auditElectron(projectPath, spinner) {
  spinner.text = 'Scanning for Electron/ReactNative security issues...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      const patterns = [
        { pattern: /contextIsolation\s*:\s*false/gi, name: 'contextIsolation disabled (preload bridge exposed)', severity: 'CRITICAL' },
        { pattern: /nodeIntegration\s*:\s*true/gi, name: 'nodeIntegration enabled (Node API in renderer)', severity: 'CRITICAL' },
        { pattern: /sandbox\s*:\s*false/gi, name: 'Electron sandbox disabled', severity: 'HIGH' },
        { pattern: /webSecurity\s*:\s*false/gi, name: 'Electron webSecurity disabled (CORS/navigation bypass)', severity: 'HIGH' },
        { pattern: /allowRunningInsecureContent\s*:\s*true/gi, name: 'Electron mixed content allowed', severity: 'HIGH' },
        { pattern: /preload\s*:\s*path\.join\s*\(\s*__dirname\s*,\s*['"][^'"]*['"]\s*\)/gi, name: 'preload script from user-controllable path', severity: 'CRITICAL' },
        { pattern: /nodeIntegrationInSubFrames\s*:\s*true/gi, name: 'Node integration in iframes (XSS→RCE)', severity: 'CRITICAL' },
        { pattern: /shell\.openExternal\s*\(\s*(?:req|request|params|user|input)/gi, name: 'shell.openExternal with user input (command injection)', severity: 'CRITICAL' },
        { pattern: /electron\.ipcRenderer|ipcRenderer\.(?:on|send|invoke)/gi, name: 'Electron IPC usage (check handler auth)', severity: 'MEDIUM' },
        { pattern: /dialog\.showOpenDialog|dialog\.showSaveDialog/gi, name: 'Electron file dialog (check path traversal)', severity: 'MEDIUM' },
        { pattern: /(?:React\.Native|react-native).*(?:DEBUG|dev_mode)\s*=\s*true/gi, name: 'ReactNative debug mode enabled', severity: 'HIGH' },
        { pattern: /enableJSCWrapper|enableHermesDebugger/gi, name: 'RN JS debugger enabled', severity: 'MEDIUM' },
        { pattern: /(?:WebView|WKWebView).*originWhitelist|allowsInlineMediaPlayback/gi, name: 'RN WebView config (check allowlist)', severity: 'MEDIUM' },
      ];

      for (const { pattern, name, severity } of patterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          const line = lines[lineNum - 1]?.trim() || '';
          if (line.startsWith('//') || line.startsWith('#') || line.startsWith('*')) continue;

          addFinding(
            severity,
            'Electron / React Native',
            name,
            `File: ${relativePath}:${lineNum}\nCode: ${line.substring(0, 120)}`,
            'Enable contextIsolation and sandbox. Disable nodeIntegration in renderer. Sanitize all ipcRenderer.send arguments. Validate shell.openExternal URLs. Use allowlist for originWhitelist in RN WebView. Disable debug mode in production builds.'
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
