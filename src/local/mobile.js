import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';

const SCAN_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.xml', '.kt', '.swift', '.dart', '.json', '.plist'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '__pycache__', 'vendor', 'android', 'ios'];

export async function auditMobile(projectPath, spinner) {
  spinner.text = 'Scanning for mobile security issues...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      const patterns = [
        { pattern: /(?:firebase|supabase|API|SECRET|TOKEN|KEY).*\s*=\s*['"][A-Za-z0-9_\-\+=\/]{20,}['"]/gi, name: 'API key/secret exposed in mobile code', severity: 'CRITICAL' },
        { pattern: /android:allowBackup\s*=\s*"true"/gi, name: 'Android allowBackup=true (data extraction)', severity: 'MEDIUM' },
        { pattern: /android:debuggable\s*=\s*"true"/gi, name: 'Android debuggable=true in release', severity: 'HIGH' },
        { pattern: /android:usesCleartextTraffic\s*=\s*"true"/gi, name: 'Android cleartext (HTTP) traffic allowed', severity: 'HIGH' },
        { pattern: /NSAppTransportSecurity.*NSAllowsArbitraryLoads/gi, name: 'iOS ATS disabled (HTTP allowed)', severity: 'HIGH' },
        { pattern: /android:networkSecurityConfig/gi, name: 'Android custom network security config', severity: 'MEDIUM' },
        { pattern: /(?:NSAllowsLocalNetworking|NSTemporaryExceptionAllowsInsecureHTTPLoads)/gi, name: 'iOS ATS exceptions enabled', severity: 'MEDIUM' },
        { pattern: /android:exported\s*=\s*"true"/gi, name: 'Android component exported (IPC risk)', severity: 'MEDIUM' },
        { pattern: /android:protectionLevel\s*=\s*"normal"/gi, name: 'Android permission protectionLevel normal', severity: 'LOW' },
        { pattern: /deeplink|intent-filter.*data.*android:scheme/gi, name: 'Deep link / intent filter configured', severity: 'MEDIUM' },
        { pattern: /(?:React\.Native|flutter|ionic|cordova|capacitor)/gi, name: 'Cross-platform framework usage', severity: 'INFO' },
        { pattern: /(?:AsyncStorage|SharedPreferences|NSUserDefaults|Keychain|Keystore)/gi, name: 'Local storage usage (check encryption)', severity: 'INFO' },
        { pattern: /ssl.*pinning|certificate.*pinning|SSLPinningPlugin|TrustKit|certificatePinner/gi, name: 'Certificate pinning implemented', severity: 'INFO' },
        { pattern: /firebase\.io\.com|google-services\.json|GoogleService-Info\.plist/gi, name: 'Firebase config file referenced', severity: 'MEDIUM' },
        { pattern: /(?:root|jailbreak).*detect|isRooted|isJailbroken|rootbeer|safety.?net/gi, name: 'Root/jailbreak detection', severity: 'INFO' },
        { pattern: /(?:WebView|WKWebView).*(?:setJavaScriptEnabled|javaScriptEnabled)/gi, name: 'WebView JS enabled (XSS surface)', severity: 'MEDIUM' },
      ];

      for (const { pattern, name, severity } of patterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          const line = lines[lineNum - 1]?.trim() || '';
          if (line.startsWith('//') || line.startsWith('#') || line.startsWith('*') || line.startsWith('<!--')) continue;

          addFinding(
            severity,
            'Mobile Security',
            name,
            `File: ${relativePath}:${lineNum}\nCode: ${line.substring(0, 120)}`,
            'Never hardcode API keys/secrets in mobile apps. Use server-side proxying. Enable certificate pinning. Set debuggable=false for release builds. Disable allowBackup unless encrypted. Use Network Security Config to restrict cleartext traffic. Enable minify/obfuscation for production.'
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
