import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { addFinding } from '../core/findings.js';

const SCAN_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.py', '.rb', '.php', '.go', '.java'];
const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', '__pycache__', 'vendor'];

export async function auditLlmAi(projectPath, spinner) {
  spinner.text = 'Scanning for AI/LLM prompt injection vectors...';
  const files = getFiles(projectPath);

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8');
      const relativePath = file.replace(projectPath, '.');
      const lines = content.split('\n');

      const patterns = [
        { pattern: /system.?prompt|systemPrompt|system_message/gi, name: 'System prompt defined (extraction target)', severity: 'INFO' },
        { pattern: /(?:chat|completion|completions|generate|ask|query).*(?:req|request|params|query|body|user|input|message)/gi, name: 'LLM completion with user input', severity: 'HIGH' },
        { pattern: /(?:tools|functions|function_call|tool_choice).*(?:req|request|params|query|body)/gi, name: 'LLM tool call from user input', severity: 'CRITICAL' },
        { pattern: /(?:ignore|forget|disregard).*(?:previous|above|instructions|rules|prompt)/gi, name: 'No prompt injection guard (ignore instructions)', severity: 'HIGH' },
        { pattern: /fetch_url|open_url|read_file|execute_code|run_shell/gi, name: 'LLM tool that can fetch/execute', severity: 'CRITICAL' },
        { pattern: /(?:RAG|retrieval|embedding|vector_store|pinecone|chroma|weaviate|qdrant)/gi, name: 'RAG pipeline (indirect injection target)', severity: 'MEDIUM' },
        { pattern: /(?:anthropic|openai|cohere|googleai|gemini|vertex.?ai|claude|gpt)/gi, name: 'AI provider library usage', severity: 'INFO' },
        { pattern: /(?:function_call|functionCall|tool_use|toolUse).*(?:auto|any)/gi, name: 'LLM auto-invokes tools (dangerous)', severity: 'HIGH' },
        { pattern: /(?:system|instruction|prompt)\s*[:=]\s*['"`][^'"`]{20,}/gi, name: 'System prompt hardcoded in source', severity: 'MEDIUM' },
        { pattern: /(?:max_tokens|maxTokens|max_completion_tokens).*(?:req|request|body)/gi, name: 'LLM token limit from user', severity: 'LOW' },
        { pattern: /(?:assistant|agent|copilot|chatbot|llm).*(?:reply|respond|say|write|tell|send)/gi, name: 'LLM agent output pipeline', severity: 'INFO' },
        { pattern: /\\\\u[eE][0-9a-fA-F]|unicode.*tag.*block|U\+E[0-9A-F]{4}/gi, name: 'Unicode/ASCII smuggling tech reference', severity: 'LOW' },
      ];

      for (const { pattern, name, severity } of patterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          const line = lines[lineNum - 1]?.trim() || '';
          if (line.startsWith('//') || line.startsWith('#') || line.startsWith('*')) continue;

          addFinding(
            severity,
            'AI/LLM Prompt Injection',
            name,
            `File: ${relativePath}:${lineNum}\nCode: ${line.substring(0, 120)}`,
            'Use structured input/output separation. Do not concatenate user input into system prompts. Restrict tool-use to safe operations. Rate-limit LLM interactions. Sanitize RAG document inputs (indirect injection). Never let LLM execute code directly.'
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
