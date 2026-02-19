const crypto = require('crypto');

function toObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return {};
  }
  return value;
}

function clampPositiveInt(value, fallback, min = 1, max = 1000000) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  const normalized = Math.floor(parsed);
  if (normalized < min || normalized > max) {
    return fallback;
  }
  return normalized;
}

function normalizeMode(value, fallback = 'monitor') {
  const normalized = String(value || fallback).toLowerCase();
  return normalized === 'block' ? 'block' : 'monitor';
}

function snippetHash(text) {
  return crypto.createHash('sha256').update(String(text || ''), 'utf8').digest('hex').slice(0, 16);
}

function normalizePatternList(patterns) {
  const defaults = [
    'child_process',
    'process\\.env',
    'fs\\.',
    'require\\(',
    'rm\\s+-rf',
    'id_rsa',
    'curl\\s+https?://',
    'wget\\s+https?://',
    'nc\\s+-',
    "token\\s*=\\s*['\\\"]?[A-Za-z0-9_-]{16,}",
  ];
  const source = Array.isArray(patterns) ? patterns : defaults;
  const compiled = [];
  for (const raw of source) {
    const value = String(raw || '').trim();
    if (!value) {
      continue;
    }
    try {
      compiled.push({
        source: value,
        regex: new RegExp(value, 'i'),
      });
    } catch {
      // Ignore invalid user regex and continue with valid patterns.
    }
  }
  return compiled;
}

function collectCandidates(bodyJson, targetToolNames = new Set(), maxCodeChars = 20000) {
  const candidates = [];
  if (!bodyJson || typeof bodyJson !== 'object') {
    return candidates;
  }

  const pushCandidate = (entry) => {
    if (!entry || typeof entry.text !== 'string') {
      return;
    }
    const text = entry.text.slice(0, maxCodeChars);
    if (!text.trim()) {
      return;
    }
    candidates.push({
      ...entry,
      text,
    });
  };

  if (typeof bodyJson.input === 'string') {
    pushCandidate({ source: 'input', text: bodyJson.input });
  }

  if (Array.isArray(bodyJson.messages)) {
    bodyJson.messages.forEach((message, messageIndex) => {
      if (!message || typeof message !== 'object') {
        return;
      }
      if (typeof message.content === 'string') {
        pushCandidate({
          source: 'message',
          message_index: messageIndex,
          role: String(message.role || '').toLowerCase(),
          text: message.content,
        });
      }

      if (Array.isArray(message.tool_calls)) {
        message.tool_calls.forEach((toolCall, toolIndex) => {
          const toolName = String(toolCall?.function?.name || toolCall?.name || '').trim();
          if (targetToolNames.size > 0 && toolName && !targetToolNames.has(toolName.toLowerCase())) {
            return;
          }
          const args = toolCall?.function?.arguments;
          if (typeof args === 'string') {
            pushCandidate({
              source: 'tool_call',
              message_index: messageIndex,
              tool_index: toolIndex,
              tool_name: toolName,
              text: args,
            });
          }
        });
      }

      if (Array.isArray(message.content)) {
        message.content.forEach((part, partIndex) => {
          if (!part || typeof part !== 'object') {
            return;
          }
          if (typeof part.text === 'string') {
            pushCandidate({
              source: 'message_part',
              message_index: messageIndex,
              part_index: partIndex,
              role: String(message.role || '').toLowerCase(),
              text: part.text,
            });
          }
        });
      }
    });
  }

  return candidates;
}

class ExperimentalSandbox {
  constructor(config = {}) {
    const normalized = toObject(config);
    this.enabled = normalized.enabled === true;
    this.mode = normalizeMode(normalized.mode, 'monitor');
    this.maxCodeChars = clampPositiveInt(normalized.max_code_chars, 20000, 256, 2000000);
    this.maxFindings = clampPositiveInt(normalized.max_findings, 25, 1, 1000);
    this.patterns = normalizePatternList(normalized.disallowed_patterns);
    this.targetToolNames = new Set(
      Array.isArray(normalized.target_tool_names)
        ? normalized.target_tool_names.map((item) => String(item || '').toLowerCase().trim()).filter(Boolean)
        : ['execute_shell', 'execute_sql', 'bash', 'python', 'terminal']
    );
    this.observability = normalized.observability !== false;
  }

  isEnabled() {
    return this.enabled === true;
  }

  inspect({ bodyJson, effectiveMode = 'monitor' } = {}) {
    if (!this.isEnabled()) {
      return {
        enabled: false,
        detected: false,
        shouldBlock: false,
        findings: [],
      };
    }

    const candidates = collectCandidates(bodyJson, this.targetToolNames, this.maxCodeChars);
    const findings = [];
    for (const candidate of candidates) {
      for (const pattern of this.patterns) {
        if (findings.length >= this.maxFindings) {
          break;
        }
        const match = pattern.regex.exec(candidate.text);
        if (!match) {
          continue;
        }
        findings.push({
          source: candidate.source,
          message_index: candidate.message_index,
          part_index: candidate.part_index,
          tool_index: candidate.tool_index,
          tool_name: candidate.tool_name,
          role: candidate.role,
          pattern: pattern.source,
          match_preview: String(match[0] || '').slice(0, 80),
          snippet_hash: snippetHash(candidate.text),
        });
      }
      if (findings.length >= this.maxFindings) {
        break;
      }
    }

    return {
      enabled: true,
      detected: findings.length > 0,
      shouldBlock: this.mode === 'block' && String(effectiveMode || '') === 'enforce' && findings.length > 0,
      findings,
    };
  }
}

module.exports = {
  ExperimentalSandbox,
  collectCandidates,
};
