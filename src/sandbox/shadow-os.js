function clampPositiveInt(value, fallback, min = 1, max = 86400000) {
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

function toObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return {};
  }
  return value;
}

function normalizeSessionValue(value) {
  const raw = String(value || '').trim();
  if (!raw) {
    return '';
  }
  return raw.length > 256 ? raw.slice(0, 256) : raw;
}

function mapHeaderValue(headers = {}, name) {
  const target = String(name || '').toLowerCase();
  for (const [key, value] of Object.entries(headers || {})) {
    if (String(key).toLowerCase() === target) {
      return value;
    }
  }
  return undefined;
}

function extractToolNameFromCall(toolCall) {
  if (!toolCall || typeof toolCall !== 'object') {
    return '';
  }
  if (typeof toolCall === 'string') {
    return String(toolCall);
  }
  const direct = toolCall.name || toolCall.tool_name;
  if (typeof direct === 'string' && direct) {
    return direct;
  }
  const fn = toolCall.function?.name;
  if (typeof fn === 'string' && fn) {
    return fn;
  }
  return '';
}

function extractHighRiskToolCalls(bodyJson) {
  if (!bodyJson || typeof bodyJson !== 'object') {
    return [];
  }
  const out = [];
  const topTool = bodyJson.tool?.name || bodyJson.tool_name || bodyJson.name;
  if (typeof topTool === 'string' && topTool) {
    out.push(String(topTool));
  }
  if (Array.isArray(bodyJson.tool_calls)) {
    for (const call of bodyJson.tool_calls) {
      const name = extractToolNameFromCall(call);
      if (name) {
        out.push(name);
      }
    }
  }
  if (Array.isArray(bodyJson.messages)) {
    for (const message of bodyJson.messages) {
      if (!message || typeof message !== 'object') {
        continue;
      }
      const toolCalls = Array.isArray(message.tool_calls) ? message.tool_calls : [];
      for (const call of toolCalls) {
        const name = extractToolNameFromCall(call);
        if (name) {
          out.push(name);
        }
      }
      if (message.tool_call) {
        const name = extractToolNameFromCall(message.tool_call);
        if (name) {
          out.push(name);
        }
      }
    }
  }
  return out.map((item) => String(item || '').trim()).filter(Boolean);
}

class ShadowOS {
  constructor(config = {}, deps = {}) {
    const normalized = toObject(config);
    this.enabled = normalized.enabled === true;
    this.mode = normalizeMode(normalized.mode, 'monitor');
    this.windowMs = clampPositiveInt(normalized.window_ms, 15 * 60 * 1000, 1000, 24 * 60 * 60 * 1000);
    this.maxSessions = clampPositiveInt(normalized.max_sessions, 5000, 1, 500000);
    this.maxHistoryPerSession = clampPositiveInt(normalized.max_history_per_session, 128, 8, 50000);
    this.repeatThreshold = clampPositiveInt(normalized.repeat_threshold, 4, 2, 1000);
    this.sessionHeader = String(normalized.session_header || 'x-sentinel-session-id').toLowerCase();
    this.fallbackHeaders = Array.isArray(normalized.fallback_headers)
      ? normalized.fallback_headers.map((item) => String(item || '').toLowerCase()).filter(Boolean)
      : ['x-sentinel-agent-id', 'x-forwarded-for', 'user-agent'];
    this.highRiskTools = new Set(
      Array.isArray(normalized.high_risk_tools)
        ? normalized.high_risk_tools.map((item) => String(item || '').trim()).filter(Boolean)
        : ['execute_shell', 'execute_sql', 'aws_cli', 'grant_permissions', 'create_user', 'delete_log', 'drop_database']
    );
    this.sequenceRules = Array.isArray(normalized.sequence_rules) && normalized.sequence_rules.length > 0
      ? normalized.sequence_rules
      : [
          {
            id: 'privilege_escalation_coverup',
            requires: ['create_user', 'grant_permissions', 'delete_log'],
            order_required: true,
          },
          {
            id: 'destructive_privilege_chain',
            requires: ['grant_permissions', 'drop_database'],
            order_required: false,
          },
        ];
    this.observability = normalized.observability !== false;

    this.now = typeof deps.now === 'function' ? deps.now : Date.now;
    this.sessions = new Map();
    this.nextCleanupAt = 0;
    this.metrics = {
      evaluated: 0,
      detected: 0,
      blocked: 0,
      ttlEvictions: 0,
      lruEvictions: 0,
      lastViolationAt: null,
      lastViolationRule: null,
    };
  }

  isEnabled() {
    return this.enabled === true;
  }

  deriveSessionKey(headers = {}, correlationId = '') {
    const primary = normalizeSessionValue(mapHeaderValue(headers, this.sessionHeader));
    if (primary) {
      return `hdr:${this.sessionHeader}:${primary}`;
    }
    for (const headerName of this.fallbackHeaders) {
      const value = normalizeSessionValue(mapHeaderValue(headers, headerName));
      if (value) {
        return `hdr:${headerName}:${value}`;
      }
    }
    const fallbackCorrelation = normalizeSessionValue(correlationId);
    if (fallbackCorrelation) {
      return `corr:${fallbackCorrelation}`;
    }
    return 'shadow:anonymous';
  }

  touchSession(sessionKey, session) {
    if (!this.sessions.has(sessionKey)) {
      return;
    }
    this.sessions.delete(sessionKey);
    this.sessions.set(sessionKey, session);
  }

  cleanup(nowMs = Number(this.now())) {
    if (nowMs < this.nextCleanupAt && this.sessions.size <= this.maxSessions) {
      return;
    }
    for (const [sessionKey, session] of this.sessions.entries()) {
      if (!session || Number(session.expiresAt || 0) <= nowMs) {
        this.sessions.delete(sessionKey);
        this.metrics.ttlEvictions += 1;
      }
    }
    while (this.sessions.size > this.maxSessions) {
      const oldest = this.sessions.keys().next().value;
      if (!oldest) {
        break;
      }
      this.sessions.delete(oldest);
      this.metrics.lruEvictions += 1;
    }
    this.nextCleanupAt = nowMs + Math.min(this.windowMs, 5000);
  }

  getSession(sessionKey, createIfMissing = false) {
    const nowMs = Number(this.now());
    this.cleanup(nowMs);
    const key = String(sessionKey || '');
    let session = this.sessions.get(key);
    if (!session && createIfMissing) {
      session = {
        createdAt: nowMs,
        lastSeenAt: nowMs,
        expiresAt: nowMs + this.windowMs,
        history: [],
      };
      this.sessions.set(key, session);
    }
    if (!session) {
      return null;
    }
    session.lastSeenAt = nowMs;
    session.expiresAt = nowMs + this.windowMs;
    this.touchSession(key, session);
    return session;
  }

  pruneSessionHistory(session, nowMs) {
    if (!session || !Array.isArray(session.history)) {
      return;
    }
    const minTs = nowMs - this.windowMs;
    session.history = session.history.filter((item) => Number(item.ts || 0) >= minTs);
    if (session.history.length > this.maxHistoryPerSession) {
      session.history = session.history.slice(-this.maxHistoryPerSession);
    }
  }

  recordTools(session, tools = [], metadata = {}) {
    const nowMs = Number(this.now());
    this.pruneSessionHistory(session, nowMs);
    for (const toolName of tools) {
      session.history.push({
        tool: String(toolName),
        ts: nowMs,
        method: metadata.method,
        path: metadata.path,
        provider: metadata.provider,
      });
    }
    this.pruneSessionHistory(session, nowMs);
  }

  checkSequenceRules(history = []) {
    const byTool = new Map();
    for (const event of history) {
      const tool = String(event.tool || '');
      if (!byTool.has(tool)) {
        byTool.set(tool, []);
      }
      byTool.get(tool).push(event.ts);
    }

    const violations = [];
    for (const rule of this.sequenceRules) {
      const requires = Array.isArray(rule.requires)
        ? rule.requires.map((item) => String(item || '').trim()).filter(Boolean)
        : [];
      if (requires.length === 0) {
        continue;
      }
      if (!requires.every((tool) => byTool.has(tool))) {
        continue;
      }
      const orderRequired = rule.order_required !== false;
      if (!orderRequired) {
        violations.push({
          rule: String(rule.id || 'sequence_match'),
          tools: requires,
          orderRequired: false,
        });
        continue;
      }
      let lastTs = -Infinity;
      let ordered = true;
      for (const tool of requires) {
        const events = byTool.get(tool) || [];
        const candidate = events.find((ts) => ts >= lastTs);
        if (!Number.isFinite(candidate)) {
          ordered = false;
          break;
        }
        lastTs = candidate;
      }
      if (ordered) {
        violations.push({
          rule: String(rule.id || 'sequence_match'),
          tools: requires,
          orderRequired: true,
        });
      }
    }

    const highRiskCounts = {};
    for (const event of history) {
      const key = String(event.tool || '');
      highRiskCounts[key] = Number(highRiskCounts[key] || 0) + 1;
    }
    for (const [tool, count] of Object.entries(highRiskCounts)) {
      if (count >= this.repeatThreshold) {
        violations.push({
          rule: 'repeated_high_risk_tool',
          tools: [tool],
          count,
          orderRequired: false,
        });
      }
    }

    return violations;
  }

  evaluate({ headers = {}, bodyJson, method, path, provider, effectiveMode = 'monitor', correlationId } = {}) {
    if (!this.isEnabled()) {
      return {
        enabled: false,
        evaluated: false,
        detected: false,
        shouldBlock: false,
        reason: 'disabled',
      };
    }

    const allTools = extractHighRiskToolCalls(bodyJson);
    if (allTools.length === 0) {
      return {
        enabled: true,
        evaluated: false,
        detected: false,
        shouldBlock: false,
        reason: 'no_tool_calls',
      };
    }
    const highRiskTools = allTools.filter((tool) => this.highRiskTools.has(tool));
    if (highRiskTools.length === 0) {
      return {
        enabled: true,
        evaluated: false,
        detected: false,
        shouldBlock: false,
        reason: 'no_high_risk_tools',
        toolCalls: allTools,
      };
    }

    const sessionKey = this.deriveSessionKey(headers, correlationId);
    const session = this.getSession(sessionKey, true);
    if (!session) {
      return {
        enabled: true,
        evaluated: false,
        detected: false,
        shouldBlock: false,
        reason: 'session_unavailable',
      };
    }

    this.recordTools(session, highRiskTools, {
      method,
      path,
      provider,
    });
    const violations = this.checkSequenceRules(session.history);
    const detected = violations.length > 0;
    const shouldBlock = detected && this.mode === 'block' && String(effectiveMode || '') === 'enforce';

    this.metrics.evaluated += 1;
    if (detected) {
      this.metrics.detected += 1;
      this.metrics.lastViolationAt = Number(this.now());
      this.metrics.lastViolationRule = String(violations[0].rule || 'violation');
      if (shouldBlock) {
        this.metrics.blocked += 1;
      }
    }

    return {
      enabled: true,
      evaluated: true,
      detected,
      shouldBlock,
      mode: this.mode,
      reason: detected ? 'causal_violation' : 'within_invariants',
      sessionKey,
      toolCalls: allTools,
      highRiskTools: Array.from(new Set(highRiskTools)),
      violations,
      windowMs: this.windowMs,
    };
  }

  getStats() {
    return {
      sessions: this.sessions.size,
      window_ms: this.windowMs,
      max_sessions: this.maxSessions,
      max_history_per_session: this.maxHistoryPerSession,
      repeat_threshold: this.repeatThreshold,
      evaluated: this.metrics.evaluated,
      detected: this.metrics.detected,
      blocked: this.metrics.blocked,
      ttl_evictions: this.metrics.ttlEvictions,
      lru_evictions: this.metrics.lruEvictions,
      last_violation_at: this.metrics.lastViolationAt,
      last_violation_rule: this.metrics.lastViolationRule,
    };
  }
}

module.exports = {
  ShadowOS,
  extractHighRiskToolCalls,
};
