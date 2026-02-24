const {
  clampPositiveInt,
  normalizeMode,
  toObject,
} = require('../utils/primitives');

function parseDurationToMs(raw, fallbackMs) {
  const value = String(raw || '').trim().toLowerCase();
  if (!value) {
    return fallbackMs;
  }
  const match = value.match(/^(\d+)\s*(ms|s|m|h|d)$/);
  if (!match) {
    return fallbackMs;
  }
  const amount = Number(match[1]);
  if (!Number.isFinite(amount) || amount <= 0) {
    return fallbackMs;
  }
  const unit = match[2];
  if (unit === 'ms') {
    return amount;
  }
  if (unit === 's') {
    return amount * 1000;
  }
  if (unit === 'm') {
    return amount * 60 * 1000;
  }
  if (unit === 'h') {
    return amount * 60 * 60 * 1000;
  }
  return amount * 24 * 60 * 60 * 1000;
}

function resolvePath(source, path) {
  const value = source && typeof source === 'object' ? source : {};
  const parts = String(path || '').split('.').filter(Boolean);
  let current = value;
  for (const part of parts) {
    if (!current || typeof current !== 'object') {
      return undefined;
    }
    current = current[part];
  }
  return current;
}

function parseLiteral(raw) {
  const value = String(raw || '').trim();
  if (/^-?\d+(?:\.\d+)?$/.test(value)) {
    return Number(value);
  }
  if (value.toLowerCase() === 'true') {
    return true;
  }
  if (value.toLowerCase() === 'false') {
    return false;
  }
  return value.replace(/^["']|["']$/g, '');
}

function compare(left, operator, right) {
  if (operator === '==') {
    return String(left) === String(right);
  }
  if (operator === '!=') {
    return String(left) !== String(right);
  }
  const leftNum = Number(left);
  const rightNum = Number(right);
  if (!Number.isFinite(leftNum) || !Number.isFinite(rightNum)) {
    return false;
  }
  if (operator === '>') {
    return leftNum > rightNum;
  }
  if (operator === '<') {
    return leftNum < rightNum;
  }
  if (operator === '>=') {
    return leftNum >= rightNum;
  }
  if (operator === '<=') {
    return leftNum <= rightNum;
  }
  return false;
}

class LFRLEngine {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'block']);
    this.maxRules = clampPositiveInt(config.max_rules, 128, 1, 5000);
    this.maxEvents = clampPositiveInt(config.max_events, 20_000, 16, 1_000_000);
    this.maxMatches = clampPositiveInt(config.max_matches, 32, 1, 1024);
    this.defaultWithinMs = clampPositiveInt(config.default_within_ms, 10 * 60 * 1000, 1000, 24 * 60 * 60 * 1000);
    this.ttlMs = clampPositiveInt(config.ttl_ms, 24 * 60 * 60 * 1000, 60_000, 365 * 24 * 60 * 60 * 1000);
    this.blockOnRuleAction = config.block_on_rule_action !== false;
    this.observability = config.observability !== false;
    this.metricEvents = new Map();
    this.compiledRules = this.compileRules(config.rules);
  }

  isEnabled() {
    return this.enabled === true;
  }

  compileRules(rules = []) {
    const source = Array.isArray(rules) ? rules : [];
    const compiled = [];
    for (const item of source.slice(0, this.maxRules)) {
      if (!item) {
        continue;
      }
      let raw = '';
      if (typeof item === 'string') {
        raw = item.trim();
      } else if (typeof item === 'object') {
        const id = String(item.id || item.name || `rule_${compiled.length + 1}`).trim();
        const when = String(item.when || '').trim();
        const action = String(item.action || 'warn').trim().toUpperCase();
        raw = `RULE ${id} WHEN ${when} THEN ${action}`;
      }
      if (!raw) {
        continue;
      }
      const parsed = this.compileRule(raw);
      if (parsed) {
        compiled.push(parsed);
      }
    }
    return compiled;
  }

  compileRule(raw) {
    const normalized = String(raw || '').replace(/\s+/g, ' ').trim();
    const match = normalized.match(/^RULE\s+([A-Za-z0-9_.-]+)\s+WHEN\s+(.+)\s+THEN\s+(BLOCK|WARN|ALLOW)$/i);
    if (!match) {
      return null;
    }
    const id = String(match[1] || '').slice(0, 120);
    const when = String(match[2] || '').trim();
    const action = String(match[3] || 'WARN').toLowerCase();
    const clauses = when
      .split(/\s+AND\s+/i)
      .map((value) => String(value || '').trim())
      .filter(Boolean)
      .slice(0, 32);
    const compiledClauses = clauses.map((clause) => this.compileClause(clause)).filter(Boolean);
    if (compiledClauses.length === 0) {
      return null;
    }
    return {
      id,
      action,
      raw: normalized,
      clauses: compiledClauses,
    };
  }

  compileClause(clause) {
    const metricMatch = clause.match(
      /^tool_calls\(\s*["']([^"']+)["']\s*\)\s*(==|!=|>=|<=|>|<)\s*(\d+)(?:\s+WITHIN\s+([A-Za-z0-9]+))?$/i
    );
    if (metricMatch) {
      const toolName = String(metricMatch[1] || '').toLowerCase().trim();
      const operator = String(metricMatch[2] || '>');
      const expected = Number(metricMatch[3] || 0);
      const withinMs = parseDurationToMs(metricMatch[4], this.defaultWithinMs);
      return {
        kind: 'tool_calls',
        toolName,
        operator,
        expected,
        withinMs,
        clause,
      };
    }

    const matchesPattern = clause.match(/^([A-Za-z0-9_.-]+)\s+MATCHES\s+([A-Za-z0-9_.-]+)$/i);
    if (matchesPattern) {
      return {
        kind: 'matches',
        fieldPath: String(matchesPattern[1] || '').trim(),
        patternKey: String(matchesPattern[2] || '').trim(),
        clause,
      };
    }

    const compareMatch = clause.match(/^([A-Za-z0-9_.-]+)\s*(==|!=|>=|<=|>|<)\s*(.+)$/);
    if (compareMatch) {
      return {
        kind: 'compare',
        fieldPath: String(compareMatch[1] || '').trim(),
        operator: String(compareMatch[2] || '==').trim(),
        expected: parseLiteral(compareMatch[3]),
        clause,
      };
    }

    return null;
  }

  pruneEvents(now = Date.now()) {
    const staleBefore = Number(now) - this.ttlMs;
    for (const [key, entries] of this.metricEvents.entries()) {
      if (!Array.isArray(entries) || entries.length === 0) {
        this.metricEvents.delete(key);
        continue;
      }
      const filtered = entries.filter((value) => Number(value) >= staleBefore);
      if (filtered.length === 0) {
        this.metricEvents.delete(key);
        continue;
      }
      while (filtered.length > this.maxEvents) {
        filtered.shift();
      }
      this.metricEvents.set(key, filtered);
    }
  }

  observe(event = {}) {
    if (!this.isEnabled()) {
      return;
    }
    const now = Date.now();
    this.pruneEvents(now);
    const payload = toObject(event);
    const toolName = String(payload.tool_name || payload.toolName || '').toLowerCase().trim();
    if (toolName) {
      const key = `tool:${toolName}`;
      if (!this.metricEvents.has(key)) {
        this.metricEvents.set(key, []);
      }
      const entries = this.metricEvents.get(key);
      entries.push(now);
      while (entries.length > this.maxEvents) {
        entries.shift();
      }
    }
  }

  countToolCalls(toolName, withinMs, now = Date.now()) {
    const key = `tool:${String(toolName || '').toLowerCase().trim()}`;
    const entries = this.metricEvents.get(key) || [];
    const minTs = Number(now) - Number(withinMs || this.defaultWithinMs);
    let count = 0;
    for (let i = entries.length - 1; i >= 0; i -= 1) {
      const timestamp = Number(entries[i] || 0);
      if (timestamp < minTs) {
        break;
      }
      count += 1;
    }
    return count;
  }

  evaluate({
    context = {},
    effectiveMode = 'monitor',
  } = {}) {
    if (!this.isEnabled()) {
      return {
        enabled: false,
        detected: false,
        shouldBlock: false,
        reason: 'clean',
        findings: [],
      };
    }

    const now = Date.now();
    this.pruneEvents(now);
    const matches = [];
    const ctx = toObject(context);

    for (const rule of this.compiledRules) {
      let matched = true;
      const diagnostics = [];
      for (const clause of rule.clauses) {
        if (clause.kind === 'tool_calls') {
          const observed = this.countToolCalls(clause.toolName, clause.withinMs, now);
          const ok = compare(observed, clause.operator, clause.expected);
          diagnostics.push({
            clause: clause.clause,
            observed,
            expected: clause.expected,
            operator: clause.operator,
          });
          if (!ok) {
            matched = false;
            break;
          }
          continue;
        }
        if (clause.kind === 'matches') {
          const value = String(resolvePath(ctx, clause.fieldPath) || '');
          const patternValue = String(resolvePath(ctx, `patterns.${clause.patternKey}`) || '');
          const regex = patternValue ? new RegExp(patternValue, 'i') : null;
          const ok = regex ? regex.test(value) : false;
          diagnostics.push({
            clause: clause.clause,
            observed: value.slice(0, 120),
            pattern: clause.patternKey,
          });
          if (!ok) {
            matched = false;
            break;
          }
          continue;
        }
        if (clause.kind === 'compare') {
          const observed = resolvePath(ctx, clause.fieldPath);
          const ok = compare(observed, clause.operator, clause.expected);
          diagnostics.push({
            clause: clause.clause,
            observed,
            expected: clause.expected,
            operator: clause.operator,
          });
          if (!ok) {
            matched = false;
            break;
          }
        }
      }
      if (!matched) {
        continue;
      }
      matches.push({
        code: 'lfrl_rule_match',
        rule_id: rule.id,
        action: rule.action,
        diagnostics,
        blockEligible: this.blockOnRuleAction && rule.action === 'block',
      });
      if (matches.length >= this.maxMatches) {
        break;
      }
    }

    const detected = matches.length > 0;
    const shouldBlock =
      detected &&
      this.mode === 'block' &&
      String(effectiveMode || '').toLowerCase() === 'enforce' &&
      matches.some((item) => item.blockEligible === true);

    return {
      enabled: true,
      mode: this.mode,
      detected,
      shouldBlock,
      reason: detected ? String(matches[0].rule_id || 'lfrl_matched') : 'clean',
      findings: matches,
      rules_loaded: this.compiledRules.length,
    };
  }
}

module.exports = {
  LFRLEngine,
};
