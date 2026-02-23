const crypto = require('crypto');
const {
  clampPositiveInt,
  normalizeMode,
  normalizeSessionValue,
  mapHeaderValue,
} = require('../utils/primitives');

const DELEGATION_VALUE_KEYS = new Set([
  'delegate_to',
  'delegates_to',
  'handoff_to',
  'transfer_to',
  'target_agent',
  'next_agent',
  'agent_id',
  'agent',
]);

const DELEGATION_TOOL_NAME_PATTERN = /(delegate|handoff|transfer|spawn|route)_?agent/i;
const MAX_DELEGATION_ARG_PARSE_BYTES = 4096;

function toHeaderString(headers, headerName) {
  const value = mapHeaderValue(headers, headerName);
  if (value === undefined || value === null) {
    return '';
  }
  if (Array.isArray(value)) {
    return normalizeSessionValue(value[0]);
  }
  return normalizeSessionValue(value);
}

function toFirstForwardedIp(value) {
  return normalizeSessionValue(String(value || '').split(',')[0] || '');
}

function extractHeaderIdentity(headers, headerName) {
  const raw = toHeaderString(headers, headerName);
  if (!raw) {
    return '';
  }
  if (headerName === 'x-forwarded-for' || headerName === 'forwarded') {
    return toFirstForwardedIp(raw);
  }
  return raw;
}

function parseToken(value) {
  const raw = String(value || '').trim();
  if (!raw) {
    return '';
  }
  const idx = raw.indexOf(':');
  if (idx <= 0) {
    return raw;
  }
  return raw.slice(idx + 1);
}

function safeTimingEqual(a, b) {
  const left = Buffer.from(String(a || ''), 'utf8');
  const right = Buffer.from(String(b || ''), 'utf8');
  if (left.length === 0 || right.length === 0 || left.length !== right.length) {
    return false;
  }
  return crypto.timingSafeEqual(left, right);
}

function addEdge(adjacency, from, to) {
  const source = normalizeSessionValue(from, 128);
  const target = normalizeSessionValue(to, 128);
  if (!source || !target || source === target) {
    return false;
  }
  if (!adjacency.has(source)) {
    adjacency.set(source, new Set());
  }
  const targets = adjacency.get(source);
  if (targets.has(target)) {
    return false;
  }
  targets.add(target);
  return true;
}

function hasCycle(adjacency) {
  const visited = new Set();
  const stack = new Set();

  function visit(node) {
    if (stack.has(node)) {
      return true;
    }
    if (visited.has(node)) {
      return false;
    }
    visited.add(node);
    stack.add(node);
    const targets = adjacency.get(node);
    if (targets) {
      for (const next of targets) {
        if (visit(next)) {
          return true;
        }
      }
    }
    stack.delete(node);
    return false;
  }

  for (const node of adjacency.keys()) {
    if (visit(node)) {
      return true;
    }
  }
  return false;
}

function extractDelegationTarget(toolCall) {
  const fn = toolCall?.function;
  if (!fn || typeof fn !== 'object') {
    return '';
  }
  const argsRaw = fn.arguments;
  if (!argsRaw) {
    return '';
  }
  if (typeof argsRaw === 'object' && !Array.isArray(argsRaw)) {
    for (const [key, value] of Object.entries(argsRaw)) {
      if (DELEGATION_VALUE_KEYS.has(String(key || '').toLowerCase())) {
        return normalizeSessionValue(value, 128);
      }
    }
    return '';
  }
  if (typeof argsRaw !== 'string' || !argsRaw.trim()) {
    return '';
  }
  if (Buffer.byteLength(argsRaw, 'utf8') > MAX_DELEGATION_ARG_PARSE_BYTES) {
    return '';
  }
  try {
    const parsed = JSON.parse(argsRaw);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      for (const [key, value] of Object.entries(parsed)) {
        if (DELEGATION_VALUE_KEYS.has(String(key || '').toLowerCase())) {
          return normalizeSessionValue(value, 128);
        }
      }
    }
  } catch {
    // best-effort extraction only
  }
  return '';
}

function analyzeAgenticPayload(bodyJson, rootAgentId, options = {}) {
  const maxNodes = clampPositiveInt(options.maxNodes, 4096, 128, 1_000_000);
  const maxToolCalls = clampPositiveInt(options.maxToolCalls, 1024, 1, 1_000_000);
  const stats = {
    maxDepth: 0,
    toolCalls: 0,
    analyzedToolCalls: 0,
    delegations: 0,
    nodesVisited: 0,
    truncated: false,
    truncatedReason: '',
  };
  const adjacency = new Map();
  const visited = new Set();
  const stack = [{ value: bodyJson, depth: 0, currentAgentId: rootAgentId }];

  while (stack.length > 0) {
    const current = stack.pop();
    const value = current?.value;
    if (!value || typeof value !== 'object') {
      continue;
    }
    if (visited.has(value)) {
      continue;
    }
    visited.add(value);

    stats.nodesVisited += 1;
    if (stats.nodesVisited > maxNodes) {
      stats.truncated = true;
      stats.truncatedReason = 'analysis_node_budget_exceeded';
      break;
    }

    if (Array.isArray(value)) {
      for (let i = value.length - 1; i >= 0; i -= 1) {
        stack.push({
          value: value[i],
          depth: current.depth,
          currentAgentId: current.currentAgentId,
        });
      }
      continue;
    }

    const entries = Object.entries(value);
    for (let i = entries.length - 1; i >= 0; i -= 1) {
      const [rawKey, rawVal] = entries[i];
      const key = String(rawKey || '').toLowerCase();
      const val = rawVal;
      let nextAgentId = current.currentAgentId;

      if (key === 'tool_calls' && Array.isArray(val)) {
        stats.maxDepth = Math.max(stats.maxDepth, current.depth + 1);
        for (const toolCall of val) {
          if (stats.analyzedToolCalls >= maxToolCalls) {
            stats.truncated = true;
            stats.truncatedReason = 'analysis_tool_call_budget_exceeded';
            break;
          }
          stats.toolCalls += 1;
          stats.analyzedToolCalls += 1;
          const functionName = normalizeSessionValue(toolCall?.function?.name, 128);
          if (functionName && DELEGATION_TOOL_NAME_PATTERN.test(functionName)) {
            stats.delegations += 1;
            const extractedTarget = extractDelegationTarget(toolCall);
            if (extractedTarget && addEdge(adjacency, current.currentAgentId, extractedTarget)) {
              nextAgentId = extractedTarget;
            }
          }
          stack.push({
            value: toolCall,
            depth: current.depth + 1,
            currentAgentId: nextAgentId,
          });
        }
        if (stats.truncated) {
          break;
        }
        continue;
      }

      if (DELEGATION_VALUE_KEYS.has(key) && typeof val === 'string') {
        const target = normalizeSessionValue(val, 128);
        if (target && addEdge(adjacency, current.currentAgentId, target)) {
          stats.delegations += 1;
          nextAgentId = target;
        }
      }

      stack.push({
        value: val,
        depth: current.depth,
        currentAgentId: nextAgentId,
      });
    }
    if (stats.truncated) {
      break;
    }
  }

  return {
    ...stats,
    cycleDetected: false,
    adjacency,
  };
}

class AgenticThreatShield {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'block']);
    this.maxToolCallDepth = clampPositiveInt(config.max_tool_call_depth, 10, 1, 256);
    this.maxAgentDelegations = clampPositiveInt(config.max_agent_delegations, 5, 1, 1024);
    this.detectCycles = config.detect_cycles !== false;
    this.verifyIdentityTokens = config.verify_identity_tokens === true;
    this.identityTokenHeader = String(config.identity_token_header || 'x-sentinel-agent-token').toLowerCase();
    this.agentIdHeader = String(config.agent_id_header || 'x-sentinel-agent-id').toLowerCase();
    this.sessionHeader = String(config.session_header || 'x-sentinel-session-id').toLowerCase();
    this.fallbackHeaders = Array.isArray(config.fallback_headers)
      ? config.fallback_headers.map((value) => String(value || '').toLowerCase()).filter(Boolean)
      : ['x-sentinel-agent-id', 'x-forwarded-for', 'user-agent'];
    this.hmacSecret = String(config.hmac_secret || process.env.SENTINEL_AGENTIC_HMAC_SECRET || '');
    this.ttlMs = clampPositiveInt(config.ttl_ms, 15 * 60 * 1000, 1000, 24 * 60 * 60 * 1000);
    this.maxSessions = clampPositiveInt(config.max_sessions, 5000, 16, 500000);
    this.maxGraphEdgesPerSession = clampPositiveInt(config.max_graph_edges_per_session, 256, 8, 4096);
    this.maxAnalysisNodes = clampPositiveInt(config.max_analysis_nodes, 4096, 128, 1_000_000);
    this.maxToolCallsAnalyzed = clampPositiveInt(config.max_tool_calls_analyzed, 1024, 1, 1_000_000);
    this.blockOnAnalysisTruncation = config.block_on_analysis_truncation === true;
    this.observability = config.observability !== false;
    this.sessions = new Map();
  }

  isEnabled() {
    return this.enabled === true;
  }

  deriveSessionKey(headers = {}, correlationId = '') {
    const primary = extractHeaderIdentity(headers, this.sessionHeader);
    if (primary) {
      return primary;
    }
    for (const headerName of this.fallbackHeaders) {
      const value = extractHeaderIdentity(headers, headerName);
      if (value) {
        return value;
      }
    }
    const fallback = normalizeSessionValue(correlationId, 128);
    return fallback || 'anonymous';
  }

  deriveAgentId(headers = {}, sessionKey = '') {
    const primary = extractHeaderIdentity(headers, this.agentIdHeader);
    if (primary) {
      return primary;
    }
    return normalizeSessionValue(sessionKey, 128) || 'anonymous';
  }

  prune(nowMs) {
    const minUpdatedAt = nowMs - this.ttlMs;
    for (const [sessionKey, sessionState] of this.sessions.entries()) {
      if (Number(sessionState?.updatedAt || 0) < minUpdatedAt) {
        this.sessions.delete(sessionKey);
      }
    }
    while (this.sessions.size > this.maxSessions) {
      const oldest = this.sessions.keys().next().value;
      if (!oldest) {
        break;
      }
      this.sessions.delete(oldest);
    }
  }

  getSessionState(sessionKey, nowMs) {
    let state = this.sessions.get(sessionKey);
    if (!state) {
      state = {
        updatedAt: nowMs,
        delegations: 0,
        adjacency: new Map(),
      };
      this.sessions.set(sessionKey, state);
    }
    state.updatedAt = nowMs;
    return state;
  }

  mergeAdjacency(target, source) {
    let totalEdgeCount = 0;
    for (const targets of target.values()) {
      totalEdgeCount += targets.size;
    }
    let capped = totalEdgeCount >= this.maxGraphEdgesPerSession;
    if (capped) {
      return {
        totalEdgeCount: this.maxGraphEdgesPerSession,
        capped: true,
      };
    }
    for (const [from, targets] of source.entries()) {
      for (const to of targets) {
        if (totalEdgeCount >= this.maxGraphEdgesPerSession) {
          capped = true;
          break;
        }
        if (addEdge(target, from, to)) {
          totalEdgeCount += 1;
        }
      }
      if (capped) {
        break;
      }
    }
    return {
      totalEdgeCount,
      capped,
    };
  }

  verifyIdentity({ headers, agentId, sessionKey }) {
    if (!this.verifyIdentityTokens) {
      return {
        required: false,
        verified: false,
        reason: 'identity_verification_disabled',
      };
    }
    if (!this.hmacSecret) {
      return {
        required: true,
        verified: false,
        reason: 'identity_secret_missing',
        blockEligible: false,
      };
    }
    const tokenRaw = toHeaderString(headers, this.identityTokenHeader);
    if (!tokenRaw) {
      return {
        required: true,
        verified: false,
        reason: 'identity_token_missing',
        blockEligible: true,
      };
    }
    if (!agentId) {
      return {
        required: true,
        verified: false,
        reason: 'agent_id_missing',
        blockEligible: true,
      };
    }
    const expected = crypto
      .createHmac('sha256', this.hmacSecret)
      .update(`${agentId}:${sessionKey}`)
      .digest('hex');
    const provided = parseToken(tokenRaw);
    if (!safeTimingEqual(provided, expected)) {
      return {
        required: true,
        verified: false,
        reason: 'identity_token_invalid',
        blockEligible: true,
      };
    }
    return {
      required: true,
      verified: true,
      reason: 'identity_token_valid',
      blockEligible: false,
    };
  }

  evaluate({
    headers = {},
    bodyJson = null,
    correlationId = '',
    effectiveMode = 'monitor',
  } = {}) {
    if (!this.isEnabled()) {
      return {
        enabled: false,
        evaluated: false,
        detected: false,
        shouldBlock: false,
        reasons: [],
        violations: [],
      };
    }

    const nowMs = Date.now();
    this.prune(nowMs);

    const sessionKey = this.deriveSessionKey(headers, correlationId);
    const agentId = this.deriveAgentId(headers, sessionKey);
    const analysis = analyzeAgenticPayload(bodyJson, agentId, {
      maxNodes: this.maxAnalysisNodes,
      maxToolCalls: this.maxToolCallsAnalyzed,
    });
    const sessionState = this.getSessionState(sessionKey, nowMs);
    sessionState.delegations = Math.min(
      Number.MAX_SAFE_INTEGER,
      Number(sessionState.delegations || 0) + Number(analysis.delegations || 0)
    );
    const mergedAdjacency = this.mergeAdjacency(sessionState.adjacency, analysis.adjacency);
    const sessionCycleDetected = this.detectCycles ? hasCycle(sessionState.adjacency) : false;

    const identity = this.verifyIdentity({
      headers,
      agentId,
      sessionKey,
    });

    const violations = [];
    if (analysis.maxDepth > this.maxToolCallDepth) {
      violations.push({
        code: 'tool_call_depth_exceeded',
        message: `tool call depth ${analysis.maxDepth} exceeds max ${this.maxToolCallDepth}`,
        blockEligible: true,
      });
    }
    if (sessionState.delegations > this.maxAgentDelegations) {
      violations.push({
        code: 'agent_delegation_limit_exceeded',
        message: `agent delegations ${sessionState.delegations} exceed max ${this.maxAgentDelegations}`,
        blockEligible: true,
      });
    }
    if (this.detectCycles && sessionCycleDetected) {
      violations.push({
        code: 'agentic_cycle_detected',
        message: 'delegation graph cycle detected',
        blockEligible: true,
      });
    }
    if (identity.required && !identity.verified && identity.reason !== 'identity_secret_missing') {
      violations.push({
        code: identity.reason,
        message: identity.reason,
        blockEligible: identity.blockEligible !== false,
      });
    }
    if (analysis.truncated) {
      violations.push({
        code: String(analysis.truncatedReason || 'agentic_analysis_truncated'),
        message: String(analysis.truncatedReason || 'agentic_analysis_truncated'),
        blockEligible: this.blockOnAnalysisTruncation === true,
      });
    }
    if (mergedAdjacency.capped) {
      violations.push({
        code: 'agentic_graph_edge_budget_reached',
        message: 'delegation graph edge budget reached',
        blockEligible: false,
      });
    }

    const reasons = violations.map((item) => item.code);
    const detected = violations.length > 0;
    const blockEligible = violations.some((item) => item.blockEligible !== false);
    const shouldBlock =
      detected &&
      blockEligible &&
      this.mode === 'block' &&
      String(effectiveMode || '').toLowerCase() === 'enforce';

    return {
      enabled: true,
      evaluated: true,
      mode: this.mode,
      detected,
      shouldBlock,
      reasons,
      violations,
      sessionKey,
      agentId,
      maxDepth: analysis.maxDepth,
      toolCallCount: analysis.toolCalls,
      delegationCount: analysis.delegations,
      totalDelegations: sessionState.delegations,
      graphEdgeCount: mergedAdjacency.totalEdgeCount,
      cycleDetected: sessionCycleDetected,
      analysisTruncated: analysis.truncated,
      analysisTruncatedReason: analysis.truncatedReason,
      analyzedNodes: analysis.nodesVisited,
      analyzedToolCalls: analysis.analyzedToolCalls,
      identity,
      observability: this.observability,
    };
  }
}

module.exports = {
  AgenticThreatShield,
  analyzeAgenticPayload,
  hasCycle,
};
