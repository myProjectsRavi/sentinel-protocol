const crypto = require('crypto');
const {
  clampPositiveInt,
  normalizeMode,
  normalizeSessionValue,
} = require('../utils/primitives');

const A2A_TECHNIQUE_ID = 'ASI08.A2A_CARD';

function toObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return {};
  }
  return value;
}

function stableObject(value) {
  if (value === null || value === undefined) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => stableObject(item));
  }
  if (typeof value !== 'object') {
    return value;
  }
  const out = {};
  for (const key of Object.keys(value).sort()) {
    out[key] = stableObject(value[key]);
  }
  return out;
}

function sha256(input = '') {
  return crypto.createHash('sha256').update(String(input || ''), 'utf8').digest('hex');
}

function normalizeStringList(input, maxItems, maxItemChars = 128) {
  if (!Array.isArray(input)) {
    return [];
  }
  const out = [];
  for (const item of input) {
    if (out.length >= maxItems) {
      break;
    }
    const normalized = String(item || '').trim();
    if (!normalized) {
      continue;
    }
    out.push(normalized.slice(0, maxItemChars));
  }
  return out;
}

function parseCardFromHeader(raw) {
  const value = String(raw || '').trim();
  if (!value) {
    return null;
  }
  if (value.startsWith('{')) {
    try {
      return JSON.parse(value);
    } catch {
      return null;
    }
  }
  try {
    const decoded = Buffer.from(value, 'base64url').toString('utf8');
    return JSON.parse(decoded);
  } catch {
    return null;
  }
}

function collectObservedCapabilities(bodyJson = {}, maxItems = 64) {
  const payload = toObject(bodyJson);
  const out = new Set();
  const add = (value) => {
    if (out.size >= maxItems) {
      return;
    }
    const normalized = String(value || '').trim();
    if (!normalized) {
      return;
    }
    out.add(normalized.slice(0, 128));
  };

  if (typeof payload.action === 'string') {
    add(payload.action);
  }
  if (typeof payload.capability === 'string') {
    add(payload.capability);
  }
  if (Array.isArray(payload.capabilities)) {
    for (const item of payload.capabilities) {
      add(item);
      if (out.size >= maxItems) {
        break;
      }
    }
  }
  if (typeof payload.tool_name === 'string') {
    add(payload.tool_name);
  }
  if (payload.tool && typeof payload.tool === 'object' && payload.tool.name) {
    add(payload.tool.name);
  }
  if (Array.isArray(payload.tools)) {
    for (const tool of payload.tools) {
      add(tool?.function?.name || tool?.name);
      if (out.size >= maxItems) {
        break;
      }
    }
  }

  return out;
}

function hasHeader(headers = {}, key) {
  const target = String(key || '').toLowerCase();
  for (const [name, value] of Object.entries(headers || {})) {
    if (String(name).toLowerCase() === target) {
      if (Array.isArray(value)) {
        return value.some((item) => String(item || '').trim().length > 0);
      }
      return String(value || '').trim().length > 0;
    }
  }
  return false;
}

class A2ACardVerifier {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'block']);
    this.cardHeader = String(config.card_header || 'x-a2a-agent-card').toLowerCase();
    this.agentHeader = String(config.agent_id_header || 'x-sentinel-agent-id').toLowerCase();
    this.maxCardBytes = clampPositiveInt(config.max_card_bytes, 32768, 256, 1048576);
    this.ttlMs = clampPositiveInt(config.ttl_ms, 3600000, 1000, 7 * 24 * 3600000);
    this.maxAgents = clampPositiveInt(config.max_agents, 10000, 16, 200000);
    this.maxCapabilities = clampPositiveInt(config.max_capabilities, 128, 1, 4096);
    this.maxObservedPerAgent = clampPositiveInt(config.max_observed_per_agent, 128, 1, 4096);
    this.overclaimTolerance = clampPositiveInt(config.overclaim_tolerance, 6, 0, 256);
    this.blockOnInvalidSchema = config.block_on_invalid_schema === true;
    this.blockOnDrift = config.block_on_drift === true;
    this.blockOnOverclaim = config.block_on_overclaim === true;
    this.blockOnAuthMismatch = config.block_on_auth_mismatch === true;
    this.observability = config.observability !== false;
    this.cards = new Map();
  }

  isEnabled() {
    return this.enabled === true;
  }

  prune(nowMs) {
    const minUpdatedAt = nowMs - this.ttlMs;
    for (const [agentId, entry] of this.cards.entries()) {
      if (Number(entry?.updatedAt || 0) < minUpdatedAt) {
        this.cards.delete(agentId);
      }
    }
    while (this.cards.size > this.maxAgents) {
      const oldest = this.cards.keys().next().value;
      if (!oldest) {
        break;
      }
      this.cards.delete(oldest);
    }
  }

  resolveCard(bodyJson = {}, headers = {}) {
    const payload = toObject(bodyJson);
    if (payload.agent_card && typeof payload.agent_card === 'object' && !Array.isArray(payload.agent_card)) {
      return payload.agent_card;
    }
    if (payload.agentCard && typeof payload.agentCard === 'object' && !Array.isArray(payload.agentCard)) {
      return payload.agentCard;
    }

    const altHeader = headers['x-sentinel-agent-card'];
    const primaryHeader = headers[this.cardHeader];
    return parseCardFromHeader(primaryHeader || altHeader || '');
  }

  validateCardSchema(card) {
    const findings = [];
    const safeCard = toObject(card);
    const cardId = normalizeSessionValue(safeCard.id || safeCard.agent_id || '', 160);
    const capabilities = normalizeStringList(
      safeCard.capabilities,
      this.maxCapabilities,
      160
    );

    if (!cardId) {
      findings.push({
        code: 'a2a_card_missing_id',
        blockEligible: this.blockOnInvalidSchema,
        technique_id: A2A_TECHNIQUE_ID,
      });
    }
    if (capabilities.length === 0) {
      findings.push({
        code: 'a2a_card_missing_capabilities',
        blockEligible: this.blockOnInvalidSchema,
        technique_id: A2A_TECHNIQUE_ID,
      });
    }

    const auth = toObject(safeCard.auth);
    const authSchemes = normalizeStringList(
      auth.schemes || auth.methods,
      8,
      32
    ).map((item) => item.toLowerCase());

    if (authSchemes.length === 0) {
      findings.push({
        code: 'a2a_card_missing_auth_scheme',
        blockEligible: this.blockOnInvalidSchema,
        technique_id: A2A_TECHNIQUE_ID,
      });
    }

    if (capabilities.length > this.maxCapabilities) {
      findings.push({
        code: 'a2a_card_capabilities_truncated',
        blockEligible: false,
        technique_id: A2A_TECHNIQUE_ID,
      });
    }

    return {
      cardId,
      capabilities,
      authSchemes,
      findings,
      stableHash: sha256(JSON.stringify(stableObject(safeCard))),
    };
  }

  evaluateAuthEnforcement(headers = {}, authSchemes = []) {
    const findings = [];
    const lower = new Set(authSchemes.map((item) => String(item).toLowerCase()));

    if (lower.has('oauth2') || lower.has('oidc')) {
      const hasBearer = hasHeader(headers, 'authorization');
      if (!hasBearer) {
        findings.push({
          code: 'a2a_card_auth_oauth_not_enforced',
          blockEligible: this.blockOnAuthMismatch,
          technique_id: A2A_TECHNIQUE_ID,
        });
      }
    }

    if (lower.has('mtls')) {
      const hasMtlsEvidence =
        hasHeader(headers, 'x-client-cert') ||
        hasHeader(headers, 'ssl-client-cert') ||
        hasHeader(headers, 'x-forwarded-client-cert');
      if (!hasMtlsEvidence) {
        findings.push({
          code: 'a2a_card_auth_mtls_not_enforced',
          blockEligible: this.blockOnAuthMismatch,
          technique_id: A2A_TECHNIQUE_ID,
        });
      }
    }

    return findings;
  }

  evaluate({
    headers = {},
    bodyJson = {},
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

    const nowMs = Date.now();
    this.prune(nowMs);

    const normalizedHeaders = toObject(headers);
    const card = this.resolveCard(bodyJson, normalizedHeaders);
    const findings = [];

    if (!card || typeof card !== 'object' || Array.isArray(card)) {
      findings.push({
        code: 'a2a_card_missing',
        blockEligible: this.blockOnInvalidSchema,
        technique_id: A2A_TECHNIQUE_ID,
      });
      const shouldBlock =
        this.mode === 'block' &&
        String(effectiveMode || '').toLowerCase() === 'enforce' &&
        this.blockOnInvalidSchema;
      return {
        enabled: true,
        mode: this.mode,
        detected: true,
        shouldBlock,
        reason: 'a2a_card_missing',
        findings,
      };
    }

    const rawCard = JSON.stringify(card);
    const cardBytes = Buffer.byteLength(rawCard, 'utf8');
    if (cardBytes > this.maxCardBytes) {
      findings.push({
        code: 'a2a_card_too_large',
        blockEligible: this.blockOnInvalidSchema,
        technique_id: A2A_TECHNIQUE_ID,
      });
    }

    const parsed = this.validateCardSchema(card);
    findings.push(...parsed.findings);
    findings.push(...this.evaluateAuthEnforcement(normalizedHeaders, parsed.authSchemes));

    const headerAgentId = normalizeSessionValue(normalizedHeaders[this.agentHeader] || '', 160);
    const effectiveAgentId = parsed.cardId || headerAgentId || 'agent:unknown';
    const observedCaps = collectObservedCapabilities(bodyJson, this.maxObservedPerAgent);

    const prior = this.cards.get(effectiveAgentId);
    if (prior && prior.cardHash !== parsed.stableHash) {
      findings.push({
        code: 'a2a_card_drift_detected',
        blockEligible: this.blockOnDrift,
        technique_id: A2A_TECHNIQUE_ID,
      });
    }

    const observedUnion = new Set(prior ? Array.from(prior.observedCapabilities || []) : []);
    for (const capability of observedCaps) {
      if (observedUnion.size >= this.maxObservedPerAgent) {
        break;
      }
      observedUnion.add(capability);
    }

    const declaredSet = new Set(parsed.capabilities);
    const undeployedClaims = [];
    for (const cap of declaredSet) {
      if (!observedUnion.has(cap)) {
        undeployedClaims.push(cap);
      }
    }
    if (undeployedClaims.length > this.overclaimTolerance) {
      findings.push({
        code: 'a2a_card_capability_overclaim',
        blockEligible: this.blockOnOverclaim,
        technique_id: A2A_TECHNIQUE_ID,
        undeployed_count: undeployedClaims.length,
      });
    }

    this.cards.set(effectiveAgentId, {
      updatedAt: nowMs,
      cardHash: parsed.stableHash,
      declaredCapabilities: parsed.capabilities,
      observedCapabilities: observedUnion,
      authSchemes: parsed.authSchemes,
    });

    const detected = findings.length > 0;
    const blockEligible = findings.some((item) => item.blockEligible === true);
    const shouldBlock =
      detected &&
      blockEligible &&
      this.mode === 'block' &&
      String(effectiveMode || '').toLowerCase() === 'enforce';

    return {
      enabled: true,
      mode: this.mode,
      detected,
      shouldBlock,
      reason: detected ? String(findings[0].code || 'a2a_card_violation') : 'clean',
      findings,
      agent_id: effectiveAgentId,
      card_hash_prefix: parsed.stableHash.slice(0, 16),
      observed_capabilities: Array.from(observedUnion).sort().slice(0, 64),
      declared_capabilities: parsed.capabilities,
      auth_schemes: parsed.authSchemes,
    };
  }
}

module.exports = {
  A2ACardVerifier,
};
