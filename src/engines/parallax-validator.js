const { resolveUpstreamPlan } = require('../upstream/router');
const { extractToolCallsFromResponse } = require('./canary-tool-trap');
const { clampPositiveInt, normalizeMode } = require('../utils/primitives');

function clampScore(value, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  if (parsed < 0 || parsed > 1) {
    return fallback;
  }
  return parsed;
}

function parseJsonBuffer(bodyBuffer, contentType = '') {
  const asString = Buffer.isBuffer(bodyBuffer)
    ? bodyBuffer.toString('utf8')
    : String(bodyBuffer || '');
  if (!asString) {
    return null;
  }
  const looksJson = String(contentType || '').toLowerCase().includes('application/json')
    || asString.startsWith('{')
    || asString.startsWith('[');
  if (!looksJson) {
    return null;
  }
  try {
    return JSON.parse(asString);
  } catch {
    return null;
  }
}

function parseDecisionFromText(text) {
  const raw = String(text || '').trim();
  if (!raw) {
    return null;
  }
  try {
    const parsed = JSON.parse(raw);
    if (typeof parsed === 'object' && parsed) {
      const allow = parsed.allow === true;
      const risk = clampScore(parsed.risk, allow ? 0.1 : 0.9);
      const reason = String(parsed.reason || (allow ? 'allow' : 'deny'));
      return {
        allow,
        risk,
        reason,
      };
    }
  } catch {
    // heuristic fallback below
  }

  const lowered = raw.toLowerCase();
  const denySignals = ['deny', 'block', 'malicious', 'injection', 'unsafe'];
  const allowSignals = ['allow', 'safe', 'benign'];
  const hasDeny = denySignals.some((signal) => lowered.includes(signal));
  const hasAllow = allowSignals.some((signal) => lowered.includes(signal));
  if (hasDeny && !hasAllow) {
    return { allow: false, risk: 0.9, reason: 'heuristic_deny' };
  }
  if (hasAllow && !hasDeny) {
    return { allow: true, risk: 0.1, reason: 'heuristic_allow' };
  }
  return null;
}

function parseToolCalls(responseBody, contentType) {
  const parsed = parseJsonBuffer(responseBody, contentType);
  if (!parsed) {
    return [];
  }
  return extractToolCallsFromResponse(parsed);
}

class ParallaxValidator {
  constructor(config = {}, deps = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'block']);
    this.highRiskTools = new Set(
      Array.isArray(config.high_risk_tools)
        ? config.high_risk_tools.map((value) => String(value || '')).filter(Boolean)
        : ['execute_shell', 'execute_sql', 'aws_cli']
    );
    this.secondaryTarget = String(config.secondary_target || 'ollama').toLowerCase();
    this.secondaryGroup = String(config.secondary_group || '');
    this.secondaryContract = String(config.secondary_contract || 'openai_chat_v1').toLowerCase();
    this.secondaryModel = String(config.secondary_model || '');
    this.timeoutMs = clampPositiveInt(config.timeout_ms, 3000, 100, 60000);
    this.riskThreshold = clampScore(config.risk_threshold, 0.7);

    this.upstreamClient = deps.upstreamClient;
    this.config = deps.config || {};
  }

  isEnabled() {
    return this.enabled === true && this.upstreamClient && typeof this.upstreamClient.forwardRequest === 'function';
  }

  findHighRiskTools(responseBody, contentType) {
    const toolCalls = parseToolCalls(responseBody, contentType);
    const highRisk = toolCalls.filter((toolName) => this.highRiskTools.has(toolName));
    return {
      toolCalls,
      highRiskTools: Array.from(new Set(highRisk)),
    };
  }

  buildValidationPayload({ requestBodyJson, highRiskTools }) {
    const model = this.secondaryModel || String(requestBodyJson?.model || '');
    const reviewPrompt = {
      request_model: String(requestBodyJson?.model || ''),
      requested_tools: highRiskTools,
      user_messages: Array.isArray(requestBodyJson?.messages)
        ? requestBodyJson.messages.map((message) => ({
            role: message?.role,
            content: message?.content,
          }))
        : [],
    };

    return {
      model,
      temperature: 0,
      max_tokens: 120,
      stream: false,
      messages: [
        {
          role: 'system',
          content:
            'You are Sentinel Parallax safety validator. Respond ONLY as JSON object: {"allow": boolean, "risk": number, "reason": string}.',
        },
        {
          role: 'user',
          content: `Assess whether executing these tools is safe. Input:\n${JSON.stringify(reviewPrompt)}`,
        },
      ],
    };
  }

  parseValidatorResponse(bodyBuffer, contentType) {
    const parsed = parseJsonBuffer(bodyBuffer, contentType);
    if (!parsed || !Array.isArray(parsed.choices) || parsed.choices.length === 0) {
      return null;
    }
    const content = parsed.choices[0]?.message?.content;
    return parseDecisionFromText(content);
  }

  async evaluate({
    req,
    correlationId,
    requestBodyJson,
    responseBody,
    responseContentType,
  }) {
    if (!this.isEnabled()) {
      return {
        evaluated: false,
        reason: 'disabled',
      };
    }

    const match = this.findHighRiskTools(responseBody, responseContentType);
    if (match.highRiskTools.length === 0) {
      return {
        evaluated: false,
        reason: 'no_high_risk_tools',
        toolCalls: match.toolCalls,
      };
    }

    const validationBodyJson = this.buildValidationPayload({
      requestBodyJson,
      highRiskTools: match.highRiskTools,
    });
    const validationBodyBuffer = Buffer.from(JSON.stringify(validationBodyJson), 'utf8');
    const syntheticHeaders = {
      ...(req?.headers || {}),
      'x-sentinel-target': this.secondaryTarget,
      'x-sentinel-contract': this.secondaryContract,
    };
    if (this.secondaryGroup) {
      syntheticHeaders['x-sentinel-target-group'] = this.secondaryGroup;
    }
    const syntheticReq = {
      headers: syntheticHeaders,
      originalUrl: '/v1/chat/completions',
    };

    let routePlan;
    try {
      routePlan = await resolveUpstreamPlan(syntheticReq, this.config);
    } catch (error) {
      return {
        evaluated: true,
        highRiskTools: match.highRiskTools,
        toolCalls: match.toolCalls,
        error: `route_plan_failed:${error.message}`,
        veto: false,
      };
    }

    let result;
    let timeoutHandle = null;
    try {
      result = await Promise.race([
        this.upstreamClient.forwardRequest({
          routePlan,
          req: syntheticReq,
          method: 'POST',
          pathWithQuery: '/v1/chat/completions',
          bodyBuffer: validationBodyBuffer,
          bodyJson: validationBodyJson,
          correlationId: `${correlationId}:parallax`,
          wantsStream: false,
          forwardHeaders: syntheticHeaders,
        }),
        new Promise((_, reject) => {
          timeoutHandle = setTimeout(() => reject(new Error('PARALLAX_TIMEOUT')), this.timeoutMs);
        }),
      ]);
    } catch (error) {
      if (timeoutHandle) {
        clearTimeout(timeoutHandle);
      }
      return {
        evaluated: true,
        highRiskTools: match.highRiskTools,
        toolCalls: match.toolCalls,
        error: String(error.message || 'parallax_error'),
        veto: false,
      };
    }
    if (timeoutHandle) {
      clearTimeout(timeoutHandle);
    }

    if (!result?.ok || result.status >= 400) {
      return {
        evaluated: true,
        highRiskTools: match.highRiskTools,
        toolCalls: match.toolCalls,
        error: `parallax_upstream_${result?.status || 0}`,
        veto: false,
      };
    }

    const decision = this.parseValidatorResponse(
      result.body,
      result.responseHeaders?.['content-type']
    );
    if (!decision) {
      return {
        evaluated: true,
        highRiskTools: match.highRiskTools,
        toolCalls: match.toolCalls,
        error: 'parallax_parse_failed',
        veto: false,
      };
    }

    const veto = decision.allow === false && Number(decision.risk || 0) >= this.riskThreshold;
    return {
      evaluated: true,
      highRiskTools: match.highRiskTools,
      toolCalls: match.toolCalls,
      secondaryProvider: routePlan.primary?.provider || this.secondaryTarget,
      risk: Number(decision.risk || 0),
      allow: Boolean(decision.allow),
      reason: decision.reason,
      veto,
      mode: this.mode,
    };
  }
}

module.exports = {
  ParallaxValidator,
  parseDecisionFromText,
};
