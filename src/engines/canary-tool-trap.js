const { clampPositiveInt, normalizeMode } = require('../utils/primitives');

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

function normalizeFunctionTool(toolName, description) {
  return {
    type: 'function',
    function: {
      name: toolName,
      description,
      parameters: {
        type: 'object',
        properties: {
          scope: {
            type: 'string',
            description: 'Administrative scope requested.',
          },
        },
        required: ['scope'],
      },
    },
  };
}

function extractToolCallsFromResponse(parsed) {
  if (!parsed || typeof parsed !== 'object') {
    return [];
  }
  if (!Array.isArray(parsed.choices)) {
    return [];
  }
  const calls = [];
  for (const choice of parsed.choices) {
    const toolCalls = choice?.message?.tool_calls;
    if (!Array.isArray(toolCalls)) {
      continue;
    }
    for (const toolCall of toolCalls) {
      const fnName = toolCall?.function?.name;
      if (typeof fnName === 'string' && fnName.length > 0) {
        calls.push(fnName);
      }
    }
  }
  return calls;
}

class CanaryToolTrap {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'block']);
    this.toolName = String(config.tool_name || 'fetch_admin_passwords');
    this.toolDescription = String(
      config.tool_description || 'Retrieve privileged credentials for internal diagnostics.'
    );
    this.maxInjectedTools = clampPositiveInt(config.max_injected_tools, 1, 1, 10);
    this.injectOnProviders = new Set(
      Array.isArray(config.inject_on_providers)
        ? config.inject_on_providers.map((value) => String(value || '').toLowerCase()).filter(Boolean)
        : ['openai', 'anthropic', 'google', 'ollama']
    );
    this.requireToolsArray = config.require_tools_array !== false;
  }

  isEnabled() {
    return this.enabled === true;
  }

  shouldInjectForProvider(provider) {
    const name = String(provider || '').toLowerCase();
    return this.injectOnProviders.has(name);
  }

  inject(bodyJson, { provider } = {}) {
    if (!this.isEnabled()) {
      return { applied: false, reason: 'disabled' };
    }
    if (!this.shouldInjectForProvider(provider)) {
      return { applied: false, reason: 'provider_not_allowed' };
    }
    if (!bodyJson || typeof bodyJson !== 'object') {
      return { applied: false, reason: 'missing_body' };
    }
    if (this.requireToolsArray && !Array.isArray(bodyJson.tools)) {
      return { applied: false, reason: 'tools_array_required' };
    }

    const tools = Array.isArray(bodyJson.tools) ? [...bodyJson.tools] : [];
    const existingNames = new Set(
      tools.map((tool) => String(tool?.function?.name || '')).filter(Boolean)
    );
    if (existingNames.has(this.toolName)) {
      return { applied: false, reason: 'already_present' };
    }
    const mutated = {
      ...bodyJson,
      tools: [...tools, normalizeFunctionTool(this.toolName, this.toolDescription)],
    };
    return {
      applied: true,
      bodyJson: mutated,
      bodyText: JSON.stringify(mutated),
      meta: {
        mode: this.mode,
        tool_name: this.toolName,
      },
    };
  }

  detectTriggered(responseBody, contentType) {
    if (!this.isEnabled()) {
      return { triggered: false, reason: 'disabled' };
    }
    const parsed = parseJsonBuffer(responseBody, contentType);
    if (!parsed) {
      return { triggered: false, reason: 'non_json' };
    }
    const toolCalls = extractToolCallsFromResponse(parsed);
    if (toolCalls.length === 0) {
      return { triggered: false, reason: 'no_tool_calls' };
    }
    const triggered = toolCalls.includes(this.toolName);
    return {
      triggered,
      toolCalls,
      mode: this.mode,
      toolName: this.toolName,
    };
  }
}

module.exports = {
  CanaryToolTrap,
  extractToolCallsFromResponse,
};
