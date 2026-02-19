const crypto = require('crypto');

const SUPPORTED_CONTRACTS = new Set([
  'passthrough',
  'openai_chat_v1',
  'anthropic_messages_v1',
  'google_generative_v1',
]);

function normalizeContract(value, fallback = 'passthrough') {
  const lowered = String(value || fallback).toLowerCase();
  if (SUPPORTED_CONTRACTS.has(lowered)) {
    return lowered;
  }
  return fallback;
}

function safeJsonParseBuffer(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    return null;
  }
  try {
    return JSON.parse(buffer.toString('utf8'));
  } catch {
    return null;
  }
}

function toJsonBuffer(value) {
  return Buffer.from(JSON.stringify(value));
}

function normalizeHeaders(headers = {}) {
  const normalized = {};
  for (const [key, value] of Object.entries(headers || {})) {
    normalized[String(key).toLowerCase()] = String(value);
  }
  return normalized;
}

function identityAdapter() {
  return {
    name: 'identity',
    supportsStreaming: true,
    prepareRequest(input) {
      return {
        method: input.method,
        pathWithQuery: input.pathWithQuery,
        bodyBuffer: input.bodyBuffer,
        headerOverrides: {},
      };
    },
    transformBufferedResponse(input) {
      return {
        status: input.status,
        bodyBuffer: input.bodyBuffer,
        responseHeaders: input.responseHeaders,
      };
    },
  };
}

function toAnthropicMessages(openAiMessages = []) {
  return openAiMessages
    .filter((message) => ['user', 'assistant'].includes(String(message?.role || '').toLowerCase()))
    .map((message) => ({
      role: String(message.role || '').toLowerCase() === 'assistant' ? 'assistant' : 'user',
      content: String(message.content || ''),
    }));
}

function buildSystemPrompt(openAiMessages = []) {
  const system = openAiMessages
    .filter((message) => String(message?.role || '').toLowerCase() === 'system')
    .map((message) => String(message.content || '').trim())
    .filter(Boolean);
  return system.length > 0 ? system.join('\n\n') : null;
}

function mapAnthropicStopReason(value) {
  const reason = String(value || '').toLowerCase();
  if (reason === 'max_tokens') {
    return 'length';
  }
  if (reason === 'stop_sequence') {
    return 'stop';
  }
  if (reason === 'tool_use') {
    return 'tool_calls';
  }
  return 'stop';
}

function extractAnthropicText(content = []) {
  if (!Array.isArray(content)) {
    return '';
  }
  return content
    .filter((item) => item && typeof item === 'object' && item.type === 'text')
    .map((item) => String(item.text || ''))
    .join('');
}

function openAiToAnthropicAdapter(candidate) {
  return {
    name: 'openai_to_anthropic',
    supportsStreaming: false,
    prepareRequest(input) {
      const parsed = input.bodyJson || safeJsonParseBuffer(input.bodyBuffer);
      if (!parsed || !Array.isArray(parsed.messages)) {
        throw new Error('openai_chat_v1 -> anthropic_messages_v1 requires JSON body with messages');
      }

      const anthropicPayload = {
        model: String(parsed.model || candidate?.model || process.env.SENTINEL_ANTHROPIC_MODEL || 'claude-3-5-sonnet-latest'),
        max_tokens: Number(parsed.max_tokens || parsed.max_completion_tokens || 1024),
        temperature: parsed.temperature,
        top_p: parsed.top_p,
        messages: toAnthropicMessages(parsed.messages),
      };

      const system = buildSystemPrompt(parsed.messages);
      if (system) {
        anthropicPayload.system = system;
      }

      const headerOverrides = {
        'content-type': 'application/json',
        'anthropic-version':
          String(candidate?.staticHeaders?.['anthropic-version'] || process.env.SENTINEL_ANTHROPIC_VERSION || '2023-06-01'),
      };

      return {
        method: 'POST',
        pathWithQuery: '/v1/messages',
        bodyBuffer: toJsonBuffer(anthropicPayload),
        headerOverrides,
      };
    },
    transformBufferedResponse(input) {
      if (input.status >= 400) {
        return {
          status: input.status,
          bodyBuffer: input.bodyBuffer,
          responseHeaders: input.responseHeaders,
        };
      }

      const parsed = safeJsonParseBuffer(input.bodyBuffer);
      if (!parsed) {
        return {
          status: input.status,
          bodyBuffer: input.bodyBuffer,
          responseHeaders: input.responseHeaders,
        };
      }

      const text = extractAnthropicText(parsed.content);
      const promptTokens = Number(parsed.usage?.input_tokens || 0);
      const completionTokens = Number(parsed.usage?.output_tokens || 0);

      const openAiResponse = {
        id: parsed.id || `chatcmpl_${crypto.randomUUID()}`,
        object: 'chat.completion',
        created: Math.floor(Date.now() / 1000),
        model: parsed.model || parsed?.message?.model || null,
        choices: [
          {
            index: 0,
            message: {
              role: 'assistant',
              content: text,
            },
            finish_reason: mapAnthropicStopReason(parsed.stop_reason),
          },
        ],
        usage: {
          prompt_tokens: promptTokens,
          completion_tokens: completionTokens,
          total_tokens: promptTokens + completionTokens,
        },
      };

      const responseHeaders = {
        ...(input.responseHeaders || {}),
        'content-type': 'application/json',
      };

      return {
        status: input.status,
        bodyBuffer: toJsonBuffer(openAiResponse),
        responseHeaders,
      };
    },
  };
}

function toGoogleContents(openAiMessages = []) {
  return openAiMessages
    .filter((message) => ['user', 'assistant'].includes(String(message?.role || '').toLowerCase()))
    .map((message) => ({
      role: String(message.role || '').toLowerCase() === 'assistant' ? 'model' : 'user',
      parts: [{ text: String(message.content || '') }],
    }));
}

function mapGoogleFinishReason(reason) {
  const normalized = String(reason || '').toUpperCase();
  if (normalized === 'MAX_TOKENS') {
    return 'length';
  }
  if (normalized === 'SAFETY') {
    return 'content_filter';
  }
  return 'stop';
}

function extractGoogleText(candidate) {
  if (!candidate || typeof candidate !== 'object') {
    return '';
  }
  const parts = candidate.content?.parts;
  if (!Array.isArray(parts)) {
    return '';
  }
  return parts.map((part) => String(part.text || '')).join('');
}

function openAiToGoogleAdapter(candidate) {
  return {
    name: 'openai_to_google',
    supportsStreaming: false,
    prepareRequest(input) {
      const parsed = input.bodyJson || safeJsonParseBuffer(input.bodyBuffer);
      if (!parsed || !Array.isArray(parsed.messages)) {
        throw new Error('openai_chat_v1 -> google_generative_v1 requires JSON body with messages');
      }

      const model = String(parsed.model || candidate?.model || process.env.SENTINEL_GOOGLE_MODEL || 'gemini-1.5-pro');
      const googlePayload = {
        contents: toGoogleContents(parsed.messages),
        generationConfig: {
          temperature: parsed.temperature,
          topP: parsed.top_p,
          maxOutputTokens: parsed.max_tokens,
        },
      };

      const system = buildSystemPrompt(parsed.messages);
      if (system) {
        googlePayload.systemInstruction = {
          role: 'system',
          parts: [{ text: system }],
        };
      }

      const headerOverrides = {
        'content-type': 'application/json',
      };

      if (!headerOverrides['x-goog-api-key']) {
        const envKey = process.env.SENTINEL_GOOGLE_API_KEY;
        if (envKey) {
          headerOverrides['x-goog-api-key'] = envKey;
        }
      }

      return {
        method: 'POST',
        pathWithQuery: `/v1beta/models/${encodeURIComponent(model)}:generateContent`,
        bodyBuffer: toJsonBuffer(googlePayload),
        headerOverrides,
      };
    },
    transformBufferedResponse(input) {
      if (input.status >= 400) {
        return {
          status: input.status,
          bodyBuffer: input.bodyBuffer,
          responseHeaders: input.responseHeaders,
        };
      }

      const parsed = safeJsonParseBuffer(input.bodyBuffer);
      if (!parsed) {
        return {
          status: input.status,
          bodyBuffer: input.bodyBuffer,
          responseHeaders: input.responseHeaders,
        };
      }

      const firstCandidate = Array.isArray(parsed.candidates) ? parsed.candidates[0] : null;
      const text = extractGoogleText(firstCandidate);
      const promptTokens = Number(parsed.usageMetadata?.promptTokenCount || 0);
      const completionTokens = Number(parsed.usageMetadata?.candidatesTokenCount || 0);

      const openAiResponse = {
        id: `chatcmpl_${crypto.randomUUID()}`,
        object: 'chat.completion',
        created: Math.floor(Date.now() / 1000),
        model: parsed.modelVersion || null,
        choices: [
          {
            index: 0,
            message: {
              role: 'assistant',
              content: text,
            },
            finish_reason: mapGoogleFinishReason(firstCandidate?.finishReason),
          },
        ],
        usage: {
          prompt_tokens: promptTokens,
          completion_tokens: completionTokens,
          total_tokens: Number(parsed.usageMetadata?.totalTokenCount || promptTokens + completionTokens),
        },
      };

      const responseHeaders = {
        ...(input.responseHeaders || {}),
        'content-type': 'application/json',
      };

      return {
        status: input.status,
        bodyBuffer: toJsonBuffer(openAiResponse),
        responseHeaders,
      };
    },
  };
}

function selectUpstreamAdapter(input = {}) {
  const desiredContract = normalizeContract(input.desiredContract, 'passthrough');
  const candidateContract = normalizeContract(input.candidateContract, input.providerContract || 'passthrough');
  const provider = String(input.provider || '').toLowerCase();

  if (desiredContract === 'passthrough' || desiredContract === candidateContract) {
    return {
      ok: true,
      adapter: identityAdapter(),
    };
  }

  if (desiredContract === 'openai_chat_v1' && provider === 'anthropic') {
    return {
      ok: true,
      adapter: openAiToAnthropicAdapter(input.candidate),
    };
  }

  if (desiredContract === 'openai_chat_v1' && provider === 'google') {
    return {
      ok: true,
      adapter: openAiToGoogleAdapter(input.candidate),
    };
  }

  return {
    ok: false,
    reason: `No adapter from ${desiredContract} to ${candidateContract} for provider ${provider}`,
  };
}

module.exports = {
  selectUpstreamAdapter,
  normalizeContract,
  normalizeHeaders,
};
