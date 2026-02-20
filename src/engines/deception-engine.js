const { clampPositiveInt } = require('../utils/primitives');

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

function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

const DEFAULT_STREAM_TOKENS = [
  'Querying internal index...',
  'Collecting shard metadata...',
  'Resolving schema hints...',
  'Building synthetic plan...',
  'Finalizing candidate output...',
];

class DeceptionEngine {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = String(config.mode || 'off').toLowerCase() === 'tarpit' ? 'tarpit' : 'off';
    this.onInjection = config.on_injection !== false;
    this.onLoop = config.on_loop !== false;
    this.minInjectionScore = clampScore(config.min_injection_score, 0.9);
    this.sseTokenIntervalMs = clampPositiveInt(config.sse_token_interval_ms, 1000, 50, 30000);
    this.sseMaxTokens = clampPositiveInt(config.sse_max_tokens, 20, 1, 200);
    this.nonStreamDelayMs = clampPositiveInt(config.non_stream_delay_ms, 250, 0, 15000);
  }

  isEnabled() {
    return this.enabled === true && this.mode === 'tarpit';
  }

  shouldEngage({ trigger, injectionScore = 0, effectiveMode = 'monitor' } = {}) {
    if (!this.isEnabled()) {
      return { engage: false, reason: 'disabled' };
    }
    if (effectiveMode !== 'enforce') {
      return { engage: false, reason: 'mode_not_enforce' };
    }

    if (trigger === 'injection') {
      if (!this.onInjection) {
        return { engage: false, reason: 'injection_disabled' };
      }
      if (Number(injectionScore) < this.minInjectionScore) {
        return { engage: false, reason: 'injection_below_threshold' };
      }
      return { engage: true, trigger: 'injection' };
    }

    if (trigger === 'loop') {
      if (!this.onLoop) {
        return { engage: false, reason: 'loop_disabled' };
      }
      return { engage: true, trigger: 'loop' };
    }

    return { engage: false, reason: 'unsupported_trigger' };
  }

  createBufferedPayload({ trigger = 'unknown', provider = 'openai' } = {}) {
    const created = Math.floor(Date.now() / 1000);
    const providerName = String(provider || 'openai');
    const text =
      trigger === 'loop'
        ? 'Request accepted. Continuing internal reconciliation workflow.'
        : 'Request accepted. Continuing guarded analysis workflow.';
    const payload = {
      id: `chatcmpl-sentinel-${Date.now()}`,
      object: 'chat.completion',
      created,
      model: 'sentinel-phantom-1',
      choices: [
        {
          index: 0,
          message: {
            role: 'assistant',
            content: text,
          },
          finish_reason: 'stop',
        },
      ],
      usage: {
        prompt_tokens: 0,
        completion_tokens: 0,
        total_tokens: 0,
      },
      sentinel_deception: {
        mode: this.mode,
        trigger,
        provider: providerName,
      },
    };

    return Buffer.from(JSON.stringify(payload));
  }

  buildStreamChunk(token, index) {
    const payload = {
      id: `chatcmpl-sentinel-stream-${Date.now()}`,
      object: 'chat.completion.chunk',
      created: Math.floor(Date.now() / 1000),
      model: 'sentinel-phantom-1',
      choices: [
        {
          index: 0,
          delta: {
            content: index === 0 ? `${token}` : ` ${token}`,
          },
          finish_reason: null,
        },
      ],
    };
    return `data: ${JSON.stringify(payload)}\n\n`;
  }

  async streamToSSE(res, { trigger = 'injection', onChunk } = {}) {
    const tokenBase = trigger === 'loop'
      ? ['Replaying safe checkpoint...', 'Validating loop context...', 'Holding execution...']
      : DEFAULT_STREAM_TOKENS;
    let bytes = 0;

    for (let idx = 0; idx < this.sseMaxTokens; idx += 1) {
      if (res.destroyed || res.writableEnded) {
        break;
      }
      const chunk = this.buildStreamChunk(tokenBase[idx % tokenBase.length], idx);
      const buffer = Buffer.from(chunk, 'utf8');
      bytes += buffer.length;
      if (typeof onChunk === 'function') {
        onChunk(buffer);
      }
      res.write(buffer);
      await sleep(this.sseTokenIntervalMs);
    }

    if (!res.destroyed && !res.writableEnded) {
      const doneChunk = Buffer.from('data: [DONE]\n\n', 'utf8');
      bytes += doneChunk.length;
      if (typeof onChunk === 'function') {
        onChunk(doneChunk);
      }
      res.write(doneChunk);
      res.end();
    }

    return { streamedBytes: bytes };
  }
}

module.exports = {
  DeceptionEngine,
};
