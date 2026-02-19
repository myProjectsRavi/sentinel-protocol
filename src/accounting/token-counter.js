function positiveNumberOr(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function roundCurrency(value) {
  return Number(Number(value || 0).toFixed(6));
}

function countTokensFromText(text, charsPerToken = 4) {
  const normalized = String(text || '');
  if (normalized.length === 0) {
    return 0;
  }
  const ratio = positiveNumberOr(charsPerToken, 4);
  const bytes = Buffer.byteLength(normalized, 'utf8');
  return Math.max(1, Math.ceil(bytes / ratio));
}

function countTokensFromBuffer(buffer, charsPerToken = 4) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    return 0;
  }
  const ratio = positiveNumberOr(charsPerToken, 4);
  return Math.max(1, Math.ceil(buffer.length / ratio));
}

function safeParseJsonBuffer(buffer, maxBytes = 2 * 1024 * 1024) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0 || buffer.length > maxBytes) {
    return null;
  }
  try {
    return JSON.parse(buffer.toString('utf8'));
  } catch {
    return null;
  }
}

function asNonNegativeInt(value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) {
    return null;
  }
  return Math.floor(parsed);
}

function extractUsageFromResponseBody(responseBodyBuffer) {
  const parsed = safeParseJsonBuffer(responseBodyBuffer);
  if (!parsed || typeof parsed !== 'object') {
    return null;
  }

  const usage = parsed.usage && typeof parsed.usage === 'object' ? parsed.usage : null;
  if (!usage) {
    return null;
  }

  const promptTokens = asNonNegativeInt(usage.prompt_tokens ?? usage.input_tokens);
  const completionTokens = asNonNegativeInt(usage.completion_tokens ?? usage.output_tokens);
  const totalTokens = asNonNegativeInt(usage.total_tokens);

  const inputTokens = promptTokens ?? (totalTokens !== null && completionTokens !== null ? Math.max(0, totalTokens - completionTokens) : null);
  const outputTokens = completionTokens ?? (totalTokens !== null && inputTokens !== null ? Math.max(0, totalTokens - inputTokens) : null);

  if (inputTokens === null && outputTokens === null) {
    return null;
  }

  return {
    inputTokens: inputTokens ?? 0,
    outputTokens: outputTokens ?? 0,
    totalTokens:
      totalTokens ??
      (inputTokens !== null && outputTokens !== null ? inputTokens + outputTokens : null),
    source: 'upstream_usage',
  };
}

function estimateUsageFromBuffers(input = {}) {
  return {
    inputTokens: countTokensFromBuffer(input.requestBodyBuffer, input.charsPerToken),
    outputTokens: countTokensFromBuffer(input.responseBodyBuffer, input.charsPerToken),
    totalTokens:
      countTokensFromBuffer(input.requestBodyBuffer, input.charsPerToken) +
      countTokensFromBuffer(input.responseBodyBuffer, input.charsPerToken),
    source: 'estimated',
  };
}

function estimateUsageFromStream(input = {}) {
  const inputTokens = countTokensFromBuffer(input.requestBodyBuffer, input.charsPerToken);
  const streamBytes = Number(input.streamedBytes || 0);
  const ratio = positiveNumberOr(input.charsPerToken, 4);
  const outputTokens = streamBytes > 0 ? Math.max(1, Math.ceil(streamBytes / ratio)) : 0;
  return {
    inputTokens,
    outputTokens,
    totalTokens: inputTokens + outputTokens,
    source: 'stream_estimated',
  };
}

function computeCostUsd(input = {}) {
  const inputTokens = Math.max(0, Number(input.inputTokens || 0));
  const outputTokens = Math.max(0, Number(input.outputTokens || 0));
  const inputCostPer1k = Math.max(0, Number(input.inputCostPer1k || 0));
  const outputCostPer1k = Math.max(0, Number(input.outputCostPer1k || 0));

  const inputCost = (inputTokens / 1000) * inputCostPer1k;
  const outputCost = (outputTokens / 1000) * outputCostPer1k;
  return roundCurrency(inputCost + outputCost);
}

module.exports = {
  countTokensFromText,
  countTokensFromBuffer,
  extractUsageFromResponseBody,
  estimateUsageFromBuffers,
  estimateUsageFromStream,
  computeCostUsd,
  roundCurrency,
};
