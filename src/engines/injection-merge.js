function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function mergeInjectionResults(baseResult = {}, neuralResult = null, neuralConfig = {}) {
  const base = {
    score: Number(baseResult.score || 0),
    matchedSignals: Array.isArray(baseResult.matchedSignals) ? [...baseResult.matchedSignals] : [],
    scanTruncated: Boolean(baseResult.scanTruncated),
  };

  if (!neuralResult || neuralResult.enabled !== true) {
    return {
      ...baseResult,
      ...base,
      neural: neuralResult || { enabled: false, score: 0, error: null },
    };
  }

  if (neuralResult.error) {
    return {
      ...baseResult,
      ...base,
      neural: neuralResult,
    };
  }

  const mode = String(neuralConfig.mode || 'max').toLowerCase();
  const weight = Number(neuralConfig.weight ?? 1);
  const weightedNeural = clamp(
    Number.isFinite(weight) ? Number(neuralResult.score || 0) * weight : Number(neuralResult.score || 0),
    0,
    1
  );

  let mergedScore;
  if (mode === 'blend') {
    mergedScore = clamp((base.score * 0.5) + (weightedNeural * 0.5), 0, 1);
  } else {
    mergedScore = clamp(Math.max(base.score, weightedNeural), 0, 1);
  }

  const mergedSignals = [...base.matchedSignals];
  if (weightedNeural > 0) {
    mergedSignals.push({
      id: 'neural_injection_classifier',
      category: 'neural',
      count: 1,
      contribution: Number(weightedNeural.toFixed(3)),
      attack_prototype: neuralResult.attackPrototype || null,
      benign_prototype: neuralResult.benignPrototype || null,
    });
  }

  return {
    ...baseResult,
    score: Number(mergedScore.toFixed(3)),
    matchedSignals: mergedSignals,
    scanTruncated: Boolean(base.scanTruncated || neuralResult.scanTruncated),
    neural: neuralResult,
  };
}

module.exports = {
  mergeInjectionResults,
};
