#!/usr/bin/env node

const { NeuralInjectionClassifier } = require('../src/engines/neural-injection-classifier');

function parseArg(flag) {
  const index = process.argv.indexOf(flag);
  if (index === -1) {
    return undefined;
  }
  return process.argv[index + 1];
}

async function main() {
  const modelId = parseArg('--model-id') || process.env.PRELOAD_NEURAL_MODEL_ID || 'Xenova/all-MiniLM-L6-v2';
  const cacheDir = parseArg('--cache-dir') || process.env.PRELOAD_MODEL_CACHE_DIR || '/home/sentinel/.sentinel/models';
  const timeoutMs = Number(parseArg('--timeout-ms') || process.env.PRELOAD_NEURAL_TIMEOUT_MS || 5000);

  console.log('Preloading ONNX models for neural injection classifier...');
  const classifier = new NeuralInjectionClassifier({
    enabled: true,
    model_id: modelId,
    cache_dir: cacheDir,
    timeout_ms: timeoutMs,
  });
  await classifier.loadPrototypeEmbeddings();
  console.log(`Neural model cached successfully: ${modelId}`);
  console.log(`Cache directory: ${cacheDir}`);
}

main().catch((error) => {
  console.error(`Model preload failed: ${error.message}`);
  process.exitCode = 1;
});
