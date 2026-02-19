const fs = require('fs');
const os = require('os');
const path = require('path');

const { BudgetStore } = require('../../src/accounting/budget-store');

describe('BudgetStore', () => {
  test('blocks request estimate when projected daily limit exceeded', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-budget-'));
    const storeFile = path.join(tmpDir, 'budget.json');
    const store = new BudgetStore({
      enabled: true,
      action: 'block',
      daily_limit_usd: 0.000001,
      store_file: storeFile,
      chars_per_token: 1,
      input_cost_per_1k_tokens: 0.001,
      output_cost_per_1k_tokens: 0.001,
    });

    const estimate = store.estimateRequest({
      method: 'POST',
      requestBodyBuffer: Buffer.from('x'.repeat(8000)),
    });
    expect(estimate.enabled).toBe(true);
    expect(estimate.applies).toBe(true);
    expect(estimate.allowed).toBe(false);
    expect(estimate.reason).toBe('daily_limit_exceeded');
  });

  test('records buffered usage and persists snapshot', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-budget-'));
    const storeFile = path.join(tmpDir, 'budget.json');
    const store = new BudgetStore({
      enabled: true,
      action: 'block',
      daily_limit_usd: 10,
      store_file: storeFile,
      chars_per_token: 4,
      input_cost_per_1k_tokens: 0.002,
      output_cost_per_1k_tokens: 0.004,
    });

    const result = await store.recordBuffered({
      provider: 'openai',
      requestBodyBuffer: Buffer.from('hello'),
      responseBodyBuffer: Buffer.from(JSON.stringify({
        usage: {
          prompt_tokens: 50,
          completion_tokens: 100,
          total_tokens: 150,
        },
      })),
      replayedFromVcr: false,
      replayedFromSemanticCache: false,
      correlationId: 'corr',
    });

    expect(result.charged).toBe(true);
    expect(result.inputTokens).toBe(50);
    expect(result.outputTokens).toBe(100);
    expect(result.chargedUsd).toBeCloseTo(0.0005, 6);
    expect(fs.existsSync(storeFile)).toBe(true);
  });

  test('does not charge replay hits by default', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-budget-'));
    const store = new BudgetStore({
      enabled: true,
      daily_limit_usd: 10,
      store_file: path.join(tmpDir, 'budget.json'),
    });

    const result = await store.recordBuffered({
      provider: 'openai',
      requestBodyBuffer: Buffer.from('hello'),
      responseBodyBuffer: Buffer.from('world'),
      replayedFromVcr: true,
      replayedFromSemanticCache: false,
    });
    expect(result.charged).toBe(false);
    expect(result.reason).toBe('replay_not_charged');
  });
});
