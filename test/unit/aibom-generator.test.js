const { AIBOMGenerator } = require('../../src/governance/aibom-generator');

describe('AIBOMGenerator', () => {
  test('deduplicates providers/models and increments request_count', () => {
    let now = 1_700_000_000_000;
    const engine = new AIBOMGenerator({
      clock: () => now,
    });

    engine.recordRoute({ provider: 'openai', routePlan: { routeSource: 'header' } });
    now += 10;
    engine.recordRoute({ provider: 'openai', routePlan: { routeSource: 'header' } });
    now += 10;
    engine.recordRequest({ provider: 'openai', body: { model: 'gpt-4o-mini' } });
    now += 10;
    engine.recordRequest({ provider: 'openai', body: { model: 'gpt-4o-mini' } });

    const artifact = engine.exportArtifact();
    const provider = artifact.providers.find((item) => item.id === 'openai');
    const model = artifact.models.find((item) => item.id === 'gpt-4o-mini');

    expect(provider).toBeDefined();
    expect(provider.request_count).toBe(2);
    expect(model).toBeDefined();
    expect(model.request_count).toBe(2);
  });

  test('extracts model from request body when response headers are absent', () => {
    const engine = new AIBOMGenerator();
    engine.recordRequest({
      provider: 'anthropic',
      body: {
        model: 'claude-3-7-sonnet',
      },
    });
    engine.recordResponse({
      provider: 'anthropic',
      headers: {},
      body: { id: 'ok' },
    });

    const artifact = engine.exportArtifact();
    expect(artifact.models.some((item) => item.id === 'claude-3-7-sonnet')).toBe(true);
  });

  test('extracts model from response headers when available', () => {
    const engine = new AIBOMGenerator();
    engine.recordResponse({
      provider: 'openai',
      headers: {
        'x-openai-model': 'gpt-4.1-mini',
      },
      body: { ok: true },
    });

    const artifact = engine.exportArtifact();
    expect(artifact.models.some((item) => item.id === 'gpt-4.1-mini')).toBe(true);
  });

  test('sorts export arrays deterministically', () => {
    const engine = new AIBOMGenerator();
    engine.recordRoute({ provider: 'zeta', routePlan: { routeSource: 'header' } });
    engine.recordRoute({ provider: 'alpha', routePlan: { routeSource: 'header' } });
    engine.recordRequest({
      provider: 'alpha',
      body: {
        model: 'z-model',
        tools: [{ function: { name: 'z-tool' } }, { function: { name: 'a-tool' } }],
      },
      headers: {
        'x-sentinel-agent-id': 'agent-z',
      },
    });
    engine.recordRequest({
      provider: 'alpha',
      body: {
        model: 'a-model',
      },
      headers: {
        'x-sentinel-agent-id': 'agent-a',
      },
    });

    const artifact = engine.exportArtifact();
    expect(artifact.providers.map((item) => item.id)).toEqual(['alpha', 'zeta']);
    expect(artifact.models.map((item) => item.id)).toEqual(['a-model', 'z-model']);
    expect(artifact.tools.map((item) => item.id)).toEqual(['a-tool', 'z-tool']);
    expect(artifact.agents.map((item) => item.id)).toEqual(['agent-a', 'agent-z']);
  });

  test('never persists raw prompt text in output artifact', () => {
    const engine = new AIBOMGenerator();
    const secretPrompt = 'my-raw-sensitive-prompt-token-12345';
    engine.recordRequest({
      provider: 'openai',
      body: {
        model: 'gpt-4o-mini',
        messages: [{ role: 'user', content: secretPrompt }],
      },
      headers: {
        'x-sentinel-agent-id': 'agent-privacy-test',
      },
    });

    const serialized = JSON.stringify(engine.exportArtifact());
    expect(serialized.includes(secretPrompt)).toBe(false);
  });

  test('adds dataset lineage fingerprints without exposing raw dataset identifiers', () => {
    const engine = new AIBOMGenerator();
    const datasetId = 'finance_customers_2026_q1_sensitive';
    const datasetUrl = 's3://private-bucket/training-corpus/finance-customers-2026-q1.parquet';

    engine.recordRequest({
      provider: 'openai',
      headers: {
        'x-sentinel-dataset-id': datasetId,
      },
      body: {
        model: 'gpt-4o-mini',
        dataset_id: datasetId,
        retrieval: {
          source_url: datasetUrl,
        },
      },
    });

    const artifact = engine.exportArtifact();
    expect(Array.isArray(artifact.datasets)).toBe(true);
    expect(artifact.totals.datasets).toBeGreaterThan(0);
    const serialized = JSON.stringify(artifact);
    expect(serialized.includes(datasetId)).toBe(false);
    expect(serialized.includes(datasetUrl)).toBe(false);
    expect(artifact.datasets.every((item) => String(item.id || '').includes(':'))).toBe(true);
  });

  test('handles cyclic tool payloads without recursion failure', () => {
    const engine = new AIBOMGenerator({
      maxTraversalDepth: 6,
      maxTraversalNodes: 128,
    });
    const cyclicTool = {
      function: {
        name: 'cycle_tool',
      },
    };
    cyclicTool.self = cyclicTool;
    cyclicTool.nested = { ref: cyclicTool };

    expect(() =>
      engine.recordRequest({
        provider: 'openai',
        body: {
          tools: [cyclicTool],
        },
      })
    ).not.toThrow();

    const artifact = engine.exportArtifact();
    expect(artifact.tools.some((item) => item.id === 'cycle_tool')).toBe(true);
  });

  test('returns cached export in short window and refreshes after ttl', () => {
    let now = 1_700_000_000_000;
    const engine = new AIBOMGenerator({
      clock: () => now,
      exportCacheTtlMs: 1000,
    });
    engine.recordRoute({
      provider: 'openai',
      routePlan: {
        routeSource: 'header',
      },
    });

    const first = engine.exportArtifact();
    const second = engine.exportArtifact();
    expect(first).toBe(second);

    now += 1500;
    const third = engine.exportArtifact();
    expect(third).not.toBe(first);
  });
});
