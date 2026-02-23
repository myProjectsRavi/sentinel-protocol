const {
  AtlasTracker,
  classifyEngine,
  aggregateByTechnique,
  exportNavigatorPayload,
} = require('../../src/governance/atlas-tracker');

describe('atlas tracker', () => {
  test('maps known engine injection_scanner to a non-empty atlas technique id', () => {
    const mapped = classifyEngine('injection_scanner');
    expect(mapped.technique_id).toBeTruthy();
    expect(mapped.technique_id).not.toBe('UNMAPPED');
    expect(mapped.tactic).toBeTruthy();
    expect(mapped.name).toBeTruthy();
  });

  test('returns UNMAPPED for unknown engine names', () => {
    const mapped = classifyEngine('totally_new_engine_name');
    expect(mapped.engine).toBe('totally_new_engine_name');
    expect(mapped.technique_id).toBe('UNMAPPED');
    expect(mapped.tactic).toBe('UNMAPPED');
  });

  test('aggregates counts by technique with stable sort', () => {
    const rows = aggregateByTechnique([
      { engine: 'injection_scanner' },
      { engine: 'injection_scanner' },
      { engine: 'pii_scanner' },
      { engine: 'unknown_engine' },
    ]);

    expect(rows[0]).toMatchObject({
      technique_id: 'AML.T0051.000',
      count: 2,
    });
    expect(rows[1].count).toBe(1);
    expect(rows[2].count).toBe(1);
    expect(rows[1].technique_id.localeCompare(rows[2].technique_id)).toBeLessThanOrEqual(0);
  });

  test('exports deterministic navigator-compatible payload for identical input', () => {
    const tracker = new AtlasTracker();
    const events = [
      { engine: 'injection_scanner' },
      { engine: 'pii_scanner' },
      { engine: 'unknown_engine' },
    ];
    const options = {
      source: {
        audit_path: '/tmp/sentinel-atlas.jsonl',
        limit: 200000,
      },
    };

    const first = tracker.exportNavigatorPayload(events, options);
    const second = tracker.exportNavigatorPayload(events, options);
    expect(first).toEqual(second);
    expect(first.schema_version).toBe('sentinel.atlas.navigator.v1');
    expect(Array.isArray(first.techniques)).toBe(true);

    const firstSerialized = JSON.stringify(exportNavigatorPayload(events, options));
    const secondSerialized = JSON.stringify(exportNavigatorPayload(events, options));
    expect(firstSerialized).toBe(secondSerialized);
  });

  test('classification remains bounded for oversized decision and reasons payloads', () => {
    const tracker = new AtlasTracker();
    const massiveReasons = new Array(500).fill('x'.repeat(5000));
    massiveReasons[0] = 'injection:high';
    const event = {
      decision: `blocked_policy_${'y'.repeat(10000)}`,
      reasons: massiveReasons,
    };

    const classification = tracker.classifyEvent(event);
    expect(classification).toEqual(
      expect.objectContaining({
        mapping_version: expect.any(String),
        technique_id: expect.any(String),
        tactic: expect.any(String),
      })
    );
  });
});
