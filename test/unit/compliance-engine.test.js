const fs = require('fs');
const os = require('os');
const path = require('path');

const { ComplianceEngine, readJsonLines, readJsonLinesDetailed } = require('../../src/governance/compliance-engine');

function writeJsonl(filePath, entries) {
  const lines = entries.map((entry) => JSON.stringify(entry));
  fs.writeFileSync(filePath, `${lines.join('\n')}\n`, 'utf8');
}

describe('compliance engine', () => {
  test('reads tail entries with bounded limit', () => {
    const filePath = path.join(os.tmpdir(), `sentinel-compliance-${Date.now()}-tail.jsonl`);
    writeJsonl(filePath, [{ id: 1 }, { id: 2 }, { id: 3 }, { id: 4 }]);

    const rows = readJsonLines(filePath, { limit: 2, maxReadBytes: 1024 });
    expect(rows).toEqual([{ id: 3 }, { id: 4 }]);

    const detailed = readJsonLinesDetailed(filePath, { limit: 2, maxReadBytes: 1024 });
    expect(detailed.events).toEqual([{ id: 3 }, { id: 4 }]);
    expect(detailed.metadata.parsed_events).toBe(2);
    expect(detailed.metadata.bytes_scanned).toBeGreaterThan(0);
    expect(typeof detailed.metadata.tail_sha256).toBe('string');
  });

  test('skips partial first line when reading file tail', () => {
    const filePath = path.join(os.tmpdir(), `sentinel-compliance-${Date.now()}-partial.jsonl`);
    writeJsonl(filePath, [
      { id: 1, message: 'a'.repeat(200) },
      { id: 2, message: 'b'.repeat(200) },
      { id: 3, message: 'c'.repeat(200) },
      { id: 4, message: 'd'.repeat(200) },
    ]);

    const rows = readJsonLines(filePath, { limit: 10, maxReadBytes: 350 });
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      expect(typeof row.id).toBe('number');
    }
  });

  test('generates evidence summary from bounded event sample', () => {
    const filePath = path.join(os.tmpdir(), `sentinel-compliance-${Date.now()}-report.jsonl`);
    writeJsonl(filePath, [
      { decision: 'forwarded' },
      { decision: 'blocked_policy' },
      { decision: 'upstream_error' },
      { decision: 'blocked_egress', pii_types: ['email'] },
    ]);

    const engine = new ComplianceEngine({
      auditPath: filePath,
      maxReadBytes: 1024,
    });
    const report = engine.generateSOC2Evidence({ limit: 3 });

    expect(report.framework).toBe('SOC2');
    expect(report.sample_size).toBe(3);
    expect(report.summary.total_events).toBe(3);
    expect(report.summary.blocked_events).toBe(2);
    expect(report.summary.upstream_errors).toBe(1);
    expect(report.summary.provider_totals).toEqual({ unknown: 3 });
    expect(report.source.parsed_events).toBe(3);
    expect(typeof report.integrity.window_sha256).toBe('string');
  });

  test('captures provider/reason/latency and budget aggregates for enterprise evidence', () => {
    const filePath = path.join(os.tmpdir(), `sentinel-compliance-${Date.now()}-aggregates.jsonl`);
    writeJsonl(filePath, [
      {
        timestamp: '2026-02-19T00:00:00.000Z',
        decision: 'forwarded',
        provider: 'openai',
        reasons: ['policy:monitor'],
        duration_ms: 12,
        budget_charged_usd: 0.0012,
      },
      {
        timestamp: '2026-02-19T00:00:01.000Z',
        decision: 'blocked_policy',
        provider: 'openai',
        reasons: ['injection:high'],
        duration_ms: 35,
        budget_charged_usd: 0,
      },
      {
        timestamp: '2026-02-19T00:00:02.000Z',
        decision: 'upstream_error',
        provider: 'anthropic',
        reasons: ['timeout'],
        duration_ms: 80,
        budget_charged_usd: 0.0005,
      },
    ]);

    const engine = new ComplianceEngine({
      auditPath: filePath,
      maxReadBytes: 2048,
      sampleLimit: 2,
    });
    const report = engine.generateSOC2Evidence({ limit: 10 });

    expect(report.summary.provider_totals).toEqual({
      anthropic: 1,
      openai: 2,
    });
    expect(report.summary.top_reasons.length).toBeGreaterThan(0);
    expect(report.summary.latency_ms.count).toBe(3);
    expect(report.summary.latency_ms.p95).toBe(80);
    expect(report.summary.budget_charged_usd_total).toBeCloseTo(0.0017, 6);
    expect(report.summary.window_start).toBe('2026-02-19T00:00:00.000Z');
    expect(report.summary.window_end).toBe('2026-02-19T00:00:02.000Z');
    expect(report.samples.blocked.length).toBeGreaterThan(0);
    expect(report.samples.upstream_errors.length).toBeGreaterThan(0);
  });
});
