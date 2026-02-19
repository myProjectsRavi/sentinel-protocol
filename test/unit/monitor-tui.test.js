const fs = require('fs');
const os = require('os');
const path = require('path');

const { summarizePIITypes, summarizeSwarmNodes, extractThreatEvents, LogTailer } = require('../../src/monitor/tui');

describe('monitor tui helpers', () => {
  test('summarizePIITypes returns top pii type counts', () => {
    const summary = summarizePIITypes([
      { pii_types: ['email', 'ssn'] },
      { pii_types: ['email'] },
      { pii_types: ['credit_card'] },
    ]);

    expect(summary[0][0]).toBe('email');
    expect(summary[0][1]).toBe(2);
  });

  test('summarizeSwarmNodes orders peers by rejection volume', () => {
    const nodes = summarizeSwarmNodes({
      swarm_node_metrics: {
        'node-a': { verified: 4, rejected: 1, timestamp_skew_rejected: 0 },
        'node-b': { verified: 2, rejected: 5, timestamp_skew_rejected: 2 },
      },
    });
    expect(nodes[0].nodeId).toBe('node-b');
    expect(nodes[0].skew).toBe(2);
  });

  test('extractThreatEvents returns latest blocked/egress events', () => {
    const events = extractThreatEvents([
      { decision: 'forwarded', response_status: 200, reasons: [] },
      { decision: 'blocked_egress_entropy', response_status: 403, reasons: ['egress_entropy_detected'] },
      { decision: 'forwarded', response_status: 200, reasons: ['cognitive_rollback_suggested'] },
    ]);
    expect(events.length).toBeGreaterThan(0);
    expect(events[0].decision).toContain('forwarded');
  });

  test('LogTailer reads only appended bytes and survives file rotation', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-tui-'));
    const logPath = path.join(tmpDir, 'audit.jsonl');
    const line1 = JSON.stringify({ id: 1, response_status: 200 });
    const line2 = JSON.stringify({ id: 2, response_status: 403 });

    try {
      fs.writeFileSync(logPath, `${line1}\n`);
      const tailer = new LogTailer(logPath, {
        maxEntries: 10,
        readChunkBytes: 32,
        initialReadBytes: 1024,
      });

      let entries = tailer.tick();
      expect(entries).toHaveLength(1);
      expect(entries[0].id).toBe(1);

      fs.appendFileSync(logPath, `${line2}\n`);
      entries = tailer.tick();
      expect(entries).toHaveLength(2);
      expect(entries[1].id).toBe(2);

      fs.writeFileSync(logPath, `${JSON.stringify({ id: 3, response_status: 200 })}\n`);
      entries = tailer.tick();
      expect(entries[entries.length - 1].id).toBe(3);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('LogTailer preserves multibyte utf-8 text split across chunks', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-tui-utf8-'));
    const logPath = path.join(tmpDir, 'audit.jsonl');

    try {
      const entry = {
        id: 77,
        reason: 'blocked 🔒 東京',
      };
      fs.writeFileSync(logPath, `${JSON.stringify(entry)}\n`, 'utf8');

      const tailer = new LogTailer(logPath, {
        maxEntries: 10,
        // Intentionally small to force chunk splits in multibyte sequences.
        readChunkBytes: 7,
        initialReadBytes: 1024,
      });

      const entries = tailer.tick();
      expect(entries).toHaveLength(1);
      expect(entries[0].reason).toBe('blocked 🔒 東京');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
