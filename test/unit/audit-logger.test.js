const fs = require('fs');
const os = require('os');
const path = require('path');

const { AuditLogger } = require('../../src/logging/audit-logger');

describe('AuditLogger', () => {
  test('flush waits for pending writes before resolving', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-audit-'));
    const logPath = path.join(tmpDir, 'audit.jsonl');

    try {
      const logger = new AuditLogger(logPath);
      logger.write({ id: 1, decision: 'allow' });
      logger.write({ id: 2, decision: 'block' });

      await logger.flush({ timeoutMs: 2000 });

      const lines = fs.readFileSync(logPath, 'utf8').trim().split('\n');
      expect(lines).toHaveLength(2);
      expect(JSON.parse(lines[0]).id).toBe(1);
      expect(JSON.parse(lines[1]).id).toBe(2);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('close prevents new writes', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-audit-'));
    const logPath = path.join(tmpDir, 'audit.jsonl');

    try {
      const logger = new AuditLogger(logPath);
      logger.write({ id: 1, decision: 'allow' });
      await logger.close({ timeoutMs: 2000 });
      await logger.write({ id: 2, decision: 'block' });

      const lines = fs.readFileSync(logPath, 'utf8').trim().split('\n');
      expect(lines).toHaveLength(1);
      expect(JSON.parse(lines[0]).id).toBe(1);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
