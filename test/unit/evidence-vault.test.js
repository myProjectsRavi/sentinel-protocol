const { EvidenceVault } = require('../../src/governance/evidence-vault');

describe('EvidenceVault', () => {
  test('appends evidence entries with chain hash continuity', () => {
    const vault = new EvidenceVault({
      enabled: true,
      mode: 'active',
      max_entries: 100,
      retention_days: 365,
    });
    const a = vault.append({
      timestamp: '2026-01-01T00:00:00.000Z',
      control: 'injection_scanner',
      outcome: 'blocked',
      details: { count: 1 },
    });
    const b = vault.append({
      timestamp: '2026-01-01T00:01:00.000Z',
      control: 'pii_scanner',
      outcome: 'redacted',
      details: { count: 2 },
    });

    expect(a.entry_hash).toBeDefined();
    expect(b.prev_hash).toBe(a.entry_hash);
  });

  test('fails verification on tampered middle entry', () => {
    const vault = new EvidenceVault({
      enabled: true,
      mode: 'active',
    });
    vault.append({
      timestamp: '2026-01-01T00:00:00.000Z',
      control: 'engine-a',
      outcome: 'observed',
      details: {},
    });
    vault.append({
      timestamp: '2026-01-01T00:01:00.000Z',
      control: 'engine-b',
      outcome: 'blocked',
      details: {},
    });

    vault.entries[1].payload.outcome = 'tampered';
    const check = vault.verify(1);
    expect(check.valid).toBe(false);
    expect(check.reason).toBe('payload_hash_mismatch');
  });

  test('exports deterministic compliance packet', () => {
    const build = () => {
      const vault = new EvidenceVault({
        enabled: true,
        mode: 'active',
      });
      vault.append({
        timestamp: '2026-01-01T00:00:00.000Z',
        control: 'engine-a',
        outcome: 'observed',
        details: {},
      });
      vault.append({
        timestamp: '2026-01-01T00:00:01.000Z',
        control: 'engine-b',
        outcome: 'blocked',
        details: {},
      });
      const packet = vault.exportPacket('soc2');
      return {
        framework: packet.framework,
        entry_count: packet.entry_count,
        chain_head: packet.chain_head,
        controls: packet.controls,
      };
    };
    const first = build();
    const second = build();
    expect(first).toEqual(second);
  });

  test('retention pruning removes out-of-window entries only', () => {
    const vault = new EvidenceVault({
      enabled: true,
      mode: 'active',
      retention_days: 1,
    });
    vault.append({
      timestamp: '2020-01-01T00:00:00.000Z',
      control: 'old',
      outcome: 'observed',
      details: {},
    });
    vault.append({
      timestamp: new Date().toISOString(),
      control: 'new',
      outcome: 'observed',
      details: {},
    });
    vault.prune(Date.now());

    expect(vault.entries.length).toBe(1);
    expect(vault.entries[0].payload.control).toBe('new');
  });
});
