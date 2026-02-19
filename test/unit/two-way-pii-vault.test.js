const fs = require('fs');
const path = require('path');
const { Readable } = require('stream');
const { TwoWayPIIVault } = require('../../src/pii/two-way-vault');

const VAULT_FIXTURES = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', 'fixtures', 'hardening', 'vault-attack-cases.json'), 'utf8')
);

async function collect(stream) {
  const chunks = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), 'utf8'));
  }
  return Buffer.concat(chunks).toString('utf8');
}

describe('TwoWayPIIVault', () => {
  test('tokenizes ingress findings and detokenizes buffered egress', () => {
    const vault = new TwoWayPIIVault({
      enabled: true,
      mode: 'active',
      target_types: ['email_address'],
      token_domain: 'sentinel.local',
    });
    const sessionKey = vault.deriveSessionKey(
      { 'x-sentinel-session-id': 'session-1' },
      'corr-1'
    );
    const ingress = vault.applyIngress({
      sessionKey,
      text: '{"messages":[{"role":"user","content":"email ravi@example.com"}]}',
      findings: [{ id: 'email_address', value: 'ravi@example.com' }],
    });

    expect(ingress.applied).toBe(true);
    expect(ingress.text).not.toContain('ravi@example.com');
    expect(ingress.text).toContain('@sentinel.local');

    const egress = vault.applyEgressBuffer({
      sessionKey,
      contentType: 'application/json',
      bodyBuffer: Buffer.from(`{"tool":"send_email","target":"${ingress.mappings[0].token}"}`, 'utf8'),
    });
    expect(egress.changed).toBe(true);
    expect(egress.bodyBuffer.toString('utf8')).toContain('ravi@example.com');
  });

  test('monitor mode does not mutate ingress payload', () => {
    const vault = new TwoWayPIIVault({
      enabled: true,
      mode: 'monitor',
      target_types: ['email_address'],
    });
    const result = vault.applyIngress({
      sessionKey: 's1',
      text: 'email ravi@example.com',
      findings: [{ id: 'email_address', value: 'ravi@example.com' }],
    });
    expect(result.detected).toBe(true);
    expect(result.applied).toBe(false);
    expect(result.monitorOnly).toBe(true);
  });

  test('stream transform rewrites tokens across chunk boundaries', async () => {
    const vault = new TwoWayPIIVault({
      enabled: true,
      mode: 'active',
      target_types: ['email_address'],
    });
    const sessionKey = 's-stream';
    const ingress = vault.applyIngress({
      sessionKey,
      text: 'email ravi@example.com',
      findings: [{ id: 'email_address', value: 'ravi@example.com' }],
    });
    const token = ingress.mappings[0].token;
    const transform = vault.createEgressStreamTransform({
      sessionKey,
      contentType: 'text/event-stream',
    });
    const source = Readable.from([
      Buffer.from(`data: {"target":"${token.slice(0, 8)}`, 'utf8'),
      Buffer.from(`${token.slice(8)}"}\n\n`, 'utf8'),
    ]);
    const out = await collect(source.pipe(transform));
    expect(out).toContain('ravi@example.com');
    expect(out).not.toContain(token);
  });

  test('guardrails: cross-session token replay does not detokenize', () => {
    const fixture = VAULT_FIXTURES.find((item) => item.id === 'cross_session_token_replay');
    const vault = new TwoWayPIIVault({
      enabled: true,
      mode: 'active',
      target_types: ['email_address'],
    });
    const sessionA = 'session-A';
    const sessionB = 'session-B';
    const ingress = vault.applyIngress({
      sessionKey: sessionA,
      text: 'send to ravi@example.com',
      findings: [{ id: 'email_address', value: 'ravi@example.com' }],
    });
    const token = ingress.mappings[0].token;
    const egressB = vault.applyEgressBuffer({
      sessionKey: sessionB,
      contentType: 'application/json',
      bodyBuffer: Buffer.from(`{"target":"${token}"}`, 'utf8'),
    });
    expect(Boolean(egressB.changed)).toBe(Boolean(fixture.expect_rewritten));
  });

  test('guardrails: ingress skips over-sized payload', () => {
    const fixture = VAULT_FIXTURES.find((item) => item.id === 'ingress_large_payload_skip');
    const vault = new TwoWayPIIVault({
      enabled: true,
      mode: 'active',
      target_types: ['email_address'],
      max_payload_bytes: 64,
    });
    const result = vault.applyIngress({
      sessionKey: 's-large',
      text: `prefix-${'a'.repeat(256)}-ravi@example.com`,
      findings: [{ id: 'email_address', value: 'ravi@example.com' }],
    });
    expect(result.applied).toBe(false);
    expect(result.skipped).toBe(fixture.expect_skipped);
  });

  test('guardrails: egress rewrite entry cap limits detokenization scope', () => {
    const fixture = VAULT_FIXTURES.find((item) => item.id === 'egress_entry_cap');
    const vault = new TwoWayPIIVault({
      enabled: true,
      mode: 'active',
      target_types: ['email_address'],
      max_egress_rewrite_entries: 1,
    });
    const sessionKey = 's-cap';
    const first = vault.applyIngress({
      sessionKey,
      text: 'first a@example.com',
      findings: [{ id: 'email_address', value: 'a@example.com' }],
    });
    const second = vault.applyIngress({
      sessionKey,
      text: 'second b@example.com',
      findings: [{ id: 'email_address', value: 'b@example.com' }],
    });
    const egress = vault.applyEgressBuffer({
      sessionKey,
      contentType: 'application/json',
      bodyBuffer: Buffer.from(`{"one":"${first.mappings[0].token}","two":"${second.mappings[0].token}"}`, 'utf8'),
    });
    expect(Boolean(egress.bodyBuffer.toString('utf8').includes('b@example.com'))).toBe(Boolean(fixture.expect_rewritten));
  });
});
