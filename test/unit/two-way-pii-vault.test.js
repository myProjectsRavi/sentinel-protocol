const { Readable } = require('stream');
const { TwoWayPIIVault } = require('../../src/pii/two-way-vault');

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
});
