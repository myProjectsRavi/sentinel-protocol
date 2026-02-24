const { SandboxEnforcer } = require('../../src/security/sandbox-enforcer');

describe('SandboxEnforcer', () => {
  test('blocks path traversal attempts in enforce mode', () => {
    const enforcer = new SandboxEnforcer({
      enabled: true,
      mode: 'block',
      block_on_path_escape: true,
    });
    const decision = enforcer.evaluate({
      bodyJson: {
        arguments: {
          path: '../../etc/passwd',
        },
      },
      effectiveMode: 'enforce',
    });

    expect(decision.detected).toBe(true);
    expect(decision.findings.some((item) => item.code === 'sandbox_path_traversal_detected')).toBe(true);
    expect(decision.shouldBlock).toBe(true);
  });

  test('allows arguments within declared path boundaries', () => {
    const enforcer = new SandboxEnforcer({
      enabled: true,
      mode: 'block',
      allowed_paths: ['/workspace'],
      block_on_path_escape: true,
    });
    const decision = enforcer.evaluate({
      bodyJson: {
        arguments: {
          path: '/workspace/project/readme.md',
        },
      },
      effectiveMode: 'enforce',
    });

    expect(decision.detected).toBe(false);
    expect(decision.shouldBlock).toBe(false);
  });

  test('blocks outbound network calls to non-allowlisted domains', () => {
    const enforcer = new SandboxEnforcer({
      enabled: true,
      mode: 'block',
      allowed_domains: ['api.example.com'],
      block_on_network_escape: true,
    });
    const decision = enforcer.evaluate({
      bodyJson: {
        tool_arguments: {
          url: 'https://evil.example.net/steal',
        },
      },
      effectiveMode: 'enforce',
    });

    expect(decision.detected).toBe(true);
    expect(decision.findings.some((item) => item.code === 'sandbox_network_domain_outside_boundary')).toBe(true);
    expect(decision.shouldBlock).toBe(true);
  });
});

