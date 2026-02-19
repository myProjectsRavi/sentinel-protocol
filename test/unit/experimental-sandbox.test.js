const fs = require('fs');
const path = require('path');
const { ExperimentalSandbox, collectCandidates } = require('../../src/sandbox/experimental-sandbox');

const EVASION_FIXTURES = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', 'fixtures', 'hardening', 'sandbox-evasion-cases.json'), 'utf8')
);

describe('ExperimentalSandbox', () => {
  test('is disabled by default', () => {
    const sandbox = new ExperimentalSandbox();
    const result = sandbox.inspect({
      effectiveMode: 'enforce',
      bodyJson: {
        messages: [{ role: 'user', content: 'hi' }],
      },
    });
    expect(result.enabled).toBe(false);
    expect(result.detected).toBe(false);
  });

  test('detects and blocks disallowed tool-call patterns in block mode', () => {
    const sandbox = new ExperimentalSandbox({
      enabled: true,
      mode: 'block',
      disallowed_patterns: ['child_process', 'process\\.env'],
      target_tool_names: ['execute_shell'],
    });

    const result = sandbox.inspect({
      effectiveMode: 'enforce',
      bodyJson: {
        messages: [
          {
            role: 'assistant',
            tool_calls: [
              {
                function: {
                  name: 'execute_shell',
                  arguments: 'const cp = require("child_process"); cp.exec("echo test")',
                },
              },
            ],
          },
        ],
      },
    });

    expect(result.detected).toBe(true);
    expect(result.shouldBlock).toBe(true);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].pattern).toContain('child_process');
  });

  test('monitor mode detects but does not block', () => {
    const sandbox = new ExperimentalSandbox({
      enabled: true,
      mode: 'monitor',
      disallowed_patterns: ['id_rsa'],
      target_tool_names: ['execute_shell'],
    });

    const result = sandbox.inspect({
      effectiveMode: 'enforce',
      bodyJson: {
        messages: [
          {
            role: 'assistant',
            tool_calls: [
              {
                function: {
                  name: 'execute_shell',
                  arguments: 'cat ~/.ssh/id_rsa',
                },
              },
            ],
          },
        ],
      },
    });

    expect(result.detected).toBe(true);
    expect(result.shouldBlock).toBe(false);
  });

  test('collectCandidates extracts text from tool calls and messages', () => {
    const candidates = collectCandidates(
      {
        input: 'top level input',
        messages: [
          { role: 'user', content: 'plain content' },
          {
            role: 'assistant',
            tool_calls: [{ function: { name: 'execute_shell', arguments: 'echo 1' } }],
          },
        ],
      },
      new Set(['execute_shell']),
      1000
    );

    expect(candidates.length).toBeGreaterThanOrEqual(3);
  });

  test('detects evasion patterns from fixtures', () => {
    for (const fixture of EVASION_FIXTURES) {
      const sandbox = new ExperimentalSandbox({
        enabled: true,
        mode: 'block',
        normalize_evasion: true,
        decode_base64: true,
        disallowed_patterns: fixture.patterns,
        target_tool_names: ['execute_shell'],
      });
      const result = sandbox.inspect({
        effectiveMode: 'enforce',
        bodyJson: {
          messages: [
            {
              role: 'assistant',
              tool_calls: [
                {
                  function: {
                    name: 'execute_shell',
                    arguments: fixture.input,
                  },
                },
              ],
            },
          ],
        },
      });
      expect(Boolean(result.detected)).toBe(Boolean(fixture.expect_detected));
    }
  });
});
