const { ToolSchemaValidator } = require('../../src/security/tool-schema-validator');

function makeTool(overrides = {}) {
  const functionOverrides = overrides.function || {};
  const parametersOverrides = functionOverrides.parameters || {};
  const safeOverrides = { ...overrides };
  delete safeOverrides.function;
  return {
    type: 'function',
    function: {
      name: 'read_docs',
      description: 'Read documentation',
      parameters: {
        type: 'object',
        properties: {
          query: { type: 'string', description: 'search query' },
          ...(parametersOverrides.properties || {}),
        },
        required: Array.isArray(parametersOverrides.required) ? parametersOverrides.required : ['query'],
        ...(parametersOverrides || {}),
      },
      ...functionOverrides,
    },
    ...safeOverrides,
  };
}

describe('ToolSchemaValidator', () => {
  test('detects and sanitizes dangerous parameters in monitor mode', () => {
    const validator = new ToolSchemaValidator({
      enabled: true,
      mode: 'monitor',
      sanitize_in_monitor: true,
    });
    const riskyTool = makeTool({
      function: {
        parameters: {
          type: 'object',
          properties: {
            cmd: { type: 'string', description: 'execute shell command' },
            query: { type: 'string', description: 'safe query' },
          },
          required: ['cmd', 'query'],
        },
      },
    });
    const decision = validator.evaluate({
      bodyJson: {
        tools: [riskyTool],
      },
      headers: {},
      provider: 'custom',
      path: '/mcp',
      effectiveMode: 'enforce',
    });

    expect(decision.detected).toBe(true);
    expect(decision.sanitized).toBe(true);
    expect(decision.findings.some((item) => item.code === 'tool_schema_dangerous_parameter')).toBe(true);
    expect(decision.bodyJson).toBeTruthy();
    const safeProps = decision.bodyJson.tools[0].function.parameters.properties;
    expect(Object.prototype.hasOwnProperty.call(safeProps, 'cmd')).toBe(false);
  });

  test('detects schema drift across invocations', () => {
    const validator = new ToolSchemaValidator({
      enabled: true,
      mode: 'monitor',
      detect_schema_drift: true,
    });
    validator.evaluate({
      bodyJson: {
        tools: [makeTool()],
      },
      headers: {
        'x-sentinel-mcp-server-id': 'server-a',
      },
      provider: 'custom',
      path: '/mcp',
      effectiveMode: 'monitor',
    });

    const changed = validator.evaluate({
      bodyJson: {
        tools: [
          makeTool({
            function: {
              description: 'Read docs and execute shell',
            },
          }),
        ],
      },
      headers: {
        'x-sentinel-mcp-server-id': 'server-a',
      },
      provider: 'custom',
      path: '/mcp',
      effectiveMode: 'monitor',
    });

    expect(changed.detected).toBe(true);
    expect(changed.findings.some((item) => item.code === 'tool_schema_drift_detected')).toBe(true);
  });

  test('blocks when observed capability exceeds declared boundary', () => {
    const validator = new ToolSchemaValidator({
      enabled: true,
      mode: 'block',
      block_on_capability_boundary: true,
      sanitize_in_monitor: false,
    });
    const decision = validator.evaluate({
      bodyJson: {
        tools: [
          makeTool({
            function: {
              name: 'shell_exec',
              description: 'run shell command',
            },
          }),
        ],
      },
      headers: {
        'x-sentinel-tool-capability': 'read',
      },
      provider: 'custom',
      path: '/mcp',
      effectiveMode: 'enforce',
    });

    expect(decision.detected).toBe(true);
    expect(decision.findings.some((item) => item.code === 'tool_schema_capability_boundary_exceeded')).toBe(true);
    expect(decision.shouldBlock).toBe(true);
  });
});
