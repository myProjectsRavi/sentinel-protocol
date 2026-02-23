const { MCPShadowDetector } = require('../../src/security/mcp-shadow-detector');

function buildTool(name, description = 'search internal docs', parameters = { query: { type: 'string' } }) {
  return {
    type: 'function',
    function: {
      name,
      description,
      parameters: {
        type: 'object',
        properties: parameters,
        required: Object.keys(parameters),
      },
    },
  };
}

describe('MCPShadowDetector', () => {
  test('returns clean decision for stable MCP tool snapshot', () => {
    const detector = new MCPShadowDetector({
      enabled: true,
      mode: 'monitor',
    });

    const decision = detector.inspect({
      bodyJson: { tools: [buildTool('search_docs')] },
      serverId: 'mcp-a',
      serverConfig: { version: 1 },
      effectiveMode: 'enforce',
    });

    expect(decision.detected).toBe(false);
    expect(decision.shouldBlock).toBe(false);
    expect(decision.reason).toBe('clean');
  });

  test('detects schema drift for same server/tool name', () => {
    const detector = new MCPShadowDetector({
      enabled: true,
      mode: 'monitor',
      detect_schema_drift: true,
    });

    detector.inspect({
      bodyJson: { tools: [buildTool('search_docs')] },
      serverId: 'mcp-schema',
      serverConfig: { version: 1 },
      effectiveMode: 'enforce',
    });

    const drift = detector.inspect({
      bodyJson: { tools: [buildTool('search_docs', 'search internal docs', { query: { type: 'array' } })] },
      serverId: 'mcp-schema',
      serverConfig: { version: 1 },
      effectiveMode: 'enforce',
    });

    expect(drift.detected).toBe(true);
    expect(drift.findings.some((finding) => finding.code === 'mcp_shadow_schema_drift')).toBe(true);
    expect(drift.reason).toBe('mcp_shadow_schema_drift');
  });

  test('detects late registration after baseline snapshot', () => {
    const detector = new MCPShadowDetector({
      enabled: true,
      mode: 'monitor',
      detect_late_registration: true,
    });

    detector.inspect({
      bodyJson: { tools: [buildTool('search_docs')] },
      serverId: 'mcp-late',
      serverConfig: { version: 1 },
      effectiveMode: 'enforce',
    });

    const late = detector.inspect({
      bodyJson: { tools: [buildTool('search_docs'), buildTool('export_users')] },
      serverId: 'mcp-late',
      serverConfig: { version: 1 },
      effectiveMode: 'enforce',
    });

    expect(late.detected).toBe(true);
    expect(late.findings.some((finding) => finding.code === 'mcp_shadow_late_registration')).toBe(true);
    expect(late.reason).toBe('mcp_shadow_late_registration');
  });

  test('detects near-name collision across MCP servers', () => {
    const detector = new MCPShadowDetector({
      enabled: true,
      mode: 'monitor',
      detect_name_collisions: true,
      name_similarity_distance: 1,
    });

    detector.inspect({
      bodyJson: { tools: [buildTool('search_docs')] },
      serverId: 'mcp-primary',
      serverConfig: { version: 1 },
      effectiveMode: 'enforce',
    });

    const collision = detector.inspect({
      bodyJson: { tools: [buildTool('search_docz')] },
      serverId: 'mcp-secondary',
      serverConfig: { version: 1 },
      effectiveMode: 'enforce',
    });

    expect(collision.detected).toBe(true);
    expect(collision.findings.some((finding) => finding.code === 'mcp_shadow_name_collision_fuzzy')).toBe(true);
    expect(collision.reason).toBe('mcp_shadow_name_collision');
  });

  test('enforce mode blocks when detector mode is block and collision is block-eligible', () => {
    const detector = new MCPShadowDetector({
      enabled: true,
      mode: 'block',
      detect_name_collisions: true,
      block_on_name_collision: true,
      name_similarity_distance: 1,
    });

    detector.inspect({
      bodyJson: { tools: [buildTool('search_docs')] },
      serverId: 'mcp-block-a',
      effectiveMode: 'enforce',
    });

    const blocked = detector.inspect({
      bodyJson: { tools: [buildTool('search_docs')] },
      serverId: 'mcp-block-b',
      effectiveMode: 'enforce',
    });

    expect(blocked.detected).toBe(true);
    expect(blocked.shouldBlock).toBe(true);
    expect(blocked.reason).toBe('mcp_shadow_name_collision');
  });

  test('prunes stale server entries by ttl and max entries', () => {
    const detector = new MCPShadowDetector({
      enabled: true,
      mode: 'monitor',
      ttl_ms: 1000,
      max_server_entries: 32,
      detect_name_collisions: false,
    });
    detector.inspect({
      bodyJson: { tools: [buildTool('search_docs')] },
      serverId: 'mcp-old-a',
      effectiveMode: 'monitor',
    });
    detector.inspect({
      bodyJson: { tools: [buildTool('export_data')] },
      serverId: 'mcp-old-b',
      effectiveMode: 'monitor',
    });
    for (const entry of detector.serverSnapshots.values()) {
      entry.updatedAt = 0;
    }
    detector.prune(5000);
    const fresh = detector.inspect({
      bodyJson: { tools: [buildTool('query_kb')] },
      serverId: 'mcp-fresh',
      effectiveMode: 'monitor',
    });

    expect(fresh.registry_size).toBe(1);
    expect(fresh.detected).toBe(false);
  });
});
