const readline = require('readline');
const util = require('util');

const { PIIScanner } = require('../engines/pii-scanner');
const { PolicyEngine } = require('../engines/policy-engine');
const { InMemoryRateLimiter } = require('../engines/rate-limiter');
const { NeuralInjectionClassifier } = require('../engines/neural-injection-classifier');
const { mergeInjectionResults } = require('../engines/injection-merge');
const { PIIProviderEngine } = require('../pii/provider-engine');
const { resolveProvider } = require('../upstream/router');
const { MCPPoisoningDetector } = require('../security/mcp-poisoning-detector');
const { MCPShadowDetector } = require('../security/mcp-shadow-detector');

function safeParseJson(input) {
  try {
    return JSON.parse(input);
  } catch {
    return null;
  }
}

function flattenFindings(findings) {
  return Array.from(new Set((findings || []).map((item) => item.id))).sort();
}

function highestSeverity(findings) {
  const rank = { low: 1, medium: 2, high: 3, critical: 4 };
  let out = null;
  for (const finding of findings || []) {
    if (!out || rank[finding.severity] > rank[out]) {
      out = finding.severity;
    }
  }
  return out;
}

class SentinelMCPGovernance {
  constructor(config) {
    this.config = config;
    this.rateLimiter = new InMemoryRateLimiter(config.runtime?.rate_limiter || {});
    this.policyEngine = new PolicyEngine(config, this.rateLimiter);
    this.neuralInjectionClassifier = new NeuralInjectionClassifier(config.injection?.neural || {});
    this.piiScanner = new PIIScanner({
      maxScanBytes: config.pii.max_scan_bytes,
      regexSafetyCapBytes: config.pii.regex_safety_cap_bytes,
    });
    this.piiProviderEngine = new PIIProviderEngine({
      piiConfig: config.pii,
      localScanner: this.piiScanner,
      telemetry: null,
    });
    this.mcpPoisoningDetector = new MCPPoisoningDetector(config.runtime?.mcp_poisoning || {});
    this.mcpShadowDetector = new MCPShadowDetector(config.runtime?.mcp_shadow || {});
  }

  async inspectRequest(args = {}) {
    const method = String(args.method || 'POST').toUpperCase();
    const pathname = String(args.path || '/v1/chat/completions');
    const headers = args.headers && typeof args.headers === 'object' && !Array.isArray(args.headers) ? args.headers : {};
    const providerName = String(args.provider || headers['x-sentinel-target'] || 'openai').toLowerCase();
    const customUrl = args.custom_url || headers['x-sentinel-custom-url'];
    const mode = this.config.mode || 'monitor';

    const resolved = await resolveProvider(
      {
        headers: {
          'x-sentinel-target': providerName,
          ...(customUrl ? { 'x-sentinel-custom-url': customUrl } : {}),
        },
      },
      this.config
    );

    let bodyText;
    let bodyJson;
    if (typeof args.body === 'string') {
      bodyText = args.body;
      bodyJson = safeParseJson(bodyText);
    } else {
      bodyJson = args.body && typeof args.body === 'object' ? args.body : {};
      bodyText = JSON.stringify(bodyJson);
    }

    let injectionResult = this.policyEngine.scanInjection(bodyText || '');
    if (this.neuralInjectionClassifier.enabled && bodyText) {
      const neural = await this.neuralInjectionClassifier.classify(bodyText, {
        maxScanBytes: this.config.injection?.neural?.max_scan_bytes,
        timeoutMs: this.config.injection?.neural?.timeout_ms,
      });
      injectionResult = mergeInjectionResults(injectionResult, neural, this.config.injection?.neural || {});
    }

    const mcpDecision = this.mcpPoisoningDetector.inspect({
      bodyJson,
      toolArgs: args.tool_arguments || args.arguments || {},
      serverId: args.server_id || headers['x-sentinel-mcp-server-id'] || providerName,
      serverConfig: args.mcp_server_config || null,
      effectiveMode: mode,
    });
    const mcpShadowDecision = this.mcpShadowDetector.inspect({
      bodyJson,
      serverId: args.server_id || headers['x-sentinel-mcp-server-id'] || providerName,
      serverConfig: {
        ...(args.mcp_server_config && typeof args.mcp_server_config === 'object' ? args.mcp_server_config : {}),
        phase: args.mcp_phase || headers['x-sentinel-mcp-phase'] || 'request',
      },
      effectiveMode: mode,
    });

    const policyDecision = this.policyEngine.check({
      method,
      hostname: resolved.upstreamHostname || new URL(resolved.baseUrl).hostname,
      pathname,
      bodyText,
      bodyJson,
      requestBytes: Buffer.byteLength(bodyText, 'utf8'),
      headers,
      provider: resolved.provider,
      rateLimitKey: headers['x-sentinel-agent-id'],
      clientIp: args.client_ip || headers['x-forwarded-for'] || headers['x-real-ip'],
      injectionResult,
    });

    const warnings = [];
    const reasons = [];
    let blocked = false;

    if (mcpDecision.detected) {
      warnings.push(`mcp_poisoning:${mcpDecision.reason || 'detected'}`);
      reasons.push(mcpDecision.reason || 'mcp_poisoning_detected');
      if (mcpDecision.shouldBlock) {
        blocked = true;
      }
    }
    if (mcpShadowDecision.detected) {
      warnings.push(`mcp_shadow:${mcpShadowDecision.reason || 'detected'}`);
      reasons.push(mcpShadowDecision.reason || 'mcp_shadow_detected');
      if (mcpShadowDecision.shouldBlock) {
        blocked = true;
      }
    }

    if (policyDecision.matched) {
      warnings.push(`policy:${policyDecision.rule || 'matched'}`);
      reasons.push(policyDecision.reason || 'policy_match');
      if (policyDecision.action === 'block' && mode === 'enforce') {
        blocked = true;
      }
    }

    let piiTypes = [];
    let piiSeverity = null;
    let piiProvider = 'local';
    let piiRedactions = 0;

    if (this.config.pii.enabled !== false) {
      const piiEvaluation = await this.piiProviderEngine.scan(bodyText, headers);
      piiProvider = piiEvaluation.meta.providerUsed;
      if (piiEvaluation.meta.fallbackUsed) {
        warnings.push(`pii_fallback:${piiEvaluation.meta.fallbackReason}`);
      }

      const piiResult = piiEvaluation.result;
      if (piiResult.findings.length > 0) {
        piiTypes = flattenFindings(piiResult.findings);
        piiSeverity = highestSeverity(piiResult.findings);
        piiRedactions = piiResult.findings.length;
        const action = this.config.pii.severity_actions[piiSeverity] || 'log';
        reasons.push(`pii:${piiSeverity}`);
        if (action === 'block' && mode === 'enforce') {
          blocked = true;
        }
      }
    }

    const output = {
      allowed: !blocked,
      decision: blocked ? 'block' : 'allow',
      mode,
      reasons,
      warnings,
      provider: resolved.provider,
      policy: {
        matched: policyDecision.matched,
        action: policyDecision.action,
        reason: policyDecision.reason,
        rule: policyDecision.rule || null,
        injection_score: policyDecision.injection?.score || 0,
        injection_signals: (policyDecision.injection?.matchedSignals || []).map((signal) => signal.id),
      },
      mcp: {
        enabled: mcpDecision.enabled,
        detected: mcpDecision.detected,
        should_block: mcpDecision.shouldBlock,
        reason: mcpDecision.reason || 'clean',
        findings: mcpDecision.findings || [],
        drifted: mcpDecision.drift?.drifted === true,
        sanitized_arguments_changed: Boolean(
          args.tool_arguments
            && JSON.stringify(mcpDecision.sanitizedArguments || {}) !== JSON.stringify(args.tool_arguments || {})
        ),
        shadow: {
          enabled: mcpShadowDecision.enabled,
          detected: mcpShadowDecision.detected,
          should_block: mcpShadowDecision.shouldBlock,
          reason: mcpShadowDecision.reason || 'clean',
          findings: mcpShadowDecision.findings || [],
          technique_id: mcpShadowDecision.technique_id || null,
        },
      },
      pii: {
        provider: piiProvider,
        highest_severity: piiSeverity,
        types: piiTypes,
        findings: piiRedactions,
      },
    };

    return output;
  }
}

class SentinelMCPServer {
  constructor(config, io = {}) {
    this.config = config;
    this.input = io.input || process.stdin;
    this.output = io.output || process.stdout;
    this.governance = null;
    this.rl = null;
    this.allowStdoutWrite = false;
    this.restoreIoGuards = null;
  }

  send(message) {
    const payload = `${JSON.stringify(message)}\n`;
    if (this.output === process.stdout && this.restoreIoGuards) {
      this.allowStdoutWrite = true;
      try {
        process.stdout.write(payload);
      } finally {
        this.allowStdoutWrite = false;
      }
      return;
    }
    this.output.write(payload);
  }

  enableStdioGuards() {
    if (this.output !== process.stdout || this.restoreIoGuards) {
      return;
    }

    const original = {
      log: console.log,
      info: console.info,
      warn: console.warn,
      debug: console.debug,
      stdoutWrite: process.stdout.write,
    };

    const writeStderr = (...args) => {
      const line = util.format(...args);
      process.stderr.write(`${line}\n`);
    };

    console.log = (...args) => writeStderr(...args);
    console.info = (...args) => writeStderr(...args);
    console.warn = (...args) => writeStderr(...args);
    console.debug = (...args) => writeStderr(...args);

    process.stdout.write = (...args) => {
      if (this.allowStdoutWrite) {
        return original.stdoutWrite.apply(process.stdout, args);
      }
      return process.stderr.write.apply(process.stderr, args);
    };

    this.restoreIoGuards = () => {
      console.log = original.log;
      console.info = original.info;
      console.warn = original.warn;
      console.debug = original.debug;
      process.stdout.write = original.stdoutWrite;
    };
  }

  sendError(id, code, message) {
    this.send({
      jsonrpc: '2.0',
      id: id ?? null,
      error: {
        code,
        message,
      },
    });
  }

  async handleRequest(request) {
    if (!request || request.jsonrpc !== '2.0' || typeof request.method !== 'string') {
      this.sendError(request?.id, -32600, 'Invalid Request');
      return;
    }

    if (request.method === 'initialize') {
      this.send({
        jsonrpc: '2.0',
        id: request.id ?? null,
        result: {
          protocolVersion: '2025-01-01',
          serverInfo: {
            name: 'sentinel-protocol',
            version: '1.0.0',
          },
          capabilities: {
            tools: {
              listChanged: false,
            },
          },
        },
      });
      return;
    }

    if (request.method === 'tools/list') {
      this.send({
        jsonrpc: '2.0',
        id: request.id ?? null,
        result: {
          tools: [
            {
              name: 'sentinel.inspect_request',
              description: 'Runs Sentinel governance checks (policy, injection, pii) without executing upstream calls.',
              inputSchema: {
                type: 'object',
                properties: {
                  method: { type: 'string' },
                  path: { type: 'string' },
                  provider: { type: 'string' },
                  custom_url: { type: 'string' },
                  headers: { type: 'object' },
                  body: {},
                },
              },
            },
          ],
        },
      });
      return;
    }

    if (request.method === 'tools/call') {
      const params = request.params || {};
      if (params.name !== 'sentinel.inspect_request') {
        this.sendError(request.id, -32602, `Unsupported tool: ${params.name}`);
        return;
      }
      try {
        const result = await this.governance.inspectRequest(params.arguments || {});
        this.send({
          jsonrpc: '2.0',
          id: request.id ?? null,
          result: {
            content: [
              {
                type: 'text',
                text: JSON.stringify(result, null, 2),
              },
            ],
            structuredContent: result,
          },
        });
      } catch (error) {
        this.sendError(request.id, -32000, error.message);
      }
      return;
    }

    if (request.method === 'ping') {
      this.send({
        jsonrpc: '2.0',
        id: request.id ?? null,
        result: {
          ok: true,
          timestamp: new Date().toISOString(),
        },
      });
      return;
    }

    this.sendError(request.id, -32601, `Method not found: ${request.method}`);
  }

  start() {
    this.enableStdioGuards();
    this.governance = new SentinelMCPGovernance(this.config);
    this.rl = readline.createInterface({
      input: this.input,
      crlfDelay: Infinity,
    });

    this.rl.on('line', async (line) => {
      const trimmed = String(line || '').trim();
      if (!trimmed) {
        return;
      }
      const request = safeParseJson(trimmed);
      if (!request) {
        this.sendError(null, -32700, 'Parse error');
        return;
      }
      await this.handleRequest(request);
    });

    this.rl.on('close', () => {
      if (this.restoreIoGuards) {
        this.restoreIoGuards();
        this.restoreIoGuards = null;
      }
    });
  }
}

function startMCPServer(config, io) {
  const server = new SentinelMCPServer(config, io);
  server.start();
  return server;
}

module.exports = {
  SentinelMCPGovernance,
  SentinelMCPServer,
  startMCPServer,
};
