#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');
const { Command } = require('commander');
const { createInterface } = require('node:readline/promises');

const { ensureDefaultConfigExists, loadAndValidateConfig, readYamlConfig, writeYamlConfig } = require('../src/config/loader');
const { PROFILE_NAMES, applyConfigProfile } = require('../src/config/profiles');
const { migrateConfig } = require('../src/config/migrations');
const { ConfigValidationError } = require('../src/config/schema');
const { SemanticScanner } = require('../src/engines/semantic-scanner');
const { PolicyBundle } = require('../src/governance/policy-bundle');
const { RedTeamEngine } = require('../src/governance/red-team');
const { renderRedTeamHtmlReport } = require('../src/governance/red-team-html-report');
const { ComplianceEngine } = require('../src/governance/compliance-engine');
const { EvidenceVault } = require('../src/governance/evidence-vault');
const { ThreatPropagationGraph } = require('../src/governance/threat-propagation-graph');
const { AttackCorpusEvolver } = require('../src/governance/attack-corpus-evolver');
const { ForensicDebugger } = require('../src/governance/forensic-debugger');
const { PolicyGradientAnalyzer } = require('../src/governance/policy-gradient-analyzer');
const { AtlasTracker } = require('../src/governance/atlas-tracker');
const { AIBOMGenerator } = require('../src/governance/aibom-generator');
const { CapabilityIntrospection } = require('../src/governance/capability-introspection');
const { computeSecurityPosture } = require('../src/governance/security-posture');
const {
  generateOWASPComplianceReport,
  renderOWASPLLMHtmlReport,
} = require('../src/governance/owasp-compliance-mapper');
const { DifferentialPrivacyEngine } = require('../src/privacy/differential-privacy');
const { startMCPServer } = require('../src/mcp/server');
const { startMonitorTUI } = require('../src/monitor/tui');
const { validateConfigShape } = require('../src/config/schema');
const { StatusStore } = require('../src/status/store');
const {
  detectFramework,
  normalizeFramework,
  normalizeProviders,
  injectProviderTargets,
  frameworkSnippet,
  appendGeneratedHints,
  detectOllamaAvailable,
} = require('../src/cli/adoption');
const {
  startServer,
  stopServer,
  statusServer,
  setEmergencyOpen,
  doctorServer,
} = require('../src');
const { DEFAULT_CONFIG_PATH, AUDIT_LOG_PATH, STATUS_FILE_PATH } = require('../src/utils/paths');

const program = new Command();

program.name('sentinel').description('Sentinel Protocol CLI').version('1.0.0');

function loadAuditEvents(auditPath, limit) {
  const compliance = new ComplianceEngine({
    auditPath,
  });
  const normalizedLimit = Number.isFinite(Number(limit)) && Number(limit) > 0 ? Math.floor(Number(limit)) : 200000;
  return compliance.loadEventsWithMeta({ limit: normalizedLimit });
}

function emitOutput(payload, outPath) {
  if (outPath) {
    const absolute = path.resolve(outPath);
    fs.writeFileSync(absolute, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
    return absolute;
  }
  console.log(JSON.stringify(payload, null, 2));
  return null;
}

function isInteractiveTerminal() {
  return process.stdin.isTTY === true && process.stdout.isTTY === true;
}

function envVarForProvider(provider) {
  if (provider === 'anthropic') {
    return 'SENTINEL_ANTHROPIC_API_KEY';
  }
  if (provider === 'google') {
    return 'SENTINEL_GOOGLE_API_KEY';
  }
  if (provider === 'ollama') {
    return null;
  }
  return 'SENTINEL_OPENAI_API_KEY';
}

function emitProviderEnvWarnings(providers) {
  const uniqueProviders = normalizeProviders(providers);
  for (const provider of uniqueProviders) {
    const envVar = envVarForProvider(provider);
    if (!envVar) {
      continue;
    }
    if (!process.env[envVar]) {
      console.log(`[WARN] Provider ${provider} selected but ${envVar} is not set.`);
    }
  }
}

function parseProfileChoice(input, fallback = 'minimal') {
  const normalized = String(input || '').trim().toLowerCase();
  if (!normalized) {
    return fallback;
  }
  if (normalized === '1' || normalized === 'minimal') {
    return 'minimal';
  }
  if (normalized === '2' || normalized === 'standard') {
    return 'standard';
  }
  if (normalized === '3' || normalized === 'paranoid') {
    return 'paranoid';
  }
  return fallback;
}

function parseFrameworkChoice(input, fallback = 'none') {
  const normalized = String(input || '').trim().toLowerCase();
  if (!normalized) {
    return fallback;
  }
  const frameworkChoices = ['express', 'fastify', 'nextjs', 'koa', 'hono', 'nestjs', 'none'];
  if (/^[1-7]$/.test(normalized)) {
    return frameworkChoices[Number(normalized) - 1];
  }
  return normalizeFramework(normalized) || fallback;
}

async function runInitWizard({ detectedFramework, defaultProfile = 'minimal' }) {
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  try {
    const providersRaw = await rl.question(
      'Provider(s) [openai,anthropic,google,ollama] (comma list, default: openai): '
    );
    const providers = normalizeProviders(providersRaw || 'openai');
    const frameworkRaw = await rl.question(
      `Framework [express|fastify|nextjs|koa|hono|nestjs|none] (default: ${detectedFramework || 'none'}): `
    );
    const framework = parseFrameworkChoice(frameworkRaw, detectedFramework || 'none');
    const profileRaw = await rl.question(
      `Security level [1=minimal,2=standard,3=paranoid] (default: ${defaultProfile}): `
    );
    const profile = parseProfileChoice(profileRaw, defaultProfile);
    return {
      providers,
      framework,
      profile,
    };
  } finally {
    rl.close();
  }
}

function printFrameworkGuidance(framework) {
  const normalized = normalizeFramework(framework);
  if (!normalized || normalized === 'none') {
    return;
  }
  console.log(`Detected framework: ${normalized}`);
  console.log('Framework quick-start snippet:');
  console.log(frameworkSnippet(normalized));
}

async function printAutoRuntimeHints(framework) {
  printFrameworkGuidance(framework);
  const ollamaDetected = await detectOllamaAvailable({
    timeoutMs: 500,
  });
  if (ollamaDetected) {
    console.log('Ollama detected at http://127.0.0.1:11434 (automatic local provider route available).');
  }
}

program
  .command('init')
  .description('Create default sentinel.yaml in ~/.sentinel')
  .option('--config <path>', 'Config path', DEFAULT_CONFIG_PATH)
  .option('--force', 'Overwrite existing config')
  .option('--profile <name>', 'Config profile: minimal|standard|paranoid')
  .option('--providers <list>', 'Comma-separated providers: openai,anthropic,google,ollama')
  .option('--framework <name>', 'express|fastify|nextjs|koa|hono|nestjs|none')
  .option('--yes', 'Disable interactive prompts (CI-safe)')
  .action(async (options) => {
    try {
      const configPath = options.config || DEFAULT_CONFIG_PATH;
      const result = ensureDefaultConfigExists(configPath, Boolean(options.force));
      const hasExplicitOverrides = Boolean(options.profile || options.providers || options.framework);
      if (!result.created && !options.force && !hasExplicitOverrides) {
        console.log(`Config already exists: ${result.path}`);
        return;
      }

      const detectedFramework = detectFramework(process.cwd()) || 'none';
      let selectedProfile = String(options.profile || '').trim().toLowerCase();
      let selectedProviders = normalizeProviders(options.providers || 'openai');
      let selectedFramework = parseFrameworkChoice(options.framework, detectedFramework);

      if (!selectedProfile && isInteractiveTerminal() && options.yes !== true) {
        const wizard = await runInitWizard({
          detectedFramework,
          defaultProfile: 'minimal',
        });
        selectedProfile = wizard.profile;
        selectedProviders = wizard.providers;
        selectedFramework = wizard.framework;
      }

      if (!selectedProfile) {
        selectedProfile = 'minimal';
      }
      if (!PROFILE_NAMES.has(selectedProfile)) {
        throw new Error(`Invalid --profile value "${selectedProfile}". Use minimal|standard|paranoid.`);
      }

      const parsed = readYamlConfig(result.path);
      const profiled = applyConfigProfile(parsed, selectedProfile);
      const providerScoped = injectProviderTargets(profiled.config, selectedProviders);
      validateConfigShape(providerScoped);
      writeYamlConfig(result.path, providerScoped);
      appendGeneratedHints(result.path, {
        framework: selectedFramework,
        providers: selectedProviders,
      });

      console.log(result.created ? `Created config: ${result.path}` : `Updated config: ${result.path}`);
      console.log(
        `Applied profile: ${profiled.profile} (${profiled.enabledRuntimeEngines}/${profiled.totalRuntimeEngines} runtime engines enabled)`
      );
      console.log(`Providers configured: ${selectedProviders.join(', ')}`);

      const doctor = doctorServer({ configPath: result.path });
      const summary = doctor.report.summary;
      console.log(`Doctor summary: pass=${summary.pass} warn=${summary.warn} fail=${summary.fail}`);
      for (const check of doctor.report.checks) {
        if (check.status === 'warn') {
          console.log(`[WARN] ${check.id}: ${check.message}`);
        }
      }
      emitProviderEnvWarnings(selectedProviders);
      printFrameworkGuidance(selectedFramework);
    } catch (error) {
      console.error(error.message);
      process.exitCode = 1;
    }
  });

program
  .command('start')
  .description('Start Sentinel server')
  .option('--config <path>', 'Config path', DEFAULT_CONFIG_PATH)
  .option('--port <port>', 'Port override')
  .option('--mode <mode>', 'Mode override (monitor|warn|enforce)')
  .option('--dry-run', 'Force monitor behavior')
  .option('--fail-open', 'Degrade blocking decisions to pass-through monitor mode')
  .option('--record', 'Enable VCR record mode (writes deterministic tape)')
  .option('--replay', 'Enable VCR replay mode (reads deterministic tape)')
  .option('--dashboard', 'Enable local dashboard server for this run')
  .option('--profile <name>', 'Runtime profile: minimal|standard|paranoid')
  .option('--auto', 'Auto-detect framework and print wiring snippet')
  .option('--shutdown-timeout-ms <ms>', 'Forced shutdown timeout in milliseconds', '15000')
  .option('--skip-doctor', 'Skip startup doctor checks (not recommended)')
  .action(async (options) => {
    try {
      if (options.record && options.replay) {
        throw new Error('Choose either --record or --replay, not both.');
      }
      const vcrMode = options.record ? 'record' : options.replay ? 'replay' : undefined;
      const shutdownTimeoutMs = Number(options.shutdownTimeoutMs);
      const result = startServer({
        configPath: options.config,
        port: options.port,
        modeOverride: options.mode,
        vcrMode,
        dashboardEnabled: options.dashboard === true ? true : undefined,
        profile: options.profile,
        dryRun: options.dryRun,
        failOpen: options.failOpen,
        shutdownTimeoutMs: Number.isFinite(shutdownTimeoutMs) && shutdownTimeoutMs > 0 ? shutdownTimeoutMs : 15000,
        runDoctor: !options.skipDoctor,
      });

      if (result.loaded.migration.migrated) {
        console.log(`Config migrated from v${result.loaded.migration.fromVersion} to v${result.loaded.migration.toVersion}`);
        if (result.loaded.backupPath) {
          console.log(`Backup written to: ${result.loaded.backupPath}`);
        }
      }

      if (result.doctor) {
        const summary = result.doctor.summary;
        console.log(`Doctor summary: pass=${summary.pass} warn=${summary.warn} fail=${summary.fail}`);
        for (const check of result.doctor.checks) {
          if (check.status === 'warn') {
            console.log(`[WARN] ${check.id}: ${check.message}`);
          }
        }
      }
      if (result.loaded?.profile?.name) {
        console.log(
          `Profile loaded: ${result.loaded.profile.name} (${result.loaded.profile.enabledRuntimeEngines}/${result.loaded.profile.totalRuntimeEngines} runtime engines enabled)`
        );
      }
      if (options.auto === true) {
        await printAutoRuntimeHints(detectFramework(process.cwd()) || 'none');
      }
    } catch (error) {
      console.error(error.message);
      process.exitCode = 1;
    }
  });

program
  .command('watch')
  .description('Passive monitor-first proxy mode with live dashboard and framework wiring hints')
  .option('--config <path>', 'Config path', DEFAULT_CONFIG_PATH)
  .option('--port <port>', 'Port override')
  .option('--profile <name>', 'Runtime profile: minimal|standard|paranoid', 'minimal')
  .option('--shutdown-timeout-ms <ms>', 'Forced shutdown timeout in milliseconds', '15000')
  .option('--skip-doctor', 'Skip startup doctor checks (not recommended)')
  .action(async (options) => {
    try {
      const configPath = options.config || DEFAULT_CONFIG_PATH;
      const initResult = ensureDefaultConfigExists(configPath, false);
      const shutdownTimeoutMs = Number(options.shutdownTimeoutMs);
      const result = startServer({
        configPath,
        port: options.port,
        modeOverride: 'monitor',
        dashboardEnabled: true,
        profile: options.profile,
        shutdownTimeoutMs: Number.isFinite(shutdownTimeoutMs) && shutdownTimeoutMs > 0 ? shutdownTimeoutMs : 15000,
        runDoctor: !options.skipDoctor,
      });

      console.log(initResult.created ? `Created config: ${configPath}` : `Using config: ${configPath}`);
      console.log('Watch mode active: monitor-first passive proxy with dashboard enabled.');
      console.log('Set provider SDK baseURL to http://127.0.0.1:8787/v1 and header x-sentinel-target=<provider>.');
      console.log('Dashboard: http://127.0.0.1:8788');

      if (result.doctor) {
        const summary = result.doctor.summary;
        console.log(`Doctor summary: pass=${summary.pass} warn=${summary.warn} fail=${summary.fail}`);
      }
      if (result.loaded?.profile?.name) {
        console.log(
          `Profile loaded: ${result.loaded.profile.name} (${result.loaded.profile.enabledRuntimeEngines}/${result.loaded.profile.totalRuntimeEngines} runtime engines enabled)`
        );
      }

      await printAutoRuntimeHints(detectFramework(process.cwd()) || 'none');
    } catch (error) {
      console.error(error.message);
      process.exitCode = 1;
    }
  });

program
  .command('bootstrap')
  .description('Initialize config, run doctor checks, and start Sentinel (one-command path)')
  .option('--config <path>', 'Config path', DEFAULT_CONFIG_PATH)
  .option('--force', 'Overwrite existing config')
  .option('--profile <name>', 'Profile to apply on bootstrap: minimal|standard|paranoid', 'minimal')
  .option('--port <port>', 'Port override')
  .option('--mode <mode>', 'Mode override (monitor|warn|enforce)')
  .option('--dashboard', 'Enable local dashboard server for this run')
  .option('--auto', 'Auto-detect framework and print wiring snippet')
  .option('--shutdown-timeout-ms <ms>', 'Forced shutdown timeout in milliseconds', '15000')
  .action(async (options) => {
    try {
      const bootstrapPath = options.config || DEFAULT_CONFIG_PATH;
      const initResult = ensureDefaultConfigExists(bootstrapPath, Boolean(options.force));
      const profileName = String(options.profile || 'minimal').toLowerCase();
      if (!PROFILE_NAMES.has(profileName)) {
        throw new Error(`Invalid --profile value "${options.profile}". Use minimal|standard|paranoid.`);
      }
      const parsed = readYamlConfig(bootstrapPath);
      const normalized = validateConfigShape(parsed);
      const profiled = applyConfigProfile(normalized, profileName);
      writeYamlConfig(bootstrapPath, profiled.config);
      const shutdownTimeoutMs = Number(options.shutdownTimeoutMs);
      const startResult = startServer({
        configPath: bootstrapPath,
        port: options.port,
        modeOverride: options.mode,
        dashboardEnabled: options.dashboard === true ? true : undefined,
        profile: profileName,
        shutdownTimeoutMs: Number.isFinite(shutdownTimeoutMs) && shutdownTimeoutMs > 0 ? shutdownTimeoutMs : 15000,
        runDoctor: true,
      });

      console.log(initResult.created ? `Created config: ${bootstrapPath}` : `Using config: ${bootstrapPath}`);
      console.log(
        `Bootstrap profile: ${profiled.profile} (${profiled.enabledRuntimeEngines}/${profiled.totalRuntimeEngines} runtime engines enabled)`
      );
      const framework = detectFramework(process.cwd());
      if (framework || options.auto === true) {
        await printAutoRuntimeHints(framework || 'none');
      }
      if (startResult.doctor) {
        const summary = startResult.doctor.summary;
        console.log(`Doctor summary: pass=${summary.pass} warn=${summary.warn} fail=${summary.fail}`);
      }
    } catch (error) {
      console.error(error.message);
      process.exitCode = 1;
    }
  });

program
  .command('mcp')
  .description('Run Sentinel as a minimal MCP server over stdio')
  .option('--config <path>', 'Config path', DEFAULT_CONFIG_PATH)
  .action((options) => {
    try {
      const loaded = loadAndValidateConfig({
        configPath: options.config,
        allowMigration: true,
        writeMigrated: true,
      });

      startMCPServer(loaded.config);
      console.error('Sentinel MCP server started on stdio');
    } catch (error) {
      console.error(error.message);
      process.exitCode = 1;
    }
  });

program
  .command('monitor')
  .description('Open a real-time terminal dashboard (requests/sec, blocked%, pii types, last requests)')
  .option('--refresh-ms <ms>', 'Refresh interval in milliseconds', '1000')
  .action((options) => {
    const refreshMs = Number(options.refreshMs);
    startMonitorTUI({
      refreshMs: Number.isFinite(refreshMs) && refreshMs > 100 ? refreshMs : 1000,
    });
  });

program
  .command('stop')
  .description('Stop Sentinel server using PID file')
  .action(() => {
    const result = stopServer();
    if (!result.stopped) {
      console.error(result.message);
      process.exitCode = 1;
      return;
    }
    console.log(`Stopped Sentinel (pid ${result.pid})`);
  });

program
  .command('status')
  .description('Print server status')
  .option('--json', 'Output JSON')
  .action((options) => {
    const output = statusServer(Boolean(options.json));
    if (options.json) {
      console.log(JSON.stringify(output, null, 2));
      return;
    }
    console.log(output);
  });

program
  .command('doctor')
  .description('Run startup readiness checks (RapidAPI key/config/fallback)')
  .option('--config <path>', 'Config path', DEFAULT_CONFIG_PATH)
  .option('--json', 'Output JSON')
  .action((options) => {
    try {
      const result = doctorServer({ configPath: options.config });
      if (options.json) {
        console.log(JSON.stringify(result.report, null, 2));
      } else {
        console.log(result.formatted);
      }
      if (!result.report.ok) {
        process.exitCode = 1;
      }
    } catch (error) {
      console.error(error.message);
      process.exitCode = 1;
    }
  });

program
  .command('posture')
  .description('Compute deterministic security posture score from config, counters, and optional audit summary')
  .option('--config <path>', 'Config path', DEFAULT_CONFIG_PATH)
  .option('--audit-path <path>', 'Audit log path', AUDIT_LOG_PATH)
  .option('--limit <count>', 'Max JSONL events to inspect', '200000')
  .option('--json', 'Output JSON')
  .action((options) => {
    try {
      const loaded = loadAndValidateConfig({
        configPath: options.config,
        allowMigration: true,
        writeMigrated: false,
      });
      const status = new StatusStore(STATUS_FILE_PATH).read();
      const counters = status?.counters && typeof status.counters === 'object' ? status.counters : {};

      const limit = Number(options.limit);
      const normalizedLimit = Number.isFinite(limit) && limit > 0 ? Math.floor(limit) : 200000;
      let auditSummary = {};
      if (fs.existsSync(options.auditPath)) {
        const compliance = new ComplianceEngine({
          auditPath: options.auditPath,
        });
        auditSummary = compliance.generateSOC2Evidence({ limit: normalizedLimit }).summary || {};
      }

      const postureConfig = loaded.config.runtime?.posture_scoring || {};
      const posture = computeSecurityPosture({
        config: loaded.config,
        counters,
        auditSummary,
        options: {
          warnThreshold: postureConfig.warn_threshold,
          criticalThreshold: postureConfig.critical_threshold,
          includeCounters: postureConfig.include_counters,
        },
      });

      if (options.json) {
        console.log(JSON.stringify(posture, null, 2));
      } else {
        console.log(`Posture: ${posture.posture}`);
        console.log(`Overall: ${posture.overall}`);
        console.log(`Ingress: ${posture.categories.ingress}`);
        console.log(`Egress: ${posture.categories.egress}`);
        console.log(`Privacy: ${posture.categories.privacy}`);
        console.log(`Agentic: ${posture.categories.agentic}`);
      }
    } catch (error) {
      console.error(`Posture scoring failed: ${error.message}`);
      process.exitCode = 1;
    }
  });

program
  .command('policy-gradient')
  .description('Replay audit events against current/proposed thresholds to estimate security/disruption impact')
  .option('--config <path>', 'Config path', DEFAULT_CONFIG_PATH)
  .option('--audit-path <path>', 'Audit log path', AUDIT_LOG_PATH)
  .option('--limit <count>', 'Max JSONL events to inspect', '200000')
  .option('--current-threshold <value>', 'Current injection threshold')
  .option('--proposed-threshold <value>', 'Proposed injection threshold')
  .option('--json', 'Output JSON')
  .action((options) => {
    try {
      const loaded = loadAndValidateConfig({
        configPath: options.config,
        allowMigration: true,
        writeMigrated: false,
      });
      const eventsWithMeta = loadAuditEvents(options.auditPath, options.limit);
      const analyzer = new PolicyGradientAnalyzer({
        ...(loaded.config.runtime?.policy_gradient_analyzer || {}),
        enabled: true,
      });
      const report = analyzer.analyze({
        events: eventsWithMeta.events || [],
        current: {
          injection_threshold:
            options.currentThreshold !== undefined
              ? Number(options.currentThreshold)
              : loaded.config.runtime?.policy_gradient_analyzer?.current_injection_threshold,
        },
        proposed: {
          injection_threshold:
            options.proposedThreshold !== undefined
              ? Number(options.proposedThreshold)
              : loaded.config.runtime?.policy_gradient_analyzer?.proposed_injection_threshold,
        },
      });
      if (options.json) {
        console.log(JSON.stringify(report, null, 2));
      } else {
        console.log(`Evaluated events: ${report.evaluated_events}`);
        console.log(`Current threshold: ${report.current_threshold}`);
        console.log(`Proposed threshold: ${report.proposed_threshold}`);
        console.log(`Current blocked: ${report.current_blocked}`);
        console.log(`Proposed blocked: ${report.proposed_blocked}`);
        console.log(`Delta blocked: ${report.delta_blocked}`);
        console.log(`Flips to blocked: ${report.flips_to_blocked}`);
        console.log(`Flips to allowed: ${report.flips_to_allowed}`);
        console.log(`Recommendation: ${report.recommendation}`);
      }
    } catch (error) {
      console.error(`Policy gradient analysis failed: ${error.message}`);
      process.exitCode = 1;
    }
  });

program
  .command('capabilities')
  .description('Emit capability snapshot and A2A-style agent card from current config (offline)')
  .option('--config <path>', 'Config path', DEFAULT_CONFIG_PATH)
  .option('--agent-id <id>', 'Agent card ID', 'sentinel-agent')
  .option('--json', 'Output JSON')
  .action((options) => {
    try {
      const loaded = loadAndValidateConfig({
        configPath: options.config,
        allowMigration: true,
        writeMigrated: false,
      });
      const runtime = loaded.config.runtime || {};
      const introspection = new CapabilityIntrospection({
        ...(runtime.capability_introspection || {}),
        enabled: true,
      });
      const pseudoServer = {
        config: loaded.config,
        computeEffectiveMode: () => loaded.config.mode,
        agenticThreatShield: runtime.agentic_threat_shield || {},
        a2aCardVerifier: runtime.a2a_card_verifier || {},
        consensusProtocol: runtime.consensus_protocol || {},
        crossTenantIsolator: runtime.cross_tenant_isolator || {},
        coldStartAnalyzer: runtime.cold_start_analyzer || {},
        mcpPoisoningDetector: runtime.mcp_poisoning || {},
        mcpShadowDetector: runtime.mcp_shadow || {},
        memoryPoisoningSentinel: runtime.memory_poisoning || {},
        cascadeIsolator: runtime.cascade_isolator || {},
        agentIdentityFederation: runtime.agent_identity_federation || {},
        toolUseAnomalyDetector: runtime.tool_use_anomaly || {},
        outputClassifier: runtime.output_classifier || {},
        stegoExfilDetector: runtime.stego_exfil_detector || {},
        reasoningTraceMonitor: runtime.reasoning_trace_monitor || {},
        hallucinationTripwire: runtime.hallucination_tripwire || {},
        semanticDriftCanary: runtime.semantic_drift_canary || {},
        outputProvenanceSigner: runtime.output_provenance || {},
        computeAttestation: runtime.compute_attestation || {},
        provenanceSigner: runtime.provenance || {},
        loopBreaker: runtime.loop_breaker || {},
        omniShield: runtime.omni_shield || {},
        experimentalSandbox: runtime.sandbox_experimental || {},
        shadowOS: runtime.shadow_os || {},
        epistemicAnchor: runtime.epistemic_anchor || {},
        autoImmune: runtime.auto_immune || {},
        canaryToolTrap: runtime.canary_tools || {},
      };
      const snapshot = introspection.snapshot(pseudoServer);
      const card = introspection.exportAgentCard(pseudoServer, options.agentId);
      const output = {
        snapshot,
        agent_card: card,
      };

      if (options.json) {
        console.log(JSON.stringify(output, null, 2));
      } else {
        console.log(`Capability snapshot generated at ${snapshot.generated_at}`);
        console.log(`Enabled engines: ${snapshot.engines.filter((item) => item.enabled).length}/${snapshot.engines.length}`);
        console.log(`Agent card id: ${card.id}`);
        console.log(`Capabilities: ${(card.capabilities || []).join(', ') || 'none'}`);
      }
    } catch (error) {
      console.error(`Capability introspection failed: ${error.message}`);
      process.exitCode = 1;
    }
  });

program
  .command('emergency-open <state>')
  .description('Toggle emergency pass-through mode')
  .action((state) => {
    const normalized = String(state).toLowerCase();
    if (!['on', 'off'].includes(normalized)) {
      console.error('State must be one of: on, off');
      process.exitCode = 1;
      return;
    }

    const payload = setEmergencyOpen(normalized === 'on');
    console.log(`Emergency override set to ${payload.emergency_open}`);
  });

const configCommand = program.command('config').description('Configuration utilities');

configCommand
  .command('validate')
  .description('Validate configuration file')
  .option('--config <path>', 'Config path', DEFAULT_CONFIG_PATH)
  .action((options) => {
    try {
      loadAndValidateConfig({ configPath: options.config, allowMigration: false, writeMigrated: false });
      console.log('Config is valid');
    } catch (error) {
      console.error(error.message);
      process.exitCode = 1;
    }
  });

configCommand
  .command('migrate')
  .description('Migrate config to target version')
  .requiredOption('--to-version <number>', 'Target version')
  .option('--config <path>', 'Config path', DEFAULT_CONFIG_PATH)
  .option('--write', 'Write migration result to config file')
  .option('--backup', 'Write backup before migration')
  .action((options) => {
    const targetVersion = Number(options.toVersion);
    if (!Number.isInteger(targetVersion)) {
      console.error('Target version must be an integer');
      process.exitCode = 1;
      return;
    }

    const configPath = options.config;

    try {
      const current = readYamlConfig(configPath);
      const result = migrateConfig(current, targetVersion);
      if (result.unsupported) {
        console.error(`No migration path from version ${current.version} to ${targetVersion}`);
        process.exitCode = 1;
        return;
      }

      if (!result.migrated) {
        console.log(`Config is already version ${targetVersion}`);
        return;
      }

      if (options.backup) {
        const backupPath = `${configPath}.bak.${Date.now()}`;
        fs.copyFileSync(configPath, backupPath);
        console.log(`Backup written to ${backupPath}`);
      }

      if (options.write) {
        writeYamlConfig(configPath, result.config);
        console.log(`Config migrated and written to ${configPath}`);
      } else {
        console.log(yaml.dump(result.config, { lineWidth: 120 }));
      }
    } catch (error) {
      if (error instanceof ConfigValidationError) {
        console.error(error.message);
      } else {
        console.error(error.message);
      }
      process.exitCode = 1;
    }
  });

const modelsCommand = program.command('models').description('Model utilities');

const privacyCommand = program.command('privacy').description('Differential privacy research utilities (advisory only)');

privacyCommand
  .command('simulate')
  .description('Run advisory differential-privacy simulation against numeric inputs (no live-path mutation)')
  .requiredOption('--in <path>', 'Input JSON path')
  .option('--out <path>', 'Write simulation report JSON to path')
  .option('--config <path>', 'Config path', DEFAULT_CONFIG_PATH)
  .option('--epsilon-per-call <value>', 'Override epsilon spend per call')
  .option('--state-file <path>', 'Persist differential-privacy budget state to this file')
  .option('--state-hmac-key <value>', 'Optional HMAC key for tamper-evident state envelope')
  .option('--persist-state', 'Enable persistence even if config disables it')
  .action((options) => {
    try {
      let dpConfig = {};
      if (fs.existsSync(options.config)) {
        const loaded = loadAndValidateConfig({
          configPath: options.config,
          allowMigration: true,
          writeMigrated: false,
        });
        dpConfig = loaded.config.runtime?.differential_privacy || {};
      }
      if (options.epsilonPerCall !== undefined) {
        dpConfig = {
          ...(dpConfig || {}),
          epsilon_per_call: Number(options.epsilonPerCall),
        };
      }
      if (options.stateFile) {
        dpConfig = {
          ...(dpConfig || {}),
          state_file: String(options.stateFile),
        };
      }
      if (options.stateHmacKey !== undefined) {
        dpConfig = {
          ...(dpConfig || {}),
          state_hmac_key: String(options.stateHmacKey),
        };
      }
      if (options.persistState === true || options.stateFile) {
        dpConfig = {
          ...(dpConfig || {}),
          persist_state: true,
        };
      }

      const inputPath = path.resolve(options.in);
      const payload = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
      const engine = new DifferentialPrivacyEngine(dpConfig);
      const report = engine.simulatePayload(payload);
      report.source = {
        input: inputPath,
        config: fs.existsSync(options.config) ? path.resolve(options.config) : null,
        state_file:
          dpConfig && typeof dpConfig === 'object' && dpConfig.state_file
            ? path.resolve(String(dpConfig.state_file))
            : null,
      };

      if (options.out) {
        const outPath = path.resolve(options.out);
        fs.writeFileSync(outPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
        console.log(`Privacy simulation report written: ${outPath}`);
      } else {
        console.log(JSON.stringify(report, null, 2));
      }
    } catch (error) {
      console.error(`Privacy simulation failed: ${error.message}`);
      process.exitCode = 1;
    }
  });

modelsCommand
  .command('download')
  .description('Pre-download semantic scanner model into local cache')
  .option('--config <path>', 'Optional config path to read semantic model settings')
  .option('--model-id <model>', 'Override model id from config/defaults')
  .option('--cache-dir <path>', 'Override cache directory from config/defaults')
  .action(async (options) => {
    try {
      let semanticConfig = {
        enabled: true,
      };

      const configPath = options.config || DEFAULT_CONFIG_PATH;
      if (fs.existsSync(configPath)) {
        const loaded = loadAndValidateConfig({
          configPath,
          allowMigration: true,
          writeMigrated: false,
        });
        semanticConfig = {
          ...(loaded.config.pii?.semantic || {}),
          enabled: true,
        };
      } else if (options.config) {
        console.error(`Config file not found at ${configPath}`);
        process.exitCode = 1;
        return;
      }

      if (options.modelId) {
        semanticConfig.model_id = options.modelId;
      }
      if (options.cacheDir) {
        semanticConfig.cache_dir = options.cacheDir;
      }

      const scanner = new SemanticScanner(semanticConfig);
      const startedAt = Date.now();
      await scanner.loadPipeline();
      const elapsedMs = Date.now() - startedAt;

      console.log(`Model downloaded and cached: ${scanner.modelId}`);
      console.log(`Cache directory: ${scanner.cacheDir}`);
      console.log(`Ready in ${elapsedMs}ms`);
    } catch (error) {
      console.error(`Model download failed: ${error.message}`);
      process.exitCode = 1;
    }
  });

const policyCommand = program.command('policy').description('Policy bundle signing and verification');

policyCommand
  .command('sign')
  .description('Sign a policy/config file into a cryptographic policy bundle')
  .requiredOption('--private-key <path>', 'Private key PEM path (ed25519 recommended)')
  .option('--config <path>', 'Policy/config YAML path', DEFAULT_CONFIG_PATH)
  .option('--out <path>', 'Output bundle JSON path', './policy.bundle.json')
  .option('--issuer <name>', 'Issuer name', 'sentinel-local')
  .option('--key-id <id>', 'Signing key id', 'sentinel-default')
  .action((options) => {
    try {
      const config = readYamlConfig(options.config);
      const privateKeyPem = fs.readFileSync(options.privateKey, 'utf8');
      const bundle = PolicyBundle.sign(config, privateKeyPem, {
        issuer: options.issuer,
        keyId: options.keyId,
      });
      const outPath = path.resolve(options.out);
      fs.writeFileSync(outPath, `${JSON.stringify(bundle, null, 2)}\n`, 'utf8');
      console.log(`Signed policy bundle written to ${outPath}`);
    } catch (error) {
      console.error(`Policy signing failed: ${error.message}`);
      process.exitCode = 1;
    }
  });

policyCommand
  .command('verify')
  .description('Verify a signed policy bundle')
  .requiredOption('--bundle <path>', 'Bundle JSON path')
  .requiredOption('--public-key <path>', 'Public key PEM path')
  .action((options) => {
    try {
      const bundle = JSON.parse(fs.readFileSync(options.bundle, 'utf8'));
      const publicKeyPem = fs.readFileSync(options.publicKey, 'utf8');
      const result = PolicyBundle.verify(bundle, publicKeyPem);
      console.log(JSON.stringify(result, null, 2));
      if (!result.valid) {
        process.exitCode = 1;
      }
    } catch (error) {
      console.error(`Policy verification failed: ${error.message}`);
      process.exitCode = 1;
    }
  });

const redTeamCommand = program.command('red-team').description('Run built-in adversarial simulation suites');

redTeamCommand
  .command('run')
  .description('Execute red-team suite against a running Sentinel endpoint')
  .option('--url <baseUrl>', 'Sentinel base URL', 'http://127.0.0.1:8787')
  .option('--target <target>', 'x-sentinel-target provider', 'openai')
  .option('--path <path>', 'Proxy path', '/v1/chat/completions')
  .option('--report <format>', 'Report format: json|html', 'json')
  .option('--out <path>', 'Write report to path')
  .action(async (options) => {
    try {
      const engine = new RedTeamEngine(options.url, {
        target: options.target,
        targetPath: options.path,
      });
      const report = await engine.runFullSuite();
      const reportFormat = String(options.report || 'json').toLowerCase();
      if (!['json', 'html'].includes(reportFormat)) {
        throw new Error('Invalid --report value. Use json or html.');
      }
      if (options.out) {
        const outPath = path.resolve(options.out);
        const output = reportFormat === 'html'
          ? renderRedTeamHtmlReport(report, {
              title: 'Sentinel Red-Team Report',
            })
          : `${JSON.stringify(report, null, 2)}\n`;
        fs.writeFileSync(outPath, output, 'utf8');
        console.log(`Red-team report written: ${outPath}`);
      } else {
        if (reportFormat === 'html') {
          console.log(renderRedTeamHtmlReport(report, {
            title: 'Sentinel Red-Team Report',
          }));
        } else {
          console.log(JSON.stringify(report, null, 2));
        }
      }
      if (report.score_percent < 50) {
        process.exitCode = 1;
      }
    } catch (error) {
      console.error(`Red-team run failed: ${error.message}`);
      process.exitCode = 1;
    }
  });

const complianceCommand = program.command('compliance').description('Generate compliance evidence reports from audit logs');

complianceCommand
  .command('report')
  .description('Generate SOC2/GDPR/HIPAA/EU-AI-Act summary evidence report')
  .option('--framework <name>', 'soc2 | gdpr | hipaa | eu-ai-act-article-12', 'soc2')
  .option('--audit-path <path>', 'Audit log path', AUDIT_LOG_PATH)
  .option('--limit <count>', 'Max JSONL events to inspect', '200000')
  .option('--out <path>', 'Write report JSON to path')
  .action((options) => {
    try {
      const engine = new ComplianceEngine({
        auditPath: options.auditPath,
      });
      const limit = Number(options.limit);
      const normalizedLimit = Number.isFinite(limit) && limit > 0 ? Math.floor(limit) : 200000;
      const framework = String(options.framework || 'soc2').toLowerCase();

      let report;
      if (framework === 'gdpr') {
        report = engine.generateGDPREvidence({ limit: normalizedLimit });
      } else if (framework === 'hipaa') {
        report = engine.generateHIPAAEvidence({ limit: normalizedLimit });
      } else if (framework === 'eu-ai-act' || framework === 'eu-ai-act-article-12' || framework === 'article-12') {
        report = engine.generateEUAIActArticle12Evidence({ limit: normalizedLimit });
      } else {
        report = engine.generateSOC2Evidence({ limit: normalizedLimit });
      }

      if (options.out) {
        const outPath = path.resolve(options.out);
        fs.writeFileSync(outPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
        console.log(`Compliance report written: ${outPath}`);
      } else {
        console.log(JSON.stringify(report, null, 2));
      }
    } catch (error) {
      console.error(`Compliance report failed: ${error.message}`);
      process.exitCode = 1;
    }
  });

complianceCommand
  .command('owasp-llm')
  .description('Generate OWASP LLM compliance report (Top10 or extended profiles)')
  .option('--config <path>', 'Config path', DEFAULT_CONFIG_PATH)
  .option('--profile <name>', 'llm-top10-2025 | llm-extended-2025', 'llm-top10-2025')
  .option('--report <format>', 'json|html', 'json')
  .option('--out <path>', 'Write report to path')
  .action((options) => {
    try {
      const loaded = loadAndValidateConfig({
        configPath: options.config,
        allowMigration: true,
        writeMigrated: false,
      });
      const format = String(options.report || 'json').toLowerCase();
      if (!['json', 'html'].includes(format)) {
        throw new Error('Invalid --report value. Use json or html.');
      }
      const report = generateOWASPComplianceReport(loaded.config, {
        profile: options.profile,
      });
      const defaultTitle = report?.profile?.id === 'llm-extended-2025'
        ? 'Sentinel OWASP LLM Extended Compliance Report'
        : 'Sentinel OWASP LLM Top 10 Compliance Report';
      const output =
        format === 'html'
          ? renderOWASPLLMHtmlReport(report, {
              title: defaultTitle,
            })
          : `${JSON.stringify(report, null, 2)}\n`;

      if (options.out) {
        const outPath = path.resolve(options.out);
        fs.writeFileSync(outPath, output, 'utf8');
        console.log(`OWASP LLM report written: ${outPath}`);
      } else {
        console.log(output);
      }
    } catch (error) {
      console.error(`OWASP LLM report failed: ${error.message}`);
      process.exitCode = 1;
    }
  });

complianceCommand
  .command('evidence-vault')
  .description('Build deterministic compliance evidence packet from audit logs')
  .option('--framework <name>', 'soc2 | iso27001 | eu-ai-act', 'soc2')
  .option('--audit-path <path>', 'Audit log path', AUDIT_LOG_PATH)
  .option('--limit <count>', 'Max JSONL events to inspect', '200000')
  .option('--config <path>', 'Config path', DEFAULT_CONFIG_PATH)
  .option('--out <path>', 'Write evidence packet JSON to path')
  .action((options) => {
    try {
      const loaded = loadAndValidateConfig({
        configPath: options.config,
        allowMigration: true,
        writeMigrated: false,
      });
      const { events } = loadAuditEvents(options.auditPath, options.limit);
      const vault = new EvidenceVault({
        ...(loaded.config.runtime?.evidence_vault || {}),
        enabled: true,
      });
      for (const event of events) {
        vault.append({
          timestamp: event.timestamp,
          control: event?.atlas?.engine || event.provider || 'unknown',
          outcome: event.decision || 'observed',
          details: {
            reason: event.reasons?.[0] || event.reason || 'n/a',
            provider: event.provider || 'unknown',
            status: event.response_status,
          },
        });
      }
      const payload = vault.exportPacket(options.framework || 'soc2');
      payload.source = {
        audit_path: options.auditPath,
        events_considered: events.length,
      };
      const written = emitOutput(payload, options.out);
      if (written) {
        console.log(`Evidence packet written: ${written}`);
      }
    } catch (error) {
      console.error(`Evidence packet generation failed: ${error.message}`);
      process.exitCode = 1;
    }
  });

const threatCommand = program.command('threat').description('Threat graph and corpus evolution utilities');

threatCommand
  .command('graph')
  .description('Generate cross-agent threat propagation graph from audit logs')
  .option('--audit-path <path>', 'Audit log path', AUDIT_LOG_PATH)
  .option('--limit <count>', 'Max JSONL events to inspect', '200000')
  .option('--format <format>', 'json | mermaid | dot', 'json')
  .option('--config <path>', 'Config path', DEFAULT_CONFIG_PATH)
  .option('--out <path>', 'Write report to path')
  .action((options) => {
    try {
      const loaded = loadAndValidateConfig({
        configPath: options.config,
        allowMigration: true,
        writeMigrated: false,
      });
      const { events } = loadAuditEvents(options.auditPath, options.limit);
      const graph = new ThreatPropagationGraph({
        ...(loaded.config.runtime?.threat_graph || {}),
        enabled: true,
      });
      for (const event of events) {
        graph.ingest(event);
      }
      const format = String(options.format || 'json').toLowerCase();
      if (!['json', 'mermaid', 'dot'].includes(format)) {
        throw new Error('Invalid --format value. Use json, mermaid, or dot.');
      }
      const output = graph.export(format);
      if (options.out) {
        const outPath = path.resolve(options.out);
        const serialized = typeof output === 'string' ? output : `${JSON.stringify(output, null, 2)}\n`;
        fs.writeFileSync(outPath, serialized, 'utf8');
        console.log(`Threat graph written: ${outPath}`);
      } else if (typeof output === 'string') {
        console.log(output);
      } else {
        console.log(JSON.stringify(output, null, 2));
      }
    } catch (error) {
      console.error(`Threat graph generation failed: ${error.message}`);
      process.exitCode = 1;
    }
  });

threatCommand
  .command('evolve-corpus')
  .description('Derive sanitized attack corpus candidates from blocked audit events')
  .option('--audit-path <path>', 'Audit log path', AUDIT_LOG_PATH)
  .option('--limit <count>', 'Max JSONL events to inspect', '200000')
  .option('--config <path>', 'Config path', DEFAULT_CONFIG_PATH)
  .option('--include-monitor', 'Include monitor decisions in candidate corpus')
  .option('--out <path>', 'Write evolved fixture pack JSON to path')
  .action((options) => {
    try {
      const loaded = loadAndValidateConfig({
        configPath: options.config,
        allowMigration: true,
        writeMigrated: false,
      });
      const { events } = loadAuditEvents(options.auditPath, options.limit);
      const evolver = new AttackCorpusEvolver({
        ...(loaded.config.runtime?.attack_corpus_evolver || {}),
        enabled: true,
        include_monitor_decisions: options.includeMonitor === true
          ? true
          : loaded.config.runtime?.attack_corpus_evolver?.include_monitor_decisions === true,
      });
      for (const event of events) {
        evolver.ingestAuditEvent(event);
      }
      const pack = evolver.exportFixturePack();
      pack.source = {
        audit_path: options.auditPath,
        events_considered: events.length,
      };
      const written = emitOutput(pack, options.out);
      if (written) {
        console.log(`Evolved attack corpus written: ${written}`);
      }
    } catch (error) {
      console.error(`Attack corpus evolution failed: ${error.message}`);
      process.exitCode = 1;
    }
  });

const forensicCommand = program.command('forensic').description('Replay-safe forensic debugging utilities');

forensicCommand
  .command('capture')
  .description('Capture replay-safe forensic snapshot from request/decision files')
  .requiredOption('--request <path>', 'Request JSON path')
  .requiredOption('--decision <path>', 'Decision JSON path')
  .option('--config <path>', 'Config path', DEFAULT_CONFIG_PATH)
  .option('--summary-only', 'Store summary-only snapshot payload')
  .option('--out <path>', 'Write snapshot JSON to path')
  .action((options) => {
    try {
      const loaded = loadAndValidateConfig({
        configPath: options.config,
        allowMigration: true,
        writeMigrated: false,
      });
      const requestPayload = JSON.parse(fs.readFileSync(path.resolve(options.request), 'utf8'));
      const decisionPayload = JSON.parse(fs.readFileSync(path.resolve(options.decision), 'utf8'));
      const debuggerEngine = new ForensicDebugger({
        ...(loaded.config.runtime?.forensic_debugger || {}),
        enabled: true,
      });
      const snapshot = debuggerEngine.capture({
        request: requestPayload,
        decision: decisionPayload,
        configVersion: loaded.config.version,
        summaryOnly: options.summaryOnly === true,
      });
      const written = emitOutput(snapshot, options.out);
      if (written) {
        console.log(`Forensic snapshot written: ${written}`);
      }
    } catch (error) {
      console.error(`Forensic capture failed: ${error.message}`);
      process.exitCode = 1;
    }
  });

forensicCommand
  .command('replay')
  .description('Replay snapshot with optional what-if threshold overrides')
  .requiredOption('--snapshot <path>', 'Snapshot JSON path')
  .option('--overrides <path>', 'JSON file with what-if overrides')
  .option('--config <path>', 'Config path', DEFAULT_CONFIG_PATH)
  .option('--out <path>', 'Write replay report JSON to path')
  .action((options) => {
    try {
      const loaded = loadAndValidateConfig({
        configPath: options.config,
        allowMigration: true,
        writeMigrated: false,
      });
      const snapshot = JSON.parse(fs.readFileSync(path.resolve(options.snapshot), 'utf8'));
      const overrides = options.overrides
        ? JSON.parse(fs.readFileSync(path.resolve(options.overrides), 'utf8'))
        : {};
      const debuggerEngine = new ForensicDebugger({
        ...(loaded.config.runtime?.forensic_debugger || {}),
        enabled: true,
      });

      const evaluators = [
        {
          name: 'injection_threshold_probe',
          run({ decision = {}, overrides: localOverrides = {} }) {
            const score = Number(decision.injection_score || decision.prompt_rebuff_score || 0);
            const threshold = Number(
              localOverrides.injection_threshold
                ?? loaded.config.injection?.threshold
                ?? 0.8
            );
            return {
              blocked: score >= threshold,
              score,
              threshold,
            };
          },
        },
      ];
      const replay = debuggerEngine.replay(snapshot, evaluators, overrides);
      const replayDecision = replay.results[0]?.result || {};
      const diff = debuggerEngine.diff(snapshot.decision || {}, replayDecision);
      const payload = {
        snapshot_id: snapshot.id || null,
        replay,
        diff,
      };
      const written = emitOutput(payload, options.out);
      if (written) {
        console.log(`Forensic replay report written: ${written}`);
      }
    } catch (error) {
      console.error(`Forensic replay failed: ${error.message}`);
      process.exitCode = 1;
    }
  });

const aibomCommand = program.command('aibom').description('Generate AI Bill of Materials artifacts');

aibomCommand
  .command('export')
  .description('Export observed AI providers/models/tools/agents as deterministic AIBOM JSON')
  .option('--format <format>', 'json', 'json')
  .option('--out <path>', 'Write AIBOM JSON to path')
  .action((options) => {
    try {
      const format = String(options.format || 'json').toLowerCase();
      if (format !== 'json') {
        throw new Error('Invalid --format value. Only json is supported.');
      }

      const statusStore = new StatusStore(STATUS_FILE_PATH);
      const status = statusStore.read();
      const emptyAibom = new AIBOMGenerator().exportArtifact();
      const payload =
        status && status.aibom && typeof status.aibom === 'object'
          ? status.aibom
          : {
              ...emptyAibom,
              source: {
                status_file: STATUS_FILE_PATH,
                loaded: false,
              },
            };

      if (options.out) {
        const outPath = path.resolve(options.out);
        fs.writeFileSync(outPath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
        console.log(`AIBOM report written: ${outPath}`);
      } else {
        console.log(JSON.stringify(payload, null, 2));
      }
    } catch (error) {
      console.error(`AIBOM export failed: ${error.message}`);
      process.exitCode = 1;
    }
  });

const atlasCommand = program.command('atlas').description('Generate MITRE ATLAS evidence from audit logs');

atlasCommand
  .command('report')
  .description('Generate MITRE ATLAS technique report from audit logs')
  .option('--audit-path <path>', 'Audit log path', AUDIT_LOG_PATH)
  .option('--limit <count>', 'Max JSONL events to inspect', '200000')
  .option('--out <path>', 'Write report JSON to path')
  .action((options) => {
    try {
      const limit = Number(options.limit);
      const normalizedLimit = Number.isFinite(limit) && limit > 0 ? Math.floor(limit) : 200000;
      const compliance = new ComplianceEngine({
        auditPath: options.auditPath,
      });
      const loaded = compliance.loadEventsWithMeta({ limit: normalizedLimit });
      const tracker = new AtlasTracker();
      const payload = tracker.exportNavigatorPayload(loaded.events, {
        source: {
          audit_path: options.auditPath,
          limit: normalizedLimit,
        },
      });
      payload.generated_at = new Date().toISOString();
      payload.summary = tracker.summarize(loaded.events, { topLimit: 20 });

      if (options.out) {
        const outPath = path.resolve(options.out);
        fs.writeFileSync(outPath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
        console.log(`ATLAS report written: ${outPath}`);
      } else {
        console.log(JSON.stringify(payload, null, 2));
      }
    } catch (error) {
      console.error(`ATLAS report failed: ${error.message}`);
      process.exitCode = 1;
    }
  });

program.parseAsync(process.argv).catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
