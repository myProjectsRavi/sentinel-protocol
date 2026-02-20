const fs = require('fs');

const { loadAndValidateConfig } = require('./config/loader');
const { SentinelServer } = require('./server');
const { createSentinel } = require('./embed');
const { PolicyBundle } = require('./governance/policy-bundle');
const { RedTeamEngine } = require('./governance/red-team');
const { ComplianceEngine } = require('./governance/compliance-engine');
const { RuntimeOverrideManager } = require('./runtime/override');
const { runDoctorChecks, formatDoctorReport } = require('./runtime/doctor');
const logger = require('./utils/logger');
const {
  DEFAULT_CONFIG_PATH,
  STATUS_FILE_PATH,
  PID_FILE_PATH,
  OVERRIDE_FILE_PATH,
  ensureSentinelHome,
} = require('./utils/paths');
const { StatusStore } = require('./status/store');

const DEFAULT_SIGNAL_SHUTDOWN_TIMEOUT_MS = 15000;
let activeSignalCleanup = null;

function installSignalHandlers(server, options = {}) {
  const shutdownTimeoutMs = Number(options.shutdownTimeoutMs || DEFAULT_SIGNAL_SHUTDOWN_TIMEOUT_MS);
  let shuttingDown = false;

  const handleSignal = async (signalName) => {
    if (shuttingDown) {
      console.error(`Received ${signalName} during shutdown. Forcing exit.`);
      process.exit(1);
      return;
    }

    shuttingDown = true;
    console.error(`Received ${signalName}, shutting down...`);
    logger.warn('Sentinel shutdown signal received', {
      signal: signalName,
      shutdown_timeout_ms: shutdownTimeoutMs,
    });

    const forceExitTimer = setTimeout(() => {
      console.error(`Forced shutdown after ${shutdownTimeoutMs}ms timeout.`);
      process.exit(1);
    }, shutdownTimeoutMs);
    forceExitTimer.unref?.();

    try {
      await server.stop();
      clearTimeout(forceExitTimer);
      process.exit(0);
    } catch (error) {
      clearTimeout(forceExitTimer);
      console.error(`Shutdown failed: ${error.message}`);
      process.exit(1);
    }
  };

  const onSigint = () => {
    void handleSignal('SIGINT');
  };
  const onSigterm = () => {
    void handleSignal('SIGTERM');
  };

  process.on('SIGINT', onSigint);
  process.on('SIGTERM', onSigterm);

  return () => {
    process.removeListener('SIGINT', onSigint);
    process.removeListener('SIGTERM', onSigterm);
  };
}

function loadConfigForStart(options = {}) {
  const loaded = loadAndValidateConfig({
    configPath: options.configPath || DEFAULT_CONFIG_PATH,
    allowMigration: true,
    writeMigrated: true,
  });

  if (options.modeOverride) {
    loaded.config.mode = options.modeOverride;
  }
  if (options.vcrMode) {
    loaded.config.runtime = loaded.config.runtime || {};
    loaded.config.runtime.vcr = loaded.config.runtime.vcr || {};
    loaded.config.runtime.vcr.enabled = true;
    loaded.config.runtime.vcr.mode = options.vcrMode;
  }
  if (options.dashboardEnabled !== undefined) {
    loaded.config.runtime = loaded.config.runtime || {};
    loaded.config.runtime.dashboard = loaded.config.runtime.dashboard || {};
    loaded.config.runtime.dashboard.enabled = Boolean(options.dashboardEnabled);
  }

  return loaded;
}

function startServer(options = {}) {
  ensureSentinelHome();
  const loaded = loadConfigForStart(options);
  let doctorReport = null;
  if (options.runDoctor !== false) {
    doctorReport = runDoctorChecks(loaded.config);
    if (!doctorReport.ok) {
      const details = formatDoctorReport(doctorReport, {
        includeSummary: true,
        includeWarnings: true,
        includePasses: false,
      });
      throw new Error(`Doctor checks failed.\n${details}`);
    }
  }
  const server = new SentinelServer(loaded.config, {
    dryRun: Boolean(options.dryRun),
    failOpen: Boolean(options.failOpen || process.env.SENTINEL_FAIL_OPEN === 'true'),
    portOverride:
      options.port !== undefined && options.port !== null && options.port !== ''
        ? Number(options.port)
        : undefined,
  });

  server.start();

  if (options.installSignalHandlers !== false) {
    if (typeof activeSignalCleanup === 'function') {
      activeSignalCleanup();
      activeSignalCleanup = null;
    }
    activeSignalCleanup = installSignalHandlers(server, {
      shutdownTimeoutMs: options.shutdownTimeoutMs,
    });
  }

  return { server, loaded, doctor: doctorReport };
}

function stopServer() {
  if (!fs.existsSync(PID_FILE_PATH)) {
    return { stopped: false, message: 'No PID file found. Sentinel may not be running.' };
  }

  const pid = Number(fs.readFileSync(PID_FILE_PATH, 'utf8').trim());
  if (!Number.isInteger(pid) || pid <= 0) {
    return { stopped: false, message: 'PID file is invalid.' };
  }

  try {
    process.kill(pid, 'SIGTERM');
    return { stopped: true, pid };
  } catch (error) {
    return { stopped: false, message: error.message };
  }
}

function statusServer(asJson = false) {
  const store = new StatusStore(STATUS_FILE_PATH);
  const status = store.read();
  if (!status) {
    return asJson
      ? {
          service_status: 'stopped',
          pii_provider_mode: 'unknown',
          pii_provider_fallbacks: 0,
          rapidapi_error_count: 0,
          pii_vault_enabled: false,
          pii_vault_mode: 'monitor',
          loop_breaker_enabled: false,
          intent_throttle_enabled: false,
          intent_throttle_mode: 'monitor',
          intent_drift_enabled: false,
          intent_drift_mode: 'monitor',
          swarm_enabled: false,
          swarm_mode: 'monitor',
          polymorphic_prompt_enabled: false,
          synthetic_poisoning_enabled: false,
          synthetic_poisoning_mode: 'monitor',
          cognitive_rollback_enabled: false,
          cognitive_rollback_mode: 'monitor',
          omni_shield_enabled: false,
          omni_shield_mode: 'monitor',
          sandbox_experimental_enabled: false,
          sandbox_experimental_mode: 'monitor',
          budget_enabled: false,
          budget_spent_usd_today: 0,
          budget_remaining_usd_today: 0,
          websocket_enabled: false,
          websocket_mode: 'monitor',
          websocket_active_tunnels: 0,
        }
      : [
          'Service status: stopped',
          'Configured mode: unknown',
          'Effective mode: unknown',
          'Emergency override: false',
          'VCR mode: off',
          'Semantic cache: disabled',
          'Dashboard: disabled',
          'WebSocket interception: disabled',
          'PII provider mode: unknown',
          'PII provider fallbacks: 0',
          'RapidAPI errors: 0',
          'PII vault: disabled',
          'Loop breaker: disabled',
          'Deception mode: disabled',
          'Provenance signing: disabled',
          'Swarm protocol: disabled',
          'Honeytoken injection: disabled',
          'Polymorphic prompt MTD: disabled',
          'Synthetic poisoning: disabled',
          'Cognitive rollback: disabled',
          'Omni-Shield: disabled',
          'Sandbox experimental: disabled',
          'Latency normalization: disabled',
          'Intent throttle: disabled',
          'Intent drift: disabled',
          'Canary tools: disabled',
          'Parallax validator: disabled',
          'Failover events: 0',
          'Canary routed: 0',
          'Budget: disabled',
        ].join('\n');
  }

  if (asJson) {
    return status;
  }

  const providerLines = Object.entries(status.providers || {})
    .map(([provider, details]) => {
      return `  - ${provider}: state=${details.circuit_state} failure_rate_window=${details.failure_rate_window} consecutive_timeouts=${details.consecutive_timeouts}`;
    })
    .join('\n');

  return [
    `Service status: ${status.service_status}`,
    `Configured mode: ${status.configured_mode}`,
    `Effective mode: ${status.effective_mode}`,
    `Emergency override: ${status.emergency_open}`,
    `VCR mode: ${status.vcr_mode || 'off'}`,
    `Semantic cache: ${status.semantic_cache_enabled ? 'enabled' : 'disabled'}`,
    `Dashboard: ${status.dashboard_enabled ? `enabled (http://${status.dashboard_host}:${status.dashboard_port})` : 'disabled'}`,
    `WebSocket interception: ${status.websocket_enabled ? `enabled (${status.websocket_mode}, active_tunnels=${status.websocket_active_tunnels ?? 0}, upgrades=${status.counters?.websocket_upgrades_total ?? 0}, forwarded=${status.counters?.websocket_forwarded ?? 0}, blocked=${status.counters?.websocket_blocked ?? 0}, errors=${status.counters?.websocket_errors ?? 0})` : 'disabled'}`,
    `PII provider mode: ${status.pii_provider_mode || 'unknown'}`,
    `PII provider fallbacks: ${status.pii_provider_fallbacks ?? status.counters?.pii_provider_fallbacks ?? 0}`,
    `RapidAPI errors: ${status.rapidapi_error_count ?? status.counters?.rapidapi_error_count ?? 0}`,
    `PII vault: ${status.pii_vault_enabled ? `enabled (${status.pii_vault_mode}, tokenized=${status.counters?.pii_vault_tokenized ?? 0}, detokenized=${status.counters?.pii_vault_detokenized ?? 0})` : 'disabled'}`,
    `Loop breaker: ${status.loop_breaker_enabled ? `enabled (detected=${status.counters?.loop_detected ?? 0}, blocked=${status.counters?.loop_blocked ?? 0})` : 'disabled'}`,
    `Deception mode: ${status.deception_enabled ? `enabled (engaged=${status.counters?.deception_engaged ?? 0})` : 'disabled'}`,
    `Provenance signing: ${status.provenance_enabled ? 'enabled' : 'disabled'}`,
    `Swarm protocol: ${
      status.swarm_enabled
        ? `enabled (${status.swarm_mode}, skew_window_ms=${status.swarm_allowed_clock_skew_ms ?? 'n/a'}, inbound_verified=${status.counters?.swarm_inbound_verified ?? 0}, inbound_rejected=${status.counters?.swarm_inbound_rejected ?? 0}, skew_rejected=${status.counters?.swarm_timestamp_skew_rejected ?? 0}, unknown_node_rejected=${status.counters?.swarm_unknown_node_rejected ?? 0}, outbound_signed=${status.counters?.swarm_outbound_signed ?? 0})`
        : 'disabled'
    }`,
    `Honeytoken injection: ${status.honeytoken_enabled ? `enabled (injected=${status.counters?.honeytoken_injected ?? 0})` : 'disabled'}`,
    `Polymorphic prompt MTD: ${status.polymorphic_prompt_enabled ? `enabled (applied=${status.counters?.polymorph_applied ?? 0})` : 'disabled'}`,
    `Synthetic poisoning: ${status.synthetic_poisoning_enabled ? `enabled (${status.synthetic_poisoning_mode}, injected=${status.counters?.synthetic_poisoning_injected ?? 0})` : 'disabled'}`,
    `Cognitive rollback: ${status.cognitive_rollback_enabled ? `enabled (${status.cognitive_rollback_mode}, suggested=${status.counters?.cognitive_rollback_suggested ?? 0}, auto=${status.counters?.cognitive_rollback_auto ?? 0})` : 'disabled'}`,
    `Omni-Shield: ${status.omni_shield_enabled ? `enabled (${status.omni_shield_mode}, detected=${status.counters?.omni_shield_detected ?? 0}, blocked=${status.counters?.omni_shield_blocked ?? 0}, sanitized=${status.counters?.omni_shield_sanitized ?? 0}, plugin_errors=${status.counters?.omni_shield_plugin_errors ?? 0})` : 'disabled'}`,
    `Sandbox experimental: ${status.sandbox_experimental_enabled ? `enabled (${status.sandbox_experimental_mode}, detected=${status.counters?.sandbox_detected ?? 0}, blocked=${status.counters?.sandbox_blocked ?? 0}, errors=${status.counters?.sandbox_errors ?? 0})` : 'disabled'}`,
    `Latency normalization: ${status.latency_normalization_enabled ? `enabled (applied=${status.counters?.latency_normalized ?? 0})` : 'disabled'}`,
    `Intent throttle: ${status.intent_throttle_enabled ? `enabled (${status.intent_throttle_mode}, matched=${status.counters?.intent_throttle_matches ?? 0}, blocked=${status.counters?.intent_throttle_blocked ?? 0}, errors=${status.counters?.intent_throttle_errors ?? 0})` : 'disabled'}`,
    `Intent drift: ${status.intent_drift_enabled ? `enabled (${status.intent_drift_mode}, evaluated=${status.counters?.intent_drift_evaluated ?? 0}, detected=${status.counters?.intent_drift_detected ?? 0}, blocked=${status.counters?.intent_drift_blocked ?? 0}, errors=${status.counters?.intent_drift_errors ?? 0})` : 'disabled'}`,
    `Canary tools: ${status.canary_tools_enabled ? `enabled (injected=${status.counters?.canary_tool_injected ?? 0}, triggered=${status.counters?.canary_tool_triggered ?? 0})` : 'disabled'}`,
    `Parallax validator: ${status.parallax_enabled ? `enabled (evaluated=${status.counters?.parallax_evaluated ?? 0}, vetoed=${status.counters?.parallax_vetoed ?? 0})` : 'disabled'}`,
    `Failover events: ${status.counters?.failover_events ?? 0}`,
    `Canary routed: ${status.counters?.canary_routed ?? 0}`,
    `Budget: ${status.budget_enabled ? `enabled (${status.budget_action}, day=${status.budget_day_key}, spent=$${status.budget_spent_usd_today}, remaining=$${status.budget_remaining_usd_today})` : 'disabled'}`,
    `Uptime (s): ${status.uptime_seconds}`,
    `Version: ${status.version}`,
    'Providers:',
    providerLines || '  - none',
    `Recent upstream errors: ${status.counters?.upstream_errors ?? 0}`,
  ].join('\n');
}

function setEmergencyOpen(enabled) {
  ensureSentinelHome();
  const payload = RuntimeOverrideManager.writeOverride(OVERRIDE_FILE_PATH, enabled);
  return payload;
}

function doctorServer(options = {}) {
  const loaded = loadConfigForStart({
    configPath: options.configPath || DEFAULT_CONFIG_PATH,
    modeOverride: options.modeOverride,
  });
  const report = runDoctorChecks(loaded.config);
  return {
    loaded,
    report,
    formatted: formatDoctorReport(report),
  };
}

module.exports = {
  startServer,
  stopServer,
  statusServer,
  setEmergencyOpen,
  doctorServer,
  loadConfigForStart,
  installSignalHandlers,
  createSentinel,
  PolicyBundle,
  RedTeamEngine,
  ComplianceEngine,
};
