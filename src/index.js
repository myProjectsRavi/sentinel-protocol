const fs = require('fs');

const { loadAndValidateConfig } = require('./config/loader');
const { SentinelServer } = require('./server');
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
      ? { service_status: 'stopped', pii_provider_mode: 'unknown', pii_provider_fallbacks: 0, rapidapi_error_count: 0 }
      : [
          'Service status: stopped',
          'Configured mode: unknown',
          'Effective mode: unknown',
          'Emergency override: false',
          'PII provider mode: unknown',
          'PII provider fallbacks: 0',
          'RapidAPI errors: 0',
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
    `PII provider mode: ${status.pii_provider_mode || 'unknown'}`,
    `PII provider fallbacks: ${status.pii_provider_fallbacks ?? status.counters?.pii_provider_fallbacks ?? 0}`,
    `RapidAPI errors: ${status.rapidapi_error_count ?? status.counters?.rapidapi_error_count ?? 0}`,
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
};
