const fs = require('fs');

const { loadAndValidateConfig } = require('./config/loader');
const { SentinelServer } = require('./server');
const { RuntimeOverrideManager } = require('./runtime/override');
const { runDoctorChecks, formatDoctorReport } = require('./runtime/doctor');
const {
  DEFAULT_CONFIG_PATH,
  STATUS_FILE_PATH,
  PID_FILE_PATH,
  OVERRIDE_FILE_PATH,
  ensureSentinelHome,
} = require('./utils/paths');
const { StatusStore } = require('./status/store');

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
    portOverride: options.port ? Number(options.port) : undefined,
  });

  server.start();

  const shutdown = async () => {
    await server.stop();
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

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
};
