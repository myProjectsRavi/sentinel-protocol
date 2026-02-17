const CURRENT_CONFIG_VERSION = 1;

function clone(input) {
  return JSON.parse(JSON.stringify(input));
}

function migrateFromStringVersion(config) {
  const next = clone(config);
  next.version = Number.parseInt(String(config.version).split('.')[0], 10);
  return next;
}

function migrateFromZero(config) {
  const next = clone(config);
  next.version = 1;
  if (!next.runtime) {
    next.runtime = {
      fail_open: false,
      scanner_error_action: 'allow',
      upstream: {
        retry: {
          enabled: true,
          max_attempts: 1,
          allow_post_with_idempotency_key: false,
        },
        circuit_breaker: {
          enabled: true,
          window_size: 20,
          min_failures_to_evaluate: 8,
          failure_rate_threshold: 0.5,
          consecutive_timeout_threshold: 5,
          open_seconds: 20,
          half_open_success_threshold: 3,
        },
      },
    };
  }
  return next;
}

const MIGRATORS = new Map([
  ['1.0', migrateFromStringVersion],
  ['1', migrateFromStringVersion],
  [0, migrateFromZero],
]);

function migrateConfig(config, targetVersion = CURRENT_CONFIG_VERSION) {
  const rawVersion = config.version;

  if (rawVersion === targetVersion) {
    return {
      migrated: false,
      fromVersion: rawVersion,
      toVersion: targetVersion,
      config,
      notes: [],
    };
  }

  const migrator = MIGRATORS.get(rawVersion);
  if (!migrator) {
    return {
      migrated: false,
      fromVersion: rawVersion,
      toVersion: targetVersion,
      config,
      notes: [],
      unsupported: true,
    };
  }

  const migratedConfig = migrator(config);
  migratedConfig.version = targetVersion;

  return {
    migrated: true,
    fromVersion: rawVersion,
    toVersion: targetVersion,
    config: migratedConfig,
    notes: [`Migrated config version ${rawVersion} -> ${targetVersion}`],
    unsupported: false,
  };
}

module.exports = {
  CURRENT_CONFIG_VERSION,
  migrateConfig,
};
