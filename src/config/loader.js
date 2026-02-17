const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const { ensureSentinelHome, DEFAULT_CONFIG_PATH } = require('../utils/paths');
const { CURRENT_CONFIG_VERSION, migrateConfig } = require('./migrations');
const { ConfigValidationError, validateConfigShape } = require('./schema');

const PROJECT_DEFAULT_CONFIG = path.join(__dirname, 'default.yaml');

function backupPathFor(configPath) {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  return `${configPath}.bak.${stamp}`;
}

function readYamlConfig(configPath) {
  const raw = fs.readFileSync(configPath, 'utf8');
  return yaml.load(raw);
}

function writeYamlConfig(configPath, config) {
  const dumped = yaml.dump(config, { lineWidth: 120 });
  fs.writeFileSync(configPath, dumped, 'utf8');
}

function ensureDefaultConfigExists(configPath = DEFAULT_CONFIG_PATH, force = false) {
  ensureSentinelHome();
  if (!force && fs.existsSync(configPath)) {
    return { created: false, path: configPath };
  }

  const defaultContent = fs.readFileSync(PROJECT_DEFAULT_CONFIG, 'utf8');
  fs.writeFileSync(configPath, defaultContent, 'utf8');
  return { created: true, path: configPath };
}

function loadAndValidateConfig(options = {}) {
  ensureSentinelHome();

  const {
    configPath = DEFAULT_CONFIG_PATH,
    allowMigration = true,
    writeMigrated = true,
    targetVersion = CURRENT_CONFIG_VERSION,
  } = options;

  if (!fs.existsSync(configPath)) {
    throw new Error(`Config file not found at ${configPath}. Run: sentinel init`);
  }

  let parsed;
  try {
    parsed = readYamlConfig(configPath);
  } catch (error) {
    throw new Error(`Failed to parse config YAML: ${error.message}`);
  }

  const migration = migrateConfig(parsed, targetVersion);
  let candidate = migration.config;

  if (migration.unsupported) {
    throw new Error(
      `Unsupported config version ${parsed.version}. Expected version ${targetVersion} and no migration path exists.`
    );
  }

  let backupPath;
  if (allowMigration && migration.migrated && writeMigrated) {
    backupPath = backupPathFor(configPath);
    fs.copyFileSync(configPath, backupPath);
    writeYamlConfig(configPath, candidate);
  }

  let normalized;
  try {
    normalized = validateConfigShape(candidate);
  } catch (error) {
    if (error instanceof ConfigValidationError) {
      const details = error.details.map((detail) => `- ${detail}`).join('\n');
      throw new Error(`${error.message}\n${details}`);
    }
    throw error;
  }

  return {
    config: normalized,
    configPath,
    backupPath,
    migration,
  };
}

module.exports = {
  ensureDefaultConfigExists,
  loadAndValidateConfig,
  backupPathFor,
  readYamlConfig,
  writeYamlConfig,
  PROJECT_DEFAULT_CONFIG,
};
