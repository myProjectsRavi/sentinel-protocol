#!/usr/bin/env node

const fs = require('fs');
const yaml = require('js-yaml');
const { Command } = require('commander');

const { ensureDefaultConfigExists, loadAndValidateConfig, readYamlConfig, writeYamlConfig } = require('../src/config/loader');
const { migrateConfig, CURRENT_CONFIG_VERSION } = require('../src/config/migrations');
const { ConfigValidationError } = require('../src/config/schema');
const {
  startServer,
  stopServer,
  statusServer,
  setEmergencyOpen,
  doctorServer,
} = require('../src');
const { DEFAULT_CONFIG_PATH } = require('../src/utils/paths');

const program = new Command();

program.name('sentinel').description('Sentinel Protocol CLI').version('0.2.0');

program
  .command('init')
  .description('Create default sentinel.yaml in ~/.sentinel')
  .option('--force', 'Overwrite existing config')
  .action((options) => {
    const result = ensureDefaultConfigExists(DEFAULT_CONFIG_PATH, Boolean(options.force));
    if (result.created) {
      console.log(`Created config: ${result.path}`);
      return;
    }
    console.log(`Config already exists: ${result.path}`);
  });

program
  .command('start')
  .description('Start Sentinel server')
  .option('--config <path>', 'Config path', DEFAULT_CONFIG_PATH)
  .option('--port <port>', 'Port override')
  .option('--mode <mode>', 'Mode override (monitor|warn|enforce)')
  .option('--dry-run', 'Force monitor behavior')
  .option('--fail-open', 'Degrade blocking decisions to pass-through monitor mode')
  .option('--skip-doctor', 'Skip startup doctor checks (not recommended)')
  .action((options) => {
    try {
      const result = startServer({
        configPath: options.config,
        port: options.port,
        modeOverride: options.mode,
        dryRun: options.dryRun,
        failOpen: options.failOpen,
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
    } catch (error) {
      console.error(error.message);
      process.exitCode = 1;
    }
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

program.parse(process.argv);
