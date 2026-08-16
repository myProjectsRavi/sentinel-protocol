#!/usr/bin/env node

const fs = require('fs');
const { Command } = require('commander');

const {
  ensureDefaultConfigExists,
  loadAndValidateConfig,
  readYamlConfig,
  writeYamlConfig,
} = require('../src/config/loader');
const { PROFILE_NAMES, applyConfigProfile } = require('../src/config/profiles');
const { validateConfigShape } = require('../src/config/schema');
const { detectFramework, frameworkSnippet, detectOllamaAvailable } = require('../src/cli/adoption');
const { startServer } = require('../src');
const { DEFAULT_CONFIG_PATH } = require('../src/utils/paths');

// Keep the established CLI implementation as the source of truth for every
// command except bootstrap. Bootstrap needs a small npm-entry guard so that
// rerunning the canonical npx command upgrades the executable without
// destructively reapplying a profile to an existing persisted configuration.
if (process.argv[2] !== 'bootstrap') {
  require('./sentinel');
} else {
  const cliPkg = require('../package.json');

  async function printAutoRuntimeHints(framework) {
    if (framework && framework !== 'none') {
      console.log(`Detected framework: ${framework}`);
      console.log('Framework quick-start snippet:');
      console.log(frameworkSnippet(framework));
    }

    const ollamaDetected = await detectOllamaAvailable({ timeoutMs: 500 });
    if (ollamaDetected) {
      console.log('Ollama detected at http://127.0.0.1:11434 (automatic local provider route available).');
    }
  }

  async function runBootstrap(options) {
    const bootstrapPath = options.config || DEFAULT_CONFIG_PATH;
    const force = options.force === true;
    const existedBefore = fs.existsSync(bootstrapPath);
    const initResult = ensureDefaultConfigExists(bootstrapPath, force);
    const profileName = String(options.profile || 'minimal').toLowerCase();

    if (!PROFILE_NAMES.has(profileName)) {
      throw new Error(`Invalid --profile value "${options.profile}". Use minimal|standard|paranoid.`);
    }

    let persistedProfile = null;
    let existingLoad = null;

    if (!existedBefore || force) {
      const parsed = readYamlConfig(bootstrapPath);
      const normalized = validateConfigShape(parsed);
      persistedProfile = applyConfigProfile(normalized, profileName);
      writeYamlConfig(bootstrapPath, persistedProfile.config);
    } else {
      // Existing-user contract: preserve the user's configuration and runtime
      // behavior. Only the explicit versioned migration pipeline may write
      // changes, and it creates a backup before doing so. --profile is an
      // initialization/reset choice for bootstrap; existing users can still
      // use `sentinel start --profile ...` for an intentional runtime override.
      existingLoad = loadAndValidateConfig({
        configPath: bootstrapPath,
        allowMigration: true,
        writeMigrated: true,
      });
    }

    const shutdownTimeoutMs = Number(options.shutdownTimeoutMs);
    const startResult = startServer({
      configPath: bootstrapPath,
      port: options.port,
      modeOverride: options.mode,
      dashboardEnabled: options.dashboard === true ? true : undefined,
      profile: persistedProfile ? profileName : undefined,
      shutdownTimeoutMs:
        Number.isFinite(shutdownTimeoutMs) && shutdownTimeoutMs > 0 ? shutdownTimeoutMs : 15000,
      runDoctor: true,
    });

    console.log(initResult.created ? `Created config: ${bootstrapPath}` : `Using config: ${bootstrapPath}`);

    if (persistedProfile) {
      console.log(
        `Bootstrap profile: ${persistedProfile.profile} (${persistedProfile.enabledRuntimeEngines}/${persistedProfile.totalRuntimeEngines} runtime engines enabled)`
      );
    } else {
      console.log(`Preserved existing config and runtime settings: ${bootstrapPath}`);
      if (existingLoad?.migration?.migrated) {
        console.log(
          `Migrated config ${existingLoad.migration.fromVersion} -> ${existingLoad.migration.toVersion}` +
            (existingLoad.backupPath ? ` (backup: ${existingLoad.backupPath})` : '')
        );
      }
    }

    const framework = detectFramework(process.cwd());
    if (framework || options.auto === true) {
      await printAutoRuntimeHints(framework || 'none');
    }

    if (startResult.doctor) {
      const summary = startResult.doctor.summary;
      console.log(`Doctor summary: pass=${summary.pass} warn=${summary.warn} fail=${summary.fail}`);
    }
  }

  const program = new Command();
  program.name('sentinel').description('Sentinel Protocol CLI').version(cliPkg.version);
  program
    .command('bootstrap')
    .description('Initialize or safely reuse config, run doctor checks, and start Sentinel (one-command path)')
    .option('--config <path>', 'Config path', DEFAULT_CONFIG_PATH)
    .option('--force', 'Overwrite existing config and persist the selected profile')
    .option(
      '--profile <name>',
      'Initialization profile: minimal|standard|paranoid (used only for first/forced bootstrap)',
      'minimal'
    )
    .option('--port <port>', 'Port override')
    .option('--mode <mode>', 'Mode override (monitor|warn|enforce)')
    .option('--dashboard', 'Enable local dashboard server for this run')
    .option('--auto', 'Auto-detect framework and print wiring snippet')
    .option('--shutdown-timeout-ms <ms>', 'Forced shutdown timeout in milliseconds', '15000')
    .action(async (options) => {
      try {
        await runBootstrap(options);
      } catch (error) {
        console.error(error.message);
        process.exitCode = 1;
      }
    });

  program.parseAsync(process.argv).catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
