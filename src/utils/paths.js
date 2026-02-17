const os = require('os');
const path = require('path');
const fs = require('fs');

const SENTINEL_HOME = process.env.SENTINEL_HOME || path.join(os.homedir(), '.sentinel');
const DEFAULT_CONFIG_PATH = path.join(SENTINEL_HOME, 'sentinel.yaml');
const PID_FILE_PATH = path.join(SENTINEL_HOME, 'sentinel.pid');
const STATUS_FILE_PATH = path.join(SENTINEL_HOME, 'status.json');
const OVERRIDE_FILE_PATH = path.join(SENTINEL_HOME, 'runtime.override.json');
const AUDIT_LOG_PATH = path.join(SENTINEL_HOME, 'audit.jsonl');

function ensureSentinelHome() {
  if (!fs.existsSync(SENTINEL_HOME)) {
    fs.mkdirSync(SENTINEL_HOME, { recursive: true });
  }
}

module.exports = {
  SENTINEL_HOME,
  DEFAULT_CONFIG_PATH,
  PID_FILE_PATH,
  STATUS_FILE_PATH,
  OVERRIDE_FILE_PATH,
  AUDIT_LOG_PATH,
  ensureSentinelHome,
};
