const path = require('path');

function loadOptimizerPlugin() {
  const pluginPath = process.env.SENTINEL_OPTIMIZER_PLUGIN;
  if (!pluginPath) {
    return require('./noop-plugin');
  }

  const resolved = path.isAbsolute(pluginPath) ? pluginPath : path.resolve(process.cwd(), pluginPath);
  try {
    return require(resolved);
  } catch {
    return require('./noop-plugin');
  }
}

module.exports = {
  loadOptimizerPlugin,
};
