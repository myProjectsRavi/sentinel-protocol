function toArray(value) {
  if (!value) {
    return [];
  }
  return Array.isArray(value) ? value : [value];
}

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

class PluginRegistry {
  constructor(options = {}) {
    this.logger = options.logger || console;
    this.pipeline = options.pipeline || null;
    this.plugins = new Map();
  }

  register(plugin) {
    if (!isObject(plugin)) {
      throw new Error('plugin must be an object');
    }
    const name = String(plugin.name || '').trim();
    if (!name) {
      throw new Error('plugin.name is required');
    }
    if (this.plugins.has(name)) {
      throw new Error(`plugin already registered: ${name}`);
    }

    if (typeof plugin.setup === 'function') {
      plugin.setup({
        logger: this.logger,
      });
    }

    if (this.pipeline) {
      const hooks = isObject(plugin.hooks) ? plugin.hooks : {};
      for (const [stage, handler] of Object.entries(hooks)) {
        if (typeof handler !== 'function') {
          continue;
        }
        this.pipeline.use(stage, `${name}:${stage}`, handler, {
          priority: Number(plugin.priority ?? 100),
          critical: plugin.critical === true,
        });
      }
    }

    this.plugins.set(name, plugin);
    this.logger?.info?.('Sentinel plugin registered', {
      plugin: name,
      version: plugin.version || '0.0.0',
    });
    return name;
  }

  registerAll(plugins) {
    for (const plugin of toArray(plugins)) {
      this.register(plugin);
    }
  }

  list() {
    return Array.from(this.plugins.values()).map((plugin) => ({
      name: String(plugin.name),
      version: String(plugin.version || '0.0.0'),
      description: String(plugin.description || ''),
    }));
  }
}

module.exports = {
  PluginRegistry,
};
