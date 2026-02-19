function safeNumber(value, fallback = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

class MiddlewarePipeline {
  constructor(options = {}) {
    this.logger = options.logger || console;
    this.stages = new Map();
  }

  use(stage, name, middleware, options = {}) {
    if (typeof stage !== 'string' || !stage.trim()) {
      throw new Error('pipeline stage must be a non-empty string');
    }
    if (typeof name !== 'string' || !name.trim()) {
      throw new Error('pipeline middleware name must be a non-empty string');
    }
    if (typeof middleware !== 'function') {
      throw new Error(`pipeline middleware "${name}" must be a function`);
    }
    const bucket = this.stages.get(stage) || [];
    bucket.push({
      name,
      fn: middleware,
      priority: safeNumber(options.priority, 100),
      enabled: options.enabled !== false,
      critical: options.critical === true,
    });
    bucket.sort((a, b) => a.priority - b.priority || a.name.localeCompare(b.name));
    this.stages.set(stage, bucket);
  }

  list(stage) {
    return (this.stages.get(stage) || []).map((item) => ({
      name: item.name,
      priority: item.priority,
      enabled: item.enabled,
      critical: item.critical,
    }));
  }

  async execute(stage, context) {
    const entries = this.stages.get(stage) || [];
    if (entries.length === 0) {
      return { ran: 0, stage };
    }

    let ran = 0;
    for (const entry of entries) {
      if (entry.enabled !== true) {
        continue;
      }
      try {
        await entry.fn(context);
        ran += 1;
      } catch (error) {
        if (typeof context?.warn === 'function') {
          context.warn(`pipeline:${stage}:${entry.name}:error`);
        }
        this.logger?.warn?.('Pipeline middleware failed', {
          stage,
          middleware: entry.name,
          error: error?.message || String(error),
          critical: entry.critical === true,
        });
        if (entry.critical === true) {
          throw error;
        }
      }
    }
    return { ran, stage };
  }
}

module.exports = {
  MiddlewarePipeline,
};
