class RequestContext {
  constructor(input = {}) {
    this.req = input.req || null;
    this.res = input.res || null;
    this.server = input.server || null;
    this.correlationId = input.correlationId || null;
    this.requestStart = Number(input.requestStart || Date.now());
    this.state = new Map();
    this.tags = {};
    this.warnings = [];
    this.shortCircuit = null;
  }

  set(key, value) {
    this.state.set(String(key), value);
    return this;
  }

  get(key, fallback = undefined) {
    return this.state.has(String(key)) ? this.state.get(String(key)) : fallback;
  }

  setTag(key, value) {
    if (value === undefined) {
      delete this.tags[key];
    } else {
      this.tags[key] = value;
    }
    return this;
  }

  warn(message) {
    const msg = String(message || '').trim();
    if (msg) {
      this.warnings.push(msg);
    }
    return this;
  }

  block(options = {}) {
    this.shortCircuit = {
      statusCode: Number(options.statusCode || 403),
      body: options.body || { error: 'PLUGIN_BLOCKED' },
      headers: options.headers && typeof options.headers === 'object' ? options.headers : {},
      reason: String(options.reason || 'plugin_block'),
    };
    return this.shortCircuit;
  }

  isBlocked() {
    return Boolean(this.shortCircuit);
  }
}

module.exports = {
  RequestContext,
};
