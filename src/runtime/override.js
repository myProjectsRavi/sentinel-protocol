const fs = require('fs');

class RuntimeOverrideManager {
  constructor(overridePath) {
    this.overridePath = overridePath;
    this.override = { emergency_open: false, updated_at: null };
    this.interval = null;
  }

  readFromDisk() {
    try {
      if (!fs.existsSync(this.overridePath)) {
        return { emergency_open: false, updated_at: null };
      }
      const parsed = JSON.parse(fs.readFileSync(this.overridePath, 'utf8'));
      return {
        emergency_open: Boolean(parsed.emergency_open),
        updated_at: parsed.updated_at || null,
      };
    } catch {
      return { emergency_open: false, updated_at: null };
    }
  }

  startPolling(onChange, intervalMs = 2000) {
    this.override = this.readFromDisk();
    this.interval = setInterval(() => {
      const latest = this.readFromDisk();
      if (latest.emergency_open !== this.override.emergency_open || latest.updated_at !== this.override.updated_at) {
        this.override = latest;
        onChange(this.override);
      }
    }, intervalMs);
  }

  stopPolling() {
    if (this.interval) {
      clearInterval(this.interval);
      this.interval = null;
    }
  }

  getOverride() {
    return this.override;
  }

  static writeOverride(path, enabled) {
    const payload = {
      emergency_open: Boolean(enabled),
      updated_at: new Date().toISOString(),
    };
    fs.writeFileSync(path, JSON.stringify(payload, null, 2), 'utf8');
    return payload;
  }
}

module.exports = {
  RuntimeOverrideManager,
};
