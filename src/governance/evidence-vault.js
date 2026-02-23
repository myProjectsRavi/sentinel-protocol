const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const {
  clampPositiveInt,
  normalizeMode,
} = require('../utils/primitives');

function stableObject(value) {
  if (value === null || value === undefined) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => stableObject(item));
  }
  if (typeof value !== 'object') {
    return value;
  }
  const out = {};
  for (const key of Object.keys(value).sort()) {
    out[key] = stableObject(value[key]);
  }
  return out;
}

function sha256(input = '') {
  return crypto.createHash('sha256').update(String(input || ''), 'utf8').digest('hex');
}

class EvidenceVault {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'active']);
    this.maxEntries = clampPositiveInt(config.max_entries, 100000, 100, 5_000_000);
    this.retentionDays = clampPositiveInt(config.retention_days, 90, 1, 3650);
    this.filePath = String(config.file_path || '').trim();
    this.observability = config.observability !== false;
    this.entries = [];
    this.chainHead = '';
  }

  isEnabled() {
    return this.enabled === true;
  }

  append(rawEntry = {}) {
    if (!this.isEnabled()) {
      return null;
    }
    const now = new Date().toISOString();
    const payload = {
      timestamp: rawEntry.timestamp || now,
      control: String(rawEntry.control || 'unknown'),
      outcome: String(rawEntry.outcome || 'observed'),
      details: stableObject(rawEntry.details || {}),
    };
    const payloadHash = sha256(JSON.stringify(payload));
    const entryHash = sha256(`${this.chainHead}:${payloadHash}`);
    const record = {
      index: this.entries.length,
      payload,
      payload_hash: payloadHash,
      prev_hash: this.chainHead,
      entry_hash: entryHash,
    };
    this.chainHead = entryHash;
    this.entries.push(record);
    if (this.entries.length > this.maxEntries) {
      this.entries = this.entries.slice(this.entries.length - this.maxEntries);
    }
    this.prune();
    if (this.filePath) {
      this.persist(record);
    }
    return record;
  }

  persist(record) {
    try {
      const file = path.resolve(this.filePath);
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.appendFileSync(file, `${JSON.stringify(record)}\n`, 'utf8');
    } catch {
      // best effort; runtime remains memory-safe
    }
  }

  prune(nowMs = Date.now()) {
    const cutoff = nowMs - (this.retentionDays * 24 * 3600 * 1000);
    const before = this.entries.length;
    this.entries = this.entries.filter((item) => {
      const ts = Date.parse(String(item?.payload?.timestamp || ''));
      if (!Number.isFinite(ts)) {
        return true;
      }
      return ts >= cutoff;
    });
    if (this.entries.length !== before) {
      let prev = '';
      this.entries = this.entries.map((item, idx) => {
        const payloadHash = sha256(JSON.stringify(item.payload || {}));
        const entryHash = sha256(`${prev}:${payloadHash}`);
        const next = {
          index: idx,
          payload: item.payload,
          payload_hash: payloadHash,
          prev_hash: prev,
          entry_hash: entryHash,
        };
        prev = entryHash;
        return next;
      });
      this.chainHead = prev;
    }
  }

  verify(index) {
    if (!Number.isInteger(index) || index < 0 || index >= this.entries.length) {
      return {
        valid: false,
        reason: 'index_out_of_range',
      };
    }
    const record = this.entries[index];
    const payloadHash = sha256(JSON.stringify(record.payload || {}));
    if (payloadHash !== record.payload_hash) {
      return {
        valid: false,
        reason: 'payload_hash_mismatch',
      };
    }
    const expectedEntryHash = sha256(`${record.prev_hash || ''}:${record.payload_hash || ''}`);
    if (expectedEntryHash !== record.entry_hash) {
      return {
        valid: false,
        reason: 'entry_hash_mismatch',
      };
    }
    return {
      valid: true,
      reason: 'ok',
      index,
      entry_hash: record.entry_hash,
    };
  }

  exportPacket(framework = 'soc2') {
    const fw = String(framework || 'soc2').toLowerCase();
    return {
      framework: fw,
      generated_at: new Date().toISOString(),
      entry_count: this.entries.length,
      chain_head: this.chainHead,
      controls: this.entries.map((item) => ({
        control: item.payload.control,
        outcome: item.payload.outcome,
        timestamp: item.payload.timestamp,
        entry_hash: item.entry_hash,
      })),
    };
  }

  getStats() {
    return {
      enabled: this.enabled,
      entries: this.entries.length,
      chain_head: this.chainHead ? this.chainHead.slice(0, 16) : '',
    };
  }
}

module.exports = {
  EvidenceVault,
};
