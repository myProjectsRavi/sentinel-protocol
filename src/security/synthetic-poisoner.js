const crypto = require('crypto');
const { clampPositiveInt, normalizeMode } = require('../utils/primitives');

const DEFAULT_ACKNOWLEDGEMENT = 'I_UNDERSTAND_SYNTHETIC_DATA_RISK';

function toObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return {};
  }
  return value;
}

function cloneJson(input) {
  return JSON.parse(JSON.stringify(input));
}

class SyntheticPoisoner {
  constructor(config = {}, deps = {}) {
    const normalized = toObject(config);
    this.enabled = normalized.enabled === true;
    this.mode = normalizeMode(normalized.mode, 'monitor', ['monitor', 'inject']);
    this.requiredAcknowledgement = String(
      normalized.required_acknowledgement || DEFAULT_ACKNOWLEDGEMENT
    ).trim();
    this.acknowledgement = String(normalized.acknowledgement || '').trim();
    this.allowedTriggers = new Set(
      Array.isArray(normalized.allowed_triggers)
        ? normalized.allowed_triggers.map((item) => String(item || '').trim()).filter(Boolean)
        : ['intent_velocity_exceeded']
    );
    this.targetRoles = new Set(
      Array.isArray(normalized.target_roles)
        ? normalized.target_roles.map((item) => String(item || '').toLowerCase()).filter(Boolean)
        : ['system']
    );
    this.maxInsertions = clampPositiveInt(normalized.max_insertions_per_request, 1, 1, 5);
    this.decoyLabel = String(normalized.decoy_label || 'SENTINEL_SYNTHETIC_CONTEXT').trim();
    this.observability = normalized.observability !== false;
    this.now = typeof deps.now === 'function' ? deps.now : Date.now;
    this.randomUuid = typeof deps.randomUuid === 'function' ? deps.randomUuid : crypto.randomUUID;
  }

  isEnabled() {
    return this.enabled === true;
  }

  canInjectForTrigger(trigger) {
    if (!this.isEnabled()) {
      return {
        ok: false,
        reason: 'disabled',
      };
    }
    if (this.mode !== 'inject') {
      return {
        ok: false,
        reason: 'monitor_mode',
      };
    }
    if (!this.requiredAcknowledgement || this.acknowledgement !== this.requiredAcknowledgement) {
      return {
        ok: false,
        reason: 'acknowledgement_missing',
      };
    }
    if (!this.allowedTriggers.has(String(trigger || ''))) {
      return {
        ok: false,
        reason: 'trigger_not_allowed',
      };
    }
    return {
      ok: true,
      reason: 'eligible',
    };
  }

  buildDecoyMessage({ trigger }) {
    const createdAt = new Date(Number(this.now())).toISOString();
    const decoyId = this.randomUuid();
    const decoySalary = 70000 + Math.floor((stableHash(decoyId) % 9) * 5000);
    const decoyToken = crypto.createHash('sha256').update(decoyId).digest('hex').slice(0, 16);
    const payload = {
      label: this.decoyLabel,
      advisory: 'SYNTHETIC_DECOY_DATA_FOR_SECURITY_TESTING_ONLY',
      trigger,
      generated_at: createdAt,
      decoy_records: [
        {
          employee_id: `EMP-${decoyToken}`,
          salary_usd: decoySalary,
          department: 'synthetic-security-lab',
        },
      ],
    };
    return {
      decoyId,
      text: `Synthetic context injected by Sentinel for security deception testing:\n${JSON.stringify(payload)}`,
    };
  }

  inject({ bodyJson, trigger }) {
    const eligibility = this.canInjectForTrigger(trigger);
    if (!eligibility.ok) {
      return {
        applied: false,
        reason: eligibility.reason,
      };
    }
    if (!bodyJson || typeof bodyJson !== 'object' || !Array.isArray(bodyJson.messages)) {
      return {
        applied: false,
        reason: 'unsupported_payload',
      };
    }

    const draft = cloneJson(bodyJson);
    const insertions = [];
    const targets = Array.isArray(draft.messages) ? draft.messages : [];
    let inserted = 0;

    for (let idx = 0; idx <= targets.length && inserted < this.maxInsertions; idx += 1) {
      const role = idx < targets.length ? String(targets[idx]?.role || '').toLowerCase() : '';
      if (idx < targets.length && !this.targetRoles.has(role)) {
        continue;
      }
      const decoy = this.buildDecoyMessage({ trigger });
      const message = {
        role: 'system',
        content: decoy.text,
      };
      draft.messages.splice(idx, 0, message);
      insertions.push({
        index: idx,
        decoy_id: decoy.decoyId,
      });
      inserted += 1;
      if (idx < targets.length) {
        idx += 1;
      }
    }

    if (insertions.length === 0) {
      return {
        applied: false,
        reason: 'no_target_role',
      };
    }

    return {
      applied: true,
      reason: 'injected',
      bodyJson: draft,
      bodyText: JSON.stringify(draft),
      meta: {
        trigger,
        insertions: insertions.length,
        decoy_ids: insertions.map((item) => item.decoy_id),
      },
    };
  }
}

function stableHash(input) {
  const hash = crypto.createHash('sha256').update(String(input || '')).digest();
  return hash.readUInt32BE(0);
}

module.exports = {
  SyntheticPoisoner,
  DEFAULT_ACKNOWLEDGEMENT,
};
