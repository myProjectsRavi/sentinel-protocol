function toObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return {};
  }
  return value;
}

function clampPositiveInt(value, fallback, min = 1, max = 100) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  const normalized = Math.floor(parsed);
  if (normalized < min || normalized > max) {
    return fallback;
  }
  return normalized;
}

function normalizeMode(value, fallback = 'monitor') {
  const normalized = String(value || fallback).toLowerCase();
  return normalized === 'auto' ? 'auto' : 'monitor';
}

function cloneJson(input) {
  return JSON.parse(JSON.stringify(input));
}

class CognitiveRollback {
  constructor(config = {}) {
    const normalized = toObject(config);
    this.enabled = normalized.enabled === true;
    this.mode = normalizeMode(normalized.mode, 'monitor');
    this.triggers = new Set(
      Array.isArray(normalized.triggers)
        ? normalized.triggers.map((item) => String(item || '').trim()).filter(Boolean)
        : ['canary_tool_triggered', 'parallax_veto']
    );
    this.targetRoles = new Set(
      Array.isArray(normalized.target_roles)
        ? normalized.target_roles.map((item) => String(item || '').toLowerCase()).filter(Boolean)
        : ['user', 'assistant', 'tool']
    );
    this.dropMessages = clampPositiveInt(normalized.drop_messages, 2, 1, 20);
    this.minMessagesRemaining = clampPositiveInt(normalized.min_messages_remaining, 2, 1, 100);
    this.systemMessage = String(
      normalized.system_message ||
        '[SYSTEM OVERRIDE] Your previous thought process was corrupted. Resume execution from the last safe checkpoint and try a different approach.'
    );
    this.observability = normalized.observability !== false;
  }

  isEnabled() {
    return this.enabled === true;
  }

  shouldAuto() {
    return this.isEnabled() && this.mode === 'auto';
  }

  suggest({ bodyJson, trigger } = {}) {
    if (!this.isEnabled()) {
      return {
        applicable: false,
        reason: 'disabled',
      };
    }
    const normalizedTrigger = String(trigger || '').trim();
    if (!this.triggers.has(normalizedTrigger)) {
      return {
        applicable: false,
        reason: 'trigger_not_enabled',
      };
    }
    if (!bodyJson || typeof bodyJson !== 'object' || !Array.isArray(bodyJson.messages)) {
      return {
        applicable: false,
        reason: 'unsupported_payload',
      };
    }
    if (bodyJson.messages.length <= this.minMessagesRemaining) {
      return {
        applicable: false,
        reason: 'insufficient_messages',
      };
    }

    const draft = cloneJson(bodyJson);
    const removableIndices = [];
    for (let i = draft.messages.length - 1; i >= 0; i -= 1) {
      const role = String(draft.messages[i]?.role || '').toLowerCase();
      if (this.targetRoles.has(role)) {
        removableIndices.push(i);
      }
      if (removableIndices.length >= this.dropMessages) {
        break;
      }
    }
    if (removableIndices.length === 0) {
      return {
        applicable: false,
        reason: 'no_droppable_messages',
      };
    }

    const safeIndices = removableIndices
      .sort((a, b) => b - a)
      .filter((idx) => draft.messages.length - 1 >= this.minMessagesRemaining && idx >= 0);
    let dropped = 0;
    for (const idx of safeIndices) {
      if (draft.messages.length - 1 < this.minMessagesRemaining) {
        break;
      }
      draft.messages.splice(idx, 1);
      dropped += 1;
    }
    if (dropped === 0) {
      return {
        applicable: false,
        reason: 'insufficient_messages_after_filter',
      };
    }

    draft.messages.unshift({
      role: 'system',
      content: this.systemMessage,
    });

    return {
      applicable: true,
      mode: this.mode,
      trigger: normalizedTrigger,
      bodyJson: draft,
      bodyText: JSON.stringify(draft),
      droppedMessages: dropped,
      remainingMessages: draft.messages.length,
      reason: 'suggested',
    };
  }
}

module.exports = {
  CognitiveRollback,
};
