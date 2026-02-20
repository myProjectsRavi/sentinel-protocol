const crypto = require('crypto');
const { clampPositiveInt } = require('../utils/primitives');

const DEFAULT_LEXICON = Object.freeze({
  helpful: ['assistive', 'supportive'],
  assistant: ['assistive entity', 'support assistant'],
  instruction: ['directive', 'guideline'],
  instructions: ['directives', 'guidelines'],
  policy: ['control policy', 'governance policy'],
  policies: ['control policies', 'governance policies'],
  secure: ['hardened', 'safeguarded'],
  safety: ['guardrail', 'protection posture'],
  analyze: ['evaluate', 'inspect'],
  response: ['reply', 'output'],
  enforce: ['apply', 'uphold'],
});

function toObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return {};
  }
  return value;
}

function cloneJson(input) {
  return JSON.parse(JSON.stringify(input));
}

function isBypassHeaderValue(value) {
  const normalized = String(value || '').trim().toLowerCase();
  return normalized === '1' || normalized === 'true' || normalized === 'yes' || normalized === 'on';
}

function getHeaderValue(headers = {}, wantedHeader) {
  const wanted = String(wantedHeader || '').toLowerCase();
  for (const [header, value] of Object.entries(headers || {})) {
    if (String(header).toLowerCase() === wanted) {
      return value;
    }
  }
  return undefined;
}

function normalizeLexicon(rawLexicon) {
  const source = toObject(rawLexicon);
  const merged = {};
  const entries = Object.keys(source).length > 0 ? source : DEFAULT_LEXICON;
  for (const [term, replacements] of Object.entries(entries)) {
    const normalizedTerm = String(term || '').trim().toLowerCase();
    if (!normalizedTerm) {
      continue;
    }
    const options = Array.isArray(replacements)
      ? replacements.map((item) => String(item || '').trim()).filter(Boolean)
      : [];
    if (options.length === 0) {
      continue;
    }
    merged[normalizedTerm] = options;
  }
  return merged;
}

function preserveCase(sourceWord, replacement) {
  if (!sourceWord) {
    return replacement;
  }
  if (sourceWord.toUpperCase() === sourceWord) {
    return replacement.toUpperCase();
  }
  if (sourceWord[0].toUpperCase() === sourceWord[0] && sourceWord.slice(1).toLowerCase() === sourceWord.slice(1)) {
    return replacement.charAt(0).toUpperCase() + replacement.slice(1);
  }
  return replacement;
}

function stableVariantIndex(seed) {
  const hash = crypto.createHash('sha256').update(seed).digest();
  return hash.readUInt32BE(0);
}

function mutateTextDeterministically(text, options) {
  const source = String(text || '');
  if (!source) {
    return {
      text: source,
      mutated: false,
      replacements: [],
    };
  }

  const {
    epoch,
    seed,
    messageIndex,
    maxMutations,
    lexicon,
  } = options;
  const tokenRegex = /\b[a-zA-Z][a-zA-Z_-]*\b/g;
  let match;
  let cursor = 0;
  let out = '';
  let applied = 0;
  const replacements = [];
  let tokenIndex = 0;

  while ((match = tokenRegex.exec(source)) !== null) {
    const start = match.index;
    const end = start + match[0].length;
    const rawWord = match[0];
    const normalizedWord = rawWord.toLowerCase();
    out += source.slice(cursor, start);

    const variants = lexicon[normalizedWord];
    if (!variants || variants.length === 0 || applied >= maxMutations) {
      out += rawWord;
      cursor = end;
      tokenIndex += 1;
      continue;
    }

    let variantIdx = stableVariantIndex(
      `${seed}:${epoch}:${messageIndex}:${tokenIndex}:${normalizedWord}`
    ) % variants.length;
    let replacement = variants[variantIdx];
    if (replacement.toLowerCase() === rawWord.toLowerCase() && variants.length > 1) {
      variantIdx = (variantIdx + 1) % variants.length;
      replacement = variants[variantIdx];
    }
    const casedReplacement = preserveCase(rawWord, replacement);
    out += casedReplacement;
    replacements.push({
      from: rawWord,
      to: casedReplacement,
      at: start,
    });
    applied += 1;
    cursor = end;
    tokenIndex += 1;
  }

  out += source.slice(cursor);
  return {
    text: out,
    mutated: applied > 0,
    replacements,
  };
}

class PolymorphicPromptEngine {
  constructor(config = {}, deps = {}) {
    const normalized = toObject(config);
    this.enabled = normalized.enabled === true;
    this.rotationSeconds = clampPositiveInt(normalized.rotation_seconds, 1800, 60, 24 * 3600);
    this.maxMutationsPerMessage = clampPositiveInt(normalized.max_mutations_per_message, 3, 1, 20);
    this.targetRoles = new Set(
      Array.isArray(normalized.target_roles)
        ? normalized.target_roles.map((role) => String(role || '').toLowerCase()).filter(Boolean)
        : ['system']
    );
    this.bypassHeader = String(normalized.bypass_header || 'x-sentinel-polymorph-disable').toLowerCase();
    this.seed = String(normalized.seed || 'sentinel-mtd-seed');
    this.observability = normalized.observability !== false;
    this.lexicon = normalizeLexicon(normalized.lexicon);
    this.now = typeof deps.now === 'function' ? deps.now : Date.now;
  }

  isEnabled() {
    return this.enabled === true;
  }

  currentEpoch() {
    const nowMs = Number(this.now());
    return Math.floor(nowMs / (this.rotationSeconds * 1000));
  }

  mutate({ bodyJson, headers = {} } = {}) {
    if (!this.isEnabled()) {
      return {
        applied: false,
        reason: 'disabled',
      };
    }
    if (!bodyJson || typeof bodyJson !== 'object' || !Array.isArray(bodyJson.messages)) {
      return {
        applied: false,
        reason: 'unsupported_payload',
      };
    }
    if (isBypassHeaderValue(getHeaderValue(headers, this.bypassHeader))) {
      return {
        applied: false,
        reason: 'bypass_header',
      };
    }

    const epoch = this.currentEpoch();
    const draft = cloneJson(bodyJson);
    const replacements = [];
    let mutatedMessages = 0;

    for (let messageIndex = 0; messageIndex < draft.messages.length; messageIndex += 1) {
      const message = draft.messages[messageIndex];
      if (!message || typeof message !== 'object') {
        continue;
      }
      const role = String(message.role || '').toLowerCase();
      if (!this.targetRoles.has(role)) {
        continue;
      }

      let messageMutated = false;
      if (typeof message.content === 'string') {
        const mutated = mutateTextDeterministically(message.content, {
          epoch,
          seed: this.seed,
          messageIndex,
          maxMutations: this.maxMutationsPerMessage,
          lexicon: this.lexicon,
        });
        if (mutated.mutated) {
          message.content = mutated.text;
          replacements.push(...mutated.replacements);
          messageMutated = true;
        }
      } else if (Array.isArray(message.content)) {
        for (const part of message.content) {
          if (!part || typeof part !== 'object' || String(part.type || '').toLowerCase() !== 'text') {
            continue;
          }
          if (typeof part.text !== 'string') {
            continue;
          }
          const mutated = mutateTextDeterministically(part.text, {
            epoch,
            seed: this.seed,
            messageIndex,
            maxMutations: this.maxMutationsPerMessage,
            lexicon: this.lexicon,
          });
          if (mutated.mutated) {
            part.text = mutated.text;
            replacements.push(...mutated.replacements);
            messageMutated = true;
          }
        }
      }
      if (messageMutated) {
        mutatedMessages += 1;
      }
    }

    if (replacements.length === 0) {
      return {
        applied: false,
        reason: 'no_mutations',
        meta: {
          epoch,
          replacements: 0,
          messages_mutated: 0,
        },
      };
    }

    return {
      applied: true,
      reason: 'applied',
      bodyJson: draft,
      bodyText: JSON.stringify(draft),
      meta: {
        epoch,
        replacements: replacements.length,
        messages_mutated: mutatedMessages,
        replacement_preview: replacements.slice(0, 5),
      },
    };
  }
}

module.exports = {
  PolymorphicPromptEngine,
  mutateTextDeterministically,
};
