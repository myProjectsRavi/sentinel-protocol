const path = require('path');

const PLACEHOLDER_BASE64_PNG =
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+XjT0AAAAASUVORK5CYII=';

function toObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return {};
  }
  return value;
}

function clampPositiveInt(value, fallback, min = 1, max = 100 * 1024 * 1024) {
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
  return normalized === 'block' ? 'block' : 'monitor';
}

function normalizePluginMode(value, fallback = 'enforce') {
  const normalized = String(value || fallback).toLowerCase();
  return normalized === 'always' ? 'always' : 'enforce';
}

function withTimeout(promise, timeoutMs) {
  let timer = null;
  const timeoutPromise = new Promise((_, reject) => {
    timer = setTimeout(() => {
      reject(new Error(`plugin_timeout_after_${timeoutMs}ms`));
    }, timeoutMs);
    timer.unref?.();
  });
  return Promise.race([promise, timeoutPromise]).finally(() => {
    if (timer) {
      clearTimeout(timer);
    }
  });
}

function isPlainObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value);
}

function approximateBase64Bytes(data) {
  const normalized = String(data || '').replace(/\s+/g, '');
  if (!normalized) {
    return 0;
  }
  const padding = normalized.endsWith('==') ? 2 : normalized.endsWith('=') ? 1 : 0;
  return Math.max(0, Math.floor((normalized.length * 3) / 4) - padding);
}

function parseDataImageUrl(url) {
  const value = String(url || '');
  const match = /^data:(image\/[a-z0-9.+-]+);base64,(.+)$/i.exec(value);
  if (!match) {
    return null;
  }
  return {
    mediaType: String(match[1]).toLowerCase(),
    base64Data: match[2],
  };
}

class OmniShield {
  constructor(config = {}) {
    const normalized = toObject(config);
    this.enabled = normalized.enabled === true;
    this.mode = normalizeMode(normalized.mode, 'monitor');
    this.maxImageBytes = clampPositiveInt(normalized.max_image_bytes, 5 * 1024 * 1024, 1024, 100 * 1024 * 1024);
    this.allowRemoteImageUrls = normalized.allow_remote_image_urls === true;
    this.allowBase64Images = normalized.allow_base64_images !== false;
    this.blockOnAnyImage = normalized.block_on_any_image === true;
    this.maxFindings = clampPositiveInt(normalized.max_findings, 20, 1, 200);
    this.targetRoles = new Set(
      Array.isArray(normalized.target_roles)
        ? normalized.target_roles.map((item) => String(item || '').toLowerCase()).filter(Boolean)
        : ['user']
    );
    this.observability = normalized.observability !== false;
    const plugin = toObject(normalized.plugin);
    this.plugin = {
      enabled: plugin.enabled === true,
      provider: String(plugin.provider || 'builtin_mask').toLowerCase(),
      modulePath: String(plugin.module_path || '').trim(),
      mode: normalizePluginMode(plugin.mode, 'enforce'),
      failClosed: plugin.fail_closed === true,
      maxRewrites: clampPositiveInt(plugin.max_rewrites, 20, 1, 1000),
      timeoutMs: clampPositiveInt(plugin.timeout_ms, 1500, 50, 30000),
      observability: plugin.observability !== false,
    };
    this.loadedPlugin = null;
  }

  isEnabled() {
    return this.enabled === true;
  }

  shouldInspectRole(role) {
    if (this.targetRoles.size === 0) {
      return true;
    }
    return this.targetRoles.has(String(role || '').toLowerCase());
  }

  shouldRunPlugin(effectiveMode = 'monitor') {
    if (!this.plugin.enabled) {
      return false;
    }
    if (this.plugin.mode === 'always') {
      return true;
    }
    return String(effectiveMode || '').toLowerCase() === 'enforce';
  }

  getPlaceholderDataUrl(mediaType = 'image/png') {
    const normalizedType = String(mediaType || 'image/png').toLowerCase();
    const safeType = normalizedType.startsWith('image/') ? normalizedType : 'image/png';
    return `data:${safeType};base64,${PLACEHOLDER_BASE64_PNG}`;
  }

  resolvePlugin() {
    if (this.loadedPlugin) {
      return this.loadedPlugin;
    }
    if (!this.plugin.modulePath) {
      this.loadedPlugin = this.builtinSanitize.bind(this);
      return this.loadedPlugin;
    }
    const absolute = path.isAbsolute(this.plugin.modulePath)
      ? this.plugin.modulePath
      : path.resolve(process.cwd(), this.plugin.modulePath);
    // eslint-disable-next-line global-require, import/no-dynamic-require
    const mod = require(absolute);
    const fn =
      typeof mod === 'function'
        ? mod
        : typeof mod?.sanitizeImagePayload === 'function'
          ? mod.sanitizeImagePayload
          : typeof mod?.default === 'function'
            ? mod.default
            : null;
    if (!fn) {
      throw new Error(`Invalid omni shield plugin module: ${absolute}`);
    }
    this.loadedPlugin = fn;
    return this.loadedPlugin;
  }

  builtinSanitize({ bodyJson, findings }) {
    if (!bodyJson || typeof bodyJson !== 'object' || !Array.isArray(bodyJson.messages)) {
      return {
        applied: false,
        rewrites: 0,
        unsupported: 0,
        bodyJson,
      };
    }
    const out = JSON.parse(JSON.stringify(bodyJson));
    let rewrites = 0;
    let unsupported = 0;

    for (const finding of findings || []) {
      if (rewrites >= this.plugin.maxRewrites) {
        break;
      }
      const msgIndex = Number(finding?.message_index);
      const partIndex = Number(finding?.part_index);
      if (!Number.isInteger(msgIndex) || !Number.isInteger(partIndex)) {
        continue;
      }
      const message = out.messages[msgIndex];
      if (!message || !Array.isArray(message.content)) {
        continue;
      }
      const part = message.content[partIndex];
      if (!part || typeof part !== 'object') {
        continue;
      }

      if (finding.kind === 'image_data_url') {
        const mediaType = String(finding.media_type || 'image/png');
        const replacement = this.getPlaceholderDataUrl(mediaType);
        if (typeof part.image_url === 'string') {
          part.image_url = replacement;
          rewrites += 1;
          continue;
        }
        if (part.image_url && typeof part.image_url === 'object' && typeof part.image_url.url === 'string') {
          part.image_url.url = replacement;
          rewrites += 1;
          continue;
        }
        if (typeof part.input_image === 'string') {
          part.input_image = replacement;
          rewrites += 1;
          continue;
        }
        if (part.input_image && typeof part.input_image === 'object' && typeof part.input_image.url === 'string') {
          part.input_image.url = replacement;
          rewrites += 1;
          continue;
        }
        unsupported += 1;
        continue;
      }

      if (finding.kind === 'image_base64_payload') {
        if (part.source && typeof part.source === 'object') {
          part.source.data = PLACEHOLDER_BASE64_PNG;
          rewrites += 1;
          continue;
        }
        unsupported += 1;
        continue;
      }

      unsupported += 1;
    }

    return {
      applied: rewrites > 0,
      rewrites,
      unsupported,
      bodyJson: out,
    };
  }

  async sanitizePayload({ bodyJson, findings, effectiveMode = 'monitor' } = {}) {
    if (!this.shouldRunPlugin(effectiveMode)) {
      return {
        enabled: this.plugin.enabled,
        applied: false,
        rewrites: 0,
        unsupported: 0,
        shouldBlock: false,
        reason: this.plugin.enabled ? 'mode_bypass' : 'disabled',
        bodyJson,
      };
    }
    try {
      const sanitizer = this.resolvePlugin();
      const safeBodyJson = isPlainObject(bodyJson) ? JSON.parse(JSON.stringify(bodyJson)) : bodyJson;
      const result = await withTimeout(Promise.resolve(sanitizer({
        bodyJson: safeBodyJson,
        findings: Array.isArray(findings) ? findings : [],
        pluginConfig: this.plugin,
      })), this.plugin.timeoutMs);
      if (!isPlainObject(result)) {
        throw new Error('plugin_invalid_result');
      }
      const rewrites = Number(result.rewrites || 0);
      const unsupported = Number(result.unsupported || 0);
      if (!Number.isFinite(rewrites) || rewrites < 0) {
        throw new Error('plugin_invalid_rewrites');
      }
      if (!Number.isFinite(unsupported) || unsupported < 0) {
        throw new Error('plugin_invalid_unsupported');
      }
      const boundedRewrites = Math.min(this.plugin.maxRewrites, Math.floor(rewrites));
      const boundedUnsupported = Math.floor(unsupported);
      const shouldBlock = this.plugin.failClosed && boundedUnsupported > 0 && String(effectiveMode || '') === 'enforce';
      return {
        enabled: true,
        applied: result.applied === true,
        rewrites: boundedRewrites,
        unsupported: boundedUnsupported,
        shouldBlock,
        reason: shouldBlock ? 'plugin_fail_closed' : 'ok',
        bodyJson: isPlainObject(result.bodyJson) ? result.bodyJson : bodyJson,
      };
    } catch (error) {
      const message = String(error.message || error);
      const shouldBlock = this.plugin.failClosed && String(effectiveMode || '') === 'enforce';
      return {
        enabled: true,
        applied: false,
        rewrites: 0,
        unsupported: 0,
        shouldBlock,
        reason: message.startsWith('plugin_timeout_after_') ? 'plugin_timeout' : 'plugin_error',
        error: message,
        bodyJson,
      };
    }
  }

  inspectUrl(url, meta = {}) {
    const findings = [];
    const normalizedUrl = String(url || '').trim();
    if (!normalizedUrl) {
      return findings;
    }

    const dataUrl = parseDataImageUrl(normalizedUrl);
    if (dataUrl) {
      const bytes = approximateBase64Bytes(dataUrl.base64Data);
      findings.push({
        kind: 'image_data_url',
        media_type: dataUrl.mediaType,
        bytes,
        blockable: this.blockOnAnyImage || !this.allowBase64Images || bytes > this.maxImageBytes,
        reason:
          bytes > this.maxImageBytes
            ? 'image_size_exceeded'
            : !this.allowBase64Images
              ? 'base64_images_not_allowed'
              : this.blockOnAnyImage
                ? 'image_block_on_any'
                : 'image_detected',
        ...meta,
      });
      return findings;
    }

    if (/^https?:\/\//i.test(normalizedUrl)) {
      findings.push({
        kind: 'image_remote_url',
        bytes: null,
        blockable: this.blockOnAnyImage || !this.allowRemoteImageUrls,
        reason: this.blockOnAnyImage
          ? 'image_block_on_any'
          : this.allowRemoteImageUrls
            ? 'image_detected'
            : 'remote_image_url_not_allowed',
        ...meta,
      });
      return findings;
    }

    return findings;
  }

  inspectAnthropicImage(source, meta = {}) {
    const findings = [];
    if (!source || typeof source !== 'object') {
      return findings;
    }
    if (String(source.type || '').toLowerCase() !== 'base64') {
      return findings;
    }
    const mediaType = String(source.media_type || '').toLowerCase();
    const bytes = approximateBase64Bytes(String(source.data || ''));
    findings.push({
      kind: 'image_base64_payload',
      media_type: mediaType || 'image/unknown',
      bytes,
      blockable: this.blockOnAnyImage || !this.allowBase64Images || bytes > this.maxImageBytes,
      reason:
        bytes > this.maxImageBytes
          ? 'image_size_exceeded'
          : !this.allowBase64Images
            ? 'base64_images_not_allowed'
            : this.blockOnAnyImage
              ? 'image_block_on_any'
              : 'image_detected',
      ...meta,
    });
    return findings;
  }

  inspect({ bodyJson, effectiveMode = 'monitor' } = {}) {
    if (!this.isEnabled()) {
      return {
        enabled: false,
        detected: false,
        findings: [],
        shouldBlock: false,
      };
    }
    if (!bodyJson || typeof bodyJson !== 'object') {
      return {
        enabled: true,
        detected: false,
        findings: [],
        shouldBlock: false,
      };
    }

    const findings = [];
    const pushFinding = (finding) => {
      if (finding && findings.length < this.maxFindings) {
        findings.push(finding);
      }
    };

    if (Array.isArray(bodyJson.messages)) {
      bodyJson.messages.forEach((message, messageIndex) => {
        const role = String(message?.role || '').toLowerCase();
        if (!this.shouldInspectRole(role)) {
          return;
        }
        const content = message?.content;
        if (!Array.isArray(content)) {
          return;
        }
        content.forEach((part, partIndex) => {
          if (!part || typeof part !== 'object') {
            return;
          }
          const type = String(part.type || '').toLowerCase();
          const meta = {
            role,
            message_index: messageIndex,
            part_index: partIndex,
          };

          if (type === 'image_url' || type === 'input_image') {
            const imageValue = part.image_url || part.input_image || {};
            const url =
              typeof imageValue === 'string'
                ? imageValue
                : typeof imageValue?.url === 'string'
                  ? imageValue.url
                  : '';
            for (const finding of this.inspectUrl(url, meta)) {
              pushFinding(finding);
            }
            return;
          }

          if (type === 'image') {
            for (const finding of this.inspectAnthropicImage(part.source, meta)) {
              pushFinding(finding);
            }
          }
        });
      });
    }

    const violating = findings.filter((item) => item.blockable);
    const shouldBlock = this.mode === 'block' && effectiveMode === 'enforce' && violating.length > 0;
    return {
      enabled: true,
      detected: findings.length > 0,
      findings,
      violating_findings: violating,
      shouldBlock,
    };
  }
}

module.exports = {
  OmniShield,
  approximateBase64Bytes,
  parseDataImageUrl,
  PLACEHOLDER_BASE64_PNG,
};
