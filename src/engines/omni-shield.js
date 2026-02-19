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
};
