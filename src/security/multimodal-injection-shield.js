const {
  clampPositiveInt,
  clampProbability,
  normalizeMode,
} = require('../utils/primitives');

const BASE64_BLOB_RE = /\b[A-Za-z0-9+/]{256,}={0,2}\b/g;
const MULTIMODAL_KEY_RE = /(image|audio|video|frame|waveform|spectrogram)/i;
const SUSPICIOUS_TEXT_RE = /\b(ignore\s+previous\s+instructions?|bypass\s+guardrails?|system\s+prompt|reveal\s+secret)\b/i;

function detectMagicFormat(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 4) {
    return 'unknown';
  }
  if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4e && buffer[3] === 0x47) {
    return 'image/png';
  }
  if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    return 'image/jpeg';
  }
  if (buffer[0] === 0x47 && buffer[1] === 0x49 && buffer[2] === 0x46) {
    return 'image/gif';
  }
  if (buffer[0] === 0x52 && buffer[1] === 0x49 && buffer[2] === 0x46 && buffer[3] === 0x46) {
    return 'audio/wav';
  }
  if (buffer[4] === 0x66 && buffer[5] === 0x74 && buffer[6] === 0x79 && buffer[7] === 0x70) {
    return 'video/mp4';
  }
  return 'unknown';
}

function contentTypeFamily(contentType = '') {
  const value = String(contentType || '').toLowerCase();
  if (value.includes('image/')) {
    return 'image';
  }
  if (value.includes('audio/')) {
    return 'audio';
  }
  if (value.includes('video/')) {
    return 'video';
  }
  return 'other';
}

class MultiModalInjectionShield {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'block']);
    this.maxScanBytes = clampPositiveInt(config.max_scan_bytes, 262144, 256, 16 * 1024 * 1024);
    this.maxFindings = clampPositiveInt(config.max_findings, 16, 1, 512);
    this.base64EntropyThreshold = clampProbability(config.base64_entropy_threshold, 0.55);
    this.maxDecodedBase64Bytes = clampPositiveInt(config.max_decoded_base64_bytes, 32768, 64, 1024 * 1024);
    this.blockOnMimeMismatch = config.block_on_mime_mismatch === true;
    this.blockOnSuspiciousMetadata = config.block_on_suspicious_metadata === true;
    this.blockOnBase64Injection = config.block_on_base64_injection === true;
    this.observability = config.observability !== false;
  }

  isEnabled() {
    return this.enabled === true;
  }

  evaluate({
    headers = {},
    rawBody = Buffer.alloc(0),
    bodyText = '',
    bodyJson = null,
    effectiveMode = 'monitor',
  } = {}) {
    if (!this.isEnabled()) {
      return {
        enabled: false,
        detected: false,
        shouldBlock: false,
        reason: 'clean',
        findings: [],
      };
    }

    const contentType = String(headers['content-type'] || '').toLowerCase();
    const family = contentTypeFamily(contentType);
    const boundedBuffer = Buffer.isBuffer(rawBody) ? rawBody.subarray(0, this.maxScanBytes) : Buffer.alloc(0);
    const boundedText = String(bodyText || '').slice(0, this.maxScanBytes);
    const findings = [];

    const magic = detectMagicFormat(boundedBuffer);
    if (magic !== 'unknown' && contentType && !contentType.includes(magic.split('/')[0])) {
      findings.push({
        code: 'multimodal_mime_mismatch',
        content_type: contentType,
        detected_magic: magic,
        blockEligible: this.blockOnMimeMismatch,
      });
    }

    const metadataText = boundedBuffer.toString('utf8').slice(0, 16384);
    if (/\b(?:exif|iptc|xmp|usercomment|imagemagick|photoshop)\b/i.test(metadataText) && SUSPICIOUS_TEXT_RE.test(metadataText)) {
      findings.push({
        code: 'multimodal_suspicious_metadata',
        blockEligible: this.blockOnSuspiciousMetadata,
      });
    }

    if (bodyJson && typeof bodyJson === 'object' && !Array.isArray(bodyJson)) {
      const keys = Object.keys(bodyJson).slice(0, 128);
      if (keys.some((key) => MULTIMODAL_KEY_RE.test(key)) && /data:.*;base64,/i.test(boundedText)) {
        findings.push({
          code: 'multimodal_embedded_base64_payload',
          blockEligible: this.blockOnBase64Injection,
        });
      }
    }

    BASE64_BLOB_RE.lastIndex = 0;
    let match;
    let inspected = 0;
    while ((match = BASE64_BLOB_RE.exec(boundedText)) !== null) {
      inspected += 1;
      const blob = String(match[0] || '');
      const sample = blob.slice(0, this.maxDecodedBase64Bytes);
      let decoded = '';
      try {
        decoded = Buffer.from(sample, 'base64').toString('utf8');
      } catch {
        decoded = '';
      }
      const signalDensity = decoded
        ? (decoded.match(/[{}[\]<>:;'"`]/g) || []).length / Math.max(1, decoded.length)
        : 0;
      if (SUSPICIOUS_TEXT_RE.test(decoded) || signalDensity >= this.base64EntropyThreshold) {
        findings.push({
          code: 'multimodal_base64_instruction_payload',
          density: Number(signalDensity.toFixed(6)),
          blockEligible: this.blockOnBase64Injection,
        });
      }
      if (findings.length >= this.maxFindings || inspected >= this.maxFindings) {
        break;
      }
      if (String(match[0] || '').length === 0) {
        BASE64_BLOB_RE.lastIndex += 1;
      }
    }

    if (family === 'audio' && /\bultrasonic|inaudible|hidden command\b/i.test(boundedText)) {
      findings.push({
        code: 'multimodal_audio_ultrasonic_signal',
        blockEligible: false,
      });
    }

    const detected = findings.length > 0;
    const shouldBlock =
      detected &&
      this.mode === 'block' &&
      String(effectiveMode || '').toLowerCase() === 'enforce' &&
      findings.some((finding) => finding.blockEligible === true);

    return {
      enabled: true,
      mode: this.mode,
      detected,
      shouldBlock,
      reason: detected ? String(findings[0].code || 'multimodal_injection_detected') : 'clean',
      findings: findings.slice(0, this.maxFindings),
      family,
      magic,
    };
  }
}

module.exports = {
  MultiModalInjectionShield,
};
