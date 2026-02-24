const crypto = require('crypto');
const {
  clampPositiveInt,
  normalizeMode,
} = require('../utils/primitives');

function normalizeText(value = '') {
  return String(value || '')
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();
}

function sha256(value = '') {
  return crypto.createHash('sha256').update(String(value || ''), 'utf8').digest('hex');
}

function canonicalize(value) {
  if (value === null || value === undefined) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => canonicalize(item));
  }
  if (typeof value !== 'object') {
    return value;
  }
  const out = {};
  for (const key of Object.keys(value).sort()) {
    out[key] = canonicalize(value[key]);
  }
  return out;
}

function stableStringify(value) {
  return JSON.stringify(canonicalize(value));
}

function createFingerprints(text = '') {
  const normalized = normalizeText(text);
  if (!normalized) {
    return [];
  }
  const fingerprints = [];
  fingerprints.push(sha256(normalized));
  if (normalized.length > 256) {
    fingerprints.push(sha256(normalized.slice(0, 256)));
    fingerprints.push(sha256(normalized.slice(-256)));
  }
  return Array.from(new Set(fingerprints));
}

function normalizeNodeId(value = '') {
  const normalized = String(value || 'sentinel-node')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-');
  if (!normalized) {
    return 'sentinel-node';
  }
  return normalized.slice(0, 80);
}

function normalizePeers(peers = [], maxPeers = 16) {
  if (!Array.isArray(peers)) {
    return [];
  }
  const out = [];
  const seen = new Set();
  for (const peer of peers.slice(0, maxPeers)) {
    const raw = String(peer || '').trim();
    if (!raw) {
      continue;
    }
    let normalized = '';
    try {
      const url = new URL(raw);
      if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        continue;
      }
      normalized = `${url.protocol}//${url.host}`;
    } catch {
      continue;
    }
    if (!normalized || seen.has(normalized)) {
      continue;
    }
    seen.add(normalized);
    out.push(normalized);
  }
  return out;
}

function timingSafeHexEqual(left = '', right = '') {
  const a = String(left || '').toLowerCase();
  const b = String(right || '').toLowerCase();
  if (a.length === 0 || b.length === 0 || a.length !== b.length) {
    return false;
  }
  if (!/^[a-f0-9]+$/.test(a) || !/^[a-f0-9]+$/.test(b)) {
    return false;
  }
  const leftBuffer = Buffer.from(a, 'hex');
  const rightBuffer = Buffer.from(b, 'hex');
  if (leftBuffer.length !== rightBuffer.length || leftBuffer.length === 0) {
    return false;
  }
  return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function normalizeIncomingSnapshot(payload = {}) {
  if (payload && typeof payload === 'object' && payload.snapshot && typeof payload.snapshot === 'object') {
    return payload.snapshot;
  }

  // Backward compatibility with /_sentinel/threat-intel export shape.
  if (Array.isArray(payload?.top_signatures)) {
    return {
      node_id: String(payload?.node_id || payload?.source_node_id || 'unknown'),
      generated_at: payload?.generated_at || new Date().toISOString(),
      signatures: payload.top_signatures.map((entry) => ({
        signature: String(entry?.signature || '').toLowerCase(),
        source: String(entry?.source || 'peer'),
        reason: String(entry?.reason || 'peer_snapshot'),
        severity: String(entry?.severity || 'medium'),
        hits: Number(entry?.hits || 1),
        first_seen_at: Number(entry?.first_seen_at || 0),
        last_seen_at: Number(entry?.last_seen_at || 0),
      })),
    };
  }

  if (payload && typeof payload === 'object') {
    return payload;
  }
  return {};
}

class ThreatIntelMesh {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'block']);
    this.ttlMs = clampPositiveInt(config.ttl_ms, 7 * 24 * 60 * 60 * 1000, 60_000, 180 * 24 * 60 * 60 * 1000);
    this.maxSignatures = clampPositiveInt(config.max_signatures, 50_000, 32, 1_000_000);
    this.maxTextChars = clampPositiveInt(config.max_text_chars, 8192, 128, 262144);
    this.minHitsToBlock = clampPositiveInt(config.min_hits_to_block, 2, 1, 1000);
    this.blockOnMatch = config.block_on_match === true;
    this.allowAnonymousShare = config.allow_anonymous_share === true;
    this.allowUnsignedImport = config.allow_unsigned_import === true;
    this.maxPeerSignatures = clampPositiveInt(config.max_peer_signatures, 1000, 1, 50_000);
    this.maxPeers = clampPositiveInt(config.max_peers, 16, 1, 128);
    this.syncEnabled = config.sync_enabled === true;
    this.syncIntervalMs = clampPositiveInt(config.sync_interval_ms, 90_000, 5_000, 3_600_000);
    this.syncTimeoutMs = clampPositiveInt(config.sync_timeout_ms, 2_000, 100, 60_000);
    this.nodeId = normalizeNodeId(config.node_id || process.env.SENTINEL_NODE_ID || 'sentinel-node');
    this.sharedSecret = String(config.shared_secret || process.env.SENTINEL_MESH_SHARED_SECRET || '').trim();
    this.peers = normalizePeers(config.peers, this.maxPeers);
    this.observability = config.observability !== false;
    this.signatures = new Map();
    this.lastSyncAt = 0;
    this.lastSyncStatus = 'idle';
    this.syncRuns = 0;
    this.syncFailures = 0;
    this.syncImportedSignatures = 0;

    const bootstrap = Array.isArray(config.bootstrap_signatures) ? config.bootstrap_signatures : [];
    for (const signature of bootstrap.slice(0, 1000)) {
      const value = String(signature || '').trim().toLowerCase();
      if (value.length === 64 && /^[a-f0-9]{64}$/.test(value)) {
        this.signatures.set(value, {
          signature: value,
          source: 'bootstrap',
          reason: 'bootstrap',
          severity: 'medium',
          hits: 1,
          firstSeenAt: Date.now(),
          lastSeenAt: Date.now(),
        });
      }
    }
  }

  isEnabled() {
    return this.enabled === true;
  }

  setPeers(peers = []) {
    this.peers = normalizePeers(peers, this.maxPeers);
    return this.peers;
  }

  prune(now = Date.now()) {
    const staleBefore = Number(now) - this.ttlMs;
    for (const [signature, entry] of this.signatures.entries()) {
      if (Number(entry.lastSeenAt || 0) < staleBefore) {
        this.signatures.delete(signature);
      }
    }
    while (this.signatures.size > this.maxSignatures) {
      const oldest = this.signatures.keys().next().value;
      if (!oldest) {
        break;
      }
      this.signatures.delete(oldest);
    }
  }

  ingestSignature({
    signature = '',
    text = '',
    source = 'local',
    reason = 'observed',
    severity = 'medium',
  } = {}) {
    if (!this.isEnabled()) {
      return null;
    }
    const now = Date.now();
    this.prune(now);
    let value = String(signature || '').trim().toLowerCase();
    if (!value && text) {
      value = createFingerprints(String(text || '').slice(0, this.maxTextChars))[0] || '';
    }
    if (value.length !== 64 || !/^[a-f0-9]{64}$/.test(value)) {
      return null;
    }
    const existing = this.signatures.get(value);
    if (existing) {
      existing.hits = Number(existing.hits || 0) + 1;
      existing.lastSeenAt = now;
      existing.source = source || existing.source;
      existing.reason = reason || existing.reason;
      return existing;
    }
    const created = {
      signature: value,
      source: String(source || 'local').slice(0, 64),
      reason: String(reason || 'observed').slice(0, 160),
      severity: String(severity || 'medium').toLowerCase().slice(0, 16),
      hits: 1,
      firstSeenAt: now,
      lastSeenAt: now,
    };
    this.signatures.set(value, created);
    return created;
  }

  ingestAuditEvent(event = {}) {
    if (!this.isEnabled()) {
      return [];
    }
    const payload = event && typeof event === 'object' ? event : {};
    const reasons = Array.isArray(payload.reasons) ? payload.reasons : [];
    const updates = [];
    for (const reason of reasons.slice(0, 16)) {
      const entry = this.ingestSignature({
        text: String(reason || ''),
        source: 'audit_reason',
        reason: String(reason || 'reason'),
        severity: payload.decision && String(payload.decision).startsWith('blocked') ? 'high' : 'medium',
      });
      if (entry) {
        updates.push(entry.signature);
      }
    }
    if (typeof payload.request_body === 'string' && payload.request_body.trim()) {
      for (const signature of createFingerprints(payload.request_body.slice(0, this.maxTextChars)).slice(0, 3)) {
        const entry = this.ingestSignature({
          signature,
          source: 'audit_body',
          reason: 'request_body',
          severity: 'high',
        });
        if (entry) {
          updates.push(entry.signature);
        }
      }
    }
    return updates;
  }

  evaluate({
    bodyText = '',
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

    this.prune(Date.now());
    const fingerprints = createFingerprints(String(bodyText || '').slice(0, this.maxTextChars));
    const findings = [];
    for (const signature of fingerprints) {
      const hit = this.signatures.get(signature);
      if (!hit) {
        continue;
      }
      findings.push({
        code: 'threat_intel_signature_match',
        signature,
        source: hit.source,
        severity: hit.severity,
        reason: hit.reason,
        hits: Number(hit.hits || 0),
        blockEligible: this.blockOnMatch && Number(hit.hits || 0) >= this.minHitsToBlock,
      });
    }

    const detected = findings.length > 0;
    const shouldBlock =
      detected &&
      this.mode === 'block' &&
      String(effectiveMode || '').toLowerCase() === 'enforce' &&
      findings.some((item) => item.blockEligible === true);

    return {
      enabled: true,
      mode: this.mode,
      detected,
      shouldBlock,
      reason: detected ? String(findings[0].code || 'threat_intel_match') : 'clean',
      findings,
      signatures_checked: fingerprints.length,
      signatures_total: this.signatures.size,
    };
  }

  buildShareSnapshot({ limit = this.maxPeerSignatures } = {}) {
    const max = clampPositiveInt(limit, this.maxPeerSignatures, 1, this.maxPeerSignatures);
    const signatures = Array.from(this.signatures.values())
      .sort((a, b) => Number(b.hits || 0) - Number(a.hits || 0))
      .slice(0, max)
      .map((entry) => ({
        signature: String(entry.signature || '').toLowerCase(),
        source: String(entry.source || 'local').slice(0, 64),
        reason: String(entry.reason || 'mesh').slice(0, 160),
        severity: String(entry.severity || 'medium').slice(0, 16),
        hits: Number(entry.hits || 1),
        first_seen_at: Number(entry.firstSeenAt || 0),
        last_seen_at: Number(entry.lastSeenAt || 0),
      }));
    return {
      node_id: this.nodeId,
      generated_at: new Date().toISOString(),
      signatures,
    };
  }

  signSnapshot(snapshot = {}) {
    if (!this.sharedSecret) {
      return null;
    }
    const canonical = stableStringify(snapshot);
    const signature = crypto
      .createHmac('sha256', this.sharedSecret)
      .update(canonical, 'utf8')
      .digest('hex');
    return {
      algorithm: 'hmac-sha256',
      node_id: this.nodeId,
      payload_sha256: sha256(canonical),
      signature,
      generated_at: new Date().toISOString(),
    };
  }

  verifySnapshotEnvelope({ snapshot = {}, envelope = null } = {}) {
    if (!envelope || typeof envelope !== 'object') {
      const unsignedAllowed = this.allowAnonymousShare || this.allowUnsignedImport || !this.sharedSecret;
      return {
        valid: unsignedAllowed,
        reason: unsignedAllowed ? 'unsigned_allowed' : 'missing_envelope',
      };
    }

    if (String(envelope.algorithm || '').toLowerCase() !== 'hmac-sha256') {
      return {
        valid: false,
        reason: 'unsupported_algorithm',
      };
    }

    if (!this.sharedSecret) {
      return {
        valid: this.allowAnonymousShare || this.allowUnsignedImport,
        reason: this.allowAnonymousShare || this.allowUnsignedImport ? 'no_shared_secret' : 'shared_secret_required',
      };
    }

    const expected = this.signSnapshot(snapshot);
    if (!expected || !timingSafeHexEqual(expected.signature, String(envelope.signature || ''))) {
      return {
        valid: false,
        reason: 'signature_mismatch',
      };
    }

    return {
      valid: true,
      reason: 'ok',
    };
  }

  exportShareSnapshot(options = {}) {
    const snapshot = this.buildShareSnapshot(options);
    const envelope = this.signSnapshot(snapshot);
    return {
      snapshot,
      envelope,
    };
  }

  importSnapshot({ payload = {}, source = 'peer_sync' } = {}) {
    if (!this.isEnabled()) {
      return {
        enabled: false,
        imported: 0,
        reason: 'disabled',
      };
    }

    const snapshot = normalizeIncomingSnapshot(payload);
    const envelope = payload?.envelope || null;
    const verification = this.verifySnapshotEnvelope({ snapshot, envelope });
    if (verification.valid !== true) {
      this.syncFailures += 1;
      return {
        enabled: true,
        imported: 0,
        accepted: false,
        reason: verification.reason,
      };
    }

    const signatures = Array.isArray(snapshot?.signatures) ? snapshot.signatures : [];
    let imported = 0;
    for (const item of signatures.slice(0, this.maxPeerSignatures)) {
      const signature = String(item?.signature || '').trim().toLowerCase();
      if (signature.length !== 64 || !/^[a-f0-9]{64}$/.test(signature)) {
        continue;
      }
      const entry = this.ingestSignature({
        signature,
        source: String(source || 'peer_sync').slice(0, 64),
        reason: String(item?.reason || 'peer_sync').slice(0, 160),
        severity: String(item?.severity || 'medium').slice(0, 16),
      });
      if (!entry) {
        continue;
      }

      const incomingHits = clampPositiveInt(item?.hits, 1, 1, 1_000_000);
      entry.hits = Math.max(Number(entry.hits || 0), incomingHits);

      const firstSeen = Number(item?.first_seen_at || 0);
      if (Number.isFinite(firstSeen) && firstSeen > 0) {
        entry.firstSeenAt = entry.firstSeenAt > 0 ? Math.min(entry.firstSeenAt, firstSeen) : firstSeen;
      }

      const lastSeen = Number(item?.last_seen_at || 0);
      if (Number.isFinite(lastSeen) && lastSeen > 0) {
        entry.lastSeenAt = Math.max(Number(entry.lastSeenAt || 0), lastSeen);
      }

      imported += 1;
    }

    this.syncImportedSignatures += imported;
    this.lastSyncStatus = imported > 0 ? 'ok' : 'ok_no_changes';
    return {
      enabled: true,
      imported,
      accepted: true,
      reason: 'ok',
    };
  }

  async syncWithPeer(peer, options = {}) {
    const fetchImpl = options.fetchImpl || global.fetch;
    if (typeof fetchImpl !== 'function') {
      return {
        peer,
        ok: false,
        imported: 0,
        reason: 'fetch_unavailable',
      };
    }

    let target = '';
    try {
      target = new URL('/_sentinel/threat-intel/share', String(peer || '')).toString();
    } catch {
      return {
        peer,
        ok: false,
        imported: 0,
        reason: 'invalid_peer_url',
      };
    }

    const controller = new AbortController();
    const timeoutHandle = setTimeout(() => {
      controller.abort();
    }, this.syncTimeoutMs);

    try {
      const response = await fetchImpl(target, {
        method: 'GET',
        headers: {
          'x-sentinel-mesh-node': this.nodeId,
        },
        signal: controller.signal,
      });
      if (!response.ok) {
        return {
          peer,
          ok: false,
          imported: 0,
          reason: `peer_http_${response.status}`,
        };
      }
      const body = await response.json();
      const result = this.importSnapshot({
        payload: body,
        source: `peer:${new URL(target).host}`,
      });
      return {
        peer,
        ok: result.accepted === true,
        imported: Number(result.imported || 0),
        reason: String(result.reason || 'ok'),
      };
    } catch (error) {
      return {
        peer,
        ok: false,
        imported: 0,
        reason: error && error.name === 'AbortError' ? 'peer_timeout' : 'peer_fetch_error',
      };
    } finally {
      clearTimeout(timeoutHandle);
    }
  }

  async syncWithPeers(options = {}) {
    if (!this.isEnabled()) {
      return {
        enabled: false,
        executed: false,
        reason: 'disabled',
      };
    }

    if (this.syncEnabled !== true || this.peers.length === 0) {
      return {
        enabled: true,
        executed: false,
        reason: this.syncEnabled ? 'no_peers' : 'sync_disabled',
      };
    }

    const peers = this.peers.slice(0, this.maxPeers);
    const results = [];
    let importedSignatures = 0;
    let failedPeers = 0;

    for (const peer of peers) {
      // Sequential by design to preserve predictable local resource usage.
      const result = await this.syncWithPeer(peer, options);
      results.push(result);
      importedSignatures += Number(result.imported || 0);
      if (result.ok !== true) {
        failedPeers += 1;
      }
    }

    this.syncRuns += 1;
    this.lastSyncAt = Date.now();
    this.lastSyncStatus = failedPeers > 0 ? 'degraded' : 'ok';
    this.syncFailures += failedPeers;

    return {
      enabled: true,
      executed: true,
      peers_total: peers.length,
      failed_peers: failedPeers,
      imported_signatures: importedSignatures,
      last_sync_at: this.lastSyncAt,
      status: this.lastSyncStatus,
      results,
    };
  }

  exportSnapshot() {
    const top = Array.from(this.signatures.values())
      .sort((a, b) => Number(b.hits || 0) - Number(a.hits || 0))
      .slice(0, 32)
      .map((entry) => ({
        signature: entry.signature,
        source: entry.source,
        reason: entry.reason,
        severity: entry.severity,
        hits: Number(entry.hits || 0),
        first_seen_at: Number(entry.firstSeenAt || 0),
        last_seen_at: Number(entry.lastSeenAt || 0),
      }));

    return {
      enabled: this.isEnabled(),
      mode: this.mode,
      node_id: this.nodeId,
      signatures_total: this.signatures.size,
      allow_anonymous_share: this.allowAnonymousShare,
      sync_enabled: this.syncEnabled,
      peers_total: this.peers.length,
      sync_interval_ms: this.syncIntervalMs,
      last_sync_at: this.lastSyncAt > 0 ? this.lastSyncAt : null,
      last_sync_status: this.lastSyncStatus,
      sync_runs: this.syncRuns,
      sync_failures: this.syncFailures,
      sync_imported_signatures: this.syncImportedSignatures,
      top_signatures: top,
    };
  }
}

module.exports = {
  ThreatIntelMesh,
};
