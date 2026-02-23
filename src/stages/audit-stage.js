const { classifyEvent } = require('../governance/atlas-tracker');

function enrichAuditPayload(server, payload = {}) {
  const event =
    payload && typeof payload === 'object' && !Array.isArray(payload)
      ? { ...payload }
      : { value: String(payload ?? '') };

  if (!event.timestamp) {
    event.timestamp = new Date().toISOString();
  }

  const atlas = classifyEvent(event);
  event.atlas = {
    mapping_version: atlas.mapping_version,
    engine: atlas.engine,
    technique_id: atlas.technique_id,
    tactic: atlas.tactic,
    name: atlas.name,
    severity: atlas.severity,
  };

  return event;
}

function resolveAuditWriter(server) {
  if (typeof server?.rawAuditWrite === 'function') {
    return server.rawAuditWrite;
  }
  if (server?.auditLogger && typeof server.auditLogger.write === 'function') {
    return server.auditLogger.write.bind(server.auditLogger);
  }
  throw new Error('audit_writer_unavailable');
}

function writeAudit(server, payload) {
  const writer = resolveAuditWriter(server);
  const enriched = enrichAuditPayload(server, payload);
  return writer(enriched);
}

function writeAuditAndStatus(server, payload) {
  writeAudit(server, payload);
  server.writeStatus();
}

module.exports = {
  enrichAuditPayload,
  writeAudit,
  writeAuditAndStatus,
};
