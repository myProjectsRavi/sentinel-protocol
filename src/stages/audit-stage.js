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
  if (server?.evidenceVault?.isEnabled?.()) {
    const record = server.evidenceVault.append({
      timestamp: enriched.timestamp,
      control: enriched?.atlas?.engine || 'unknown',
      outcome: enriched.decision || 'observed',
      details: {
        reason: enriched.reasons?.[0] || enriched.reason || 'n/a',
        provider: enriched.provider || 'unknown',
        status: enriched.response_status,
      },
    });
    if (record) {
      server.stats.evidence_vault_entries += 1;
    }
  }
  if (server?.threatPropagationGraph?.isEnabled?.()) {
    server.threatPropagationGraph.ingest(enriched);
    server.stats.threat_graph_events += 1;
  }
  if (server?.attackCorpusEvolver?.isEnabled?.()) {
    const candidate = server.attackCorpusEvolver.ingestAuditEvent(enriched);
    if (candidate) {
      server.stats.attack_corpus_candidates += 1;
    }
  }
  if (server?.forensicDebugger?.isEnabled?.()) {
    const summaryOnly = server.config?.runtime?.forensic_debugger?.default_summary_only !== false;
    server.forensicDebugger.capture({
      request: {
        method: enriched.method || 'UNKNOWN',
        path: enriched.path || enriched.target_path || '',
        headers: enriched.request_headers || {},
        body: enriched.request_body || {},
      },
      decision: {
        decision: enriched.decision,
        reason: enriched.reasons?.[0] || enriched.reason || '',
        provider: enriched.provider,
        response_status: enriched.response_status,
        injection_score: enriched.injection_score || enriched.prompt_rebuff_score || 0,
      },
      configVersion: Number(server.config?.version || 1),
      summaryOnly,
    });
  }
  if (server?.budgetAutopilot?.isEnabled?.()) {
    const chargedUsd = Number(enriched?.budget_charged_usd || 0);
    const latencyMs = Number(enriched?.duration_ms || 0);
    if (Number.isFinite(latencyMs) && latencyMs >= 0) {
      server.budgetAutopilot.observe({
        provider: enriched.provider || 'unknown',
        latencyMs,
        costUsd: Number.isFinite(chargedUsd) && chargedUsd >= 0 ? chargedUsd : 0,
      });
    }
  }
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
