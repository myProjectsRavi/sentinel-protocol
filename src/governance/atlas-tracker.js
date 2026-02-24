const MAPPING_VERSION = '2026.02.23';
const MAX_REASON_ITEMS = 32;
const MAX_REASON_CHARS = 160;
const MAX_DECISION_CHARS = 160;
const MAX_JOINED_REASON_CHARS = 2048;

const UNMAPPED_CLASSIFICATION = Object.freeze({
  mapping_version: MAPPING_VERSION,
  engine: 'unknown',
  technique_id: 'UNMAPPED',
  tactic: 'UNMAPPED',
  name: 'Unmapped Sentinel Detection',
  severity: 'low',
});

const ENGINE_TECHNIQUE_MAP = Object.freeze({
  injection_scanner: Object.freeze({
    technique_id: 'AML.T0051.000',
    tactic: 'Prompt Injection',
    name: 'Direct and Obfuscated Prompt Injection',
    severity: 'high',
  }),
  neural_injection_classifier: Object.freeze({
    technique_id: 'AML.T0051.000',
    tactic: 'Prompt Injection',
    name: 'Neural Prompt Injection Detection',
    severity: 'high',
  }),
  prompt_rebuff: Object.freeze({
    technique_id: 'AML.T0051.000',
    tactic: 'Prompt Injection',
    name: 'Correlated Prompt Injection Confidence',
    severity: 'high',
  }),
  pii_scanner: Object.freeze({
    technique_id: 'AML.T0044.000',
    tactic: 'Exfiltration',
    name: 'Sensitive Data Exfiltration Attempt',
    severity: 'high',
  }),
  mcp_poisoning_detector: Object.freeze({
    technique_id: 'AML.T0018.000',
    tactic: 'Supply Chain',
    name: 'Tool and Context Poisoning',
    severity: 'high',
  }),
  synthetic_poisoner: Object.freeze({
    technique_id: 'AML.T0020.000',
    tactic: 'Poisoning',
    name: 'Synthetic Training Data Poisoning Signal',
    severity: 'medium',
  }),
  agentic_threat_shield: Object.freeze({
    technique_id: 'AML.T0016.000',
    tactic: 'Execution',
    name: 'Unauthorized Agent Delegation and Looping',
    severity: 'high',
  }),
  a2a_card_verifier: Object.freeze({
    technique_id: 'AML.T0014.000',
    tactic: 'Credential Access',
    name: 'Agent Identity Card Tampering',
    severity: 'high',
  }),
  consensus_protocol: Object.freeze({
    technique_id: 'AML.T0016.000',
    tactic: 'Execution',
    name: 'Multi-Agent Quorum Failure',
    severity: 'medium',
  }),
  cross_tenant_isolator: Object.freeze({
    technique_id: 'AML.T0044.000',
    tactic: 'Exfiltration',
    name: 'Cross-Tenant Data Boundary Violation',
    severity: 'high',
  }),
  cold_start_analyzer: Object.freeze({
    technique_id: 'AML.T0034.000',
    tactic: 'Impact',
    name: 'Cold Start Security Degradation',
    severity: 'medium',
  }),
  stego_exfil_detector: Object.freeze({
    technique_id: 'AML.T0044.000',
    tactic: 'Exfiltration',
    name: 'Steganographic Data Exfiltration',
    severity: 'high',
  }),
  reasoning_trace_monitor: Object.freeze({
    technique_id: 'AML.T0051.000',
    tactic: 'Prompt Injection',
    name: 'Reasoning Trace Injection and Drift',
    severity: 'high',
  }),
  hallucination_tripwire: Object.freeze({
    technique_id: 'AML.T0043.000',
    tactic: 'Evasion',
    name: 'High-Risk Hallucination Signal',
    severity: 'medium',
  }),
  semantic_drift_canary: Object.freeze({
    technique_id: 'AML.T0034.000',
    tactic: 'Impact',
    name: 'Model Drift and Silent Swap Signal',
    severity: 'medium',
  }),
  output_provenance: Object.freeze({
    technique_id: 'AML.T0014.000',
    tactic: 'Credential Access',
    name: 'Output Provenance Integrity Failure',
    severity: 'medium',
  }),
  compute_attestation: Object.freeze({
    technique_id: 'AML.T0014.000',
    tactic: 'Credential Access',
    name: 'Runtime Attestation Integrity Failure',
    severity: 'medium',
  }),
  loop_breaker: Object.freeze({
    technique_id: 'AML.T0016.000',
    tactic: 'Execution',
    name: 'Runaway Agent Loop Control',
    severity: 'medium',
  }),
  intent_throttle: Object.freeze({
    technique_id: 'AML.T0016.000',
    tactic: 'Execution',
    name: 'High-Risk Repetition Throttling',
    severity: 'medium',
  }),
  intent_drift: Object.freeze({
    technique_id: 'AML.T0034.000',
    tactic: 'Impact',
    name: 'Objective Drift and Goal Hijack',
    severity: 'medium',
  }),
  canary_tool_trap: Object.freeze({
    technique_id: 'AML.T0026.000',
    tactic: 'Discovery',
    name: 'Unauthorized Tool Call Discovery',
    severity: 'medium',
  }),
  entropy_analyzer: Object.freeze({
    technique_id: 'AML.T0044.000',
    tactic: 'Exfiltration',
    name: 'High-Entropy Secret Exfiltration',
    severity: 'high',
  }),
  serialization_firewall: Object.freeze({
    technique_id: 'AML.T0017.000',
    tactic: 'Execution',
    name: 'Serialization and Deserialization Exploit Attempt',
    severity: 'high',
  }),
  context_integrity_guardian: Object.freeze({
    technique_id: 'AML.T0034.000',
    tactic: 'Impact',
    name: 'Context Window Integrity Degradation',
    severity: 'medium',
  }),
  tool_schema_validator: Object.freeze({
    technique_id: 'AML.T0018.000',
    tactic: 'Supply Chain',
    name: 'Tool Schema Exploitation and Privilege Escalation',
    severity: 'high',
  }),
  multimodal_injection_shield: Object.freeze({
    technique_id: 'AML.T0051.000',
    tactic: 'Prompt Injection',
    name: 'Multimodal Input Injection Payload',
    severity: 'high',
  }),
  supply_chain_validator: Object.freeze({
    technique_id: 'AML.T0018.000',
    tactic: 'Supply Chain',
    name: 'Dependency and Lockfile Integrity Drift',
    severity: 'high',
  }),
  sandbox_enforcer: Object.freeze({
    technique_id: 'AML.T0017.000',
    tactic: 'Execution',
    name: 'Sandbox Boundary Escape Attempt',
    severity: 'high',
  }),
  memory_integrity_monitor: Object.freeze({
    technique_id: 'AML.T0020.000',
    tactic: 'Poisoning',
    name: 'Agent Memory Integrity and Chain Tampering',
    severity: 'high',
  }),
  output_classifier: Object.freeze({
    technique_id: 'AML.T0043.000',
    tactic: 'Evasion',
    name: 'Adversarial Output Evasion Signal',
    severity: 'medium',
  }),
  adversarial_robustness: Object.freeze({
    technique_id: 'AML.T0043.000',
    tactic: 'Evasion',
    name: 'Adversarial Prompt Evasion and Smuggling',
    severity: 'medium',
  }),
  model_inversion_guard: Object.freeze({
    technique_id: 'AML.T0049.000',
    tactic: 'Exfiltration',
    name: 'Model Inversion and Training Data Reconstruction',
    severity: 'high',
  }),
  shadow_os: Object.freeze({
    technique_id: 'AML.T0016.000',
    tactic: 'Execution',
    name: 'Tool Sequence Abuse',
    severity: 'high',
  }),
  omni_shield: Object.freeze({
    technique_id: 'AML.T0051.000',
    tactic: 'Prompt Injection',
    name: 'Multimodal Prompt Injection',
    severity: 'high',
  }),
  experimental_sandbox: Object.freeze({
    technique_id: 'AML.T0017.000',
    tactic: 'Execution',
    name: 'Unsafe Code Execution Payload',
    severity: 'high',
  }),
  swarm_protocol: Object.freeze({
    technique_id: 'AML.T0014.000',
    tactic: 'Credential Access',
    name: 'Replay and Envelope Integrity Attack',
    severity: 'medium',
  }),
  policy_engine: Object.freeze({
    technique_id: 'AML.T0051.000',
    tactic: 'Prompt Injection',
    name: 'Policy-Detected Prompt Injection',
    severity: 'high',
  }),
});

const ENGINE_PRIORITY = Object.freeze([
  'prompt_rebuff',
  'agentic_threat_shield',
  'a2a_card_verifier',
  'consensus_protocol',
  'cross_tenant_isolator',
  'serialization_firewall',
  'tool_schema_validator',
  'memory_integrity_monitor',
  'sandbox_enforcer',
  'supply_chain_validator',
  'multimodal_injection_shield',
  'context_integrity_guardian',
  'stego_exfil_detector',
  'reasoning_trace_monitor',
  'hallucination_tripwire',
  'semantic_drift_canary',
  'output_provenance',
  'compute_attestation',
  'cold_start_analyzer',
  'mcp_poisoning_detector',
  'synthetic_poisoner',
  'model_inversion_guard',
  'injection_scanner',
  'pii_scanner',
  'output_classifier',
  'adversarial_robustness',
  'entropy_analyzer',
  'loop_breaker',
  'intent_drift',
  'intent_throttle',
  'canary_tool_trap',
  'shadow_os',
  'omni_shield',
  'experimental_sandbox',
  'swarm_protocol',
  'policy_engine',
  'neural_injection_classifier',
]);

function normalizeEngineName(value) {
  const normalized = String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_]+/g, '_')
    .replace(/^_+|_+$/g, '');
  return normalized || 'unknown';
}

function normalizeReasonList(event = {}) {
  if (Array.isArray(event.reasons)) {
    const out = [];
    for (let i = 0; i < event.reasons.length && out.length < MAX_REASON_ITEMS; i += 1) {
      const normalized = String(event.reasons[i] || '')
        .toLowerCase()
        .slice(0, MAX_REASON_CHARS);
      if (normalized) {
        out.push(normalized);
      }
    }
    return out;
  }
  if (event.reason !== undefined) {
    const reason = String(event.reason || '')
      .toLowerCase()
      .slice(0, MAX_REASON_CHARS);
    return reason ? [reason] : [];
  }
  return [];
}

function inferEngineCandidates(event = {}) {
  const candidates = new Set();
  const decision = String(event.decision || '')
    .toLowerCase()
    .slice(0, MAX_DECISION_CHARS);
  const reasons = normalizeReasonList(event);
  const joinedReasons = reasons.join(',').slice(0, MAX_JOINED_REASON_CHARS);

  if (event.engine) {
    candidates.add(normalizeEngineName(event.engine));
  }
  if (decision.includes('prompt_rebuff')) {
    candidates.add('prompt_rebuff');
  }
  if (decision.includes('agentic')) {
    candidates.add('agentic_threat_shield');
  }
  if (decision.includes('a2a_card')) {
    candidates.add('a2a_card_verifier');
  }
  if (decision.includes('consensus')) {
    candidates.add('consensus_protocol');
  }
  if (decision.includes('cross_tenant')) {
    candidates.add('cross_tenant_isolator');
  }
  if (decision.includes('cold_start')) {
    candidates.add('cold_start_analyzer');
  }
  if (decision.includes('stego')) {
    candidates.add('stego_exfil_detector');
  }
  if (decision.includes('reasoning_trace')) {
    candidates.add('reasoning_trace_monitor');
  }
  if (decision.includes('hallucination')) {
    candidates.add('hallucination_tripwire');
  }
  if (decision.includes('semantic_drift')) {
    candidates.add('semantic_drift_canary');
  }
  if (decision.includes('provenance')) {
    candidates.add('output_provenance');
  }
  if (decision.includes('attestation')) {
    candidates.add('compute_attestation');
  }
  if (decision.includes('mcp_poisoning')) {
    candidates.add('mcp_poisoning_detector');
  }
  if (decision.includes('serialization_firewall')) {
    candidates.add('serialization_firewall');
  }
  if (decision.includes('context_integrity')) {
    candidates.add('context_integrity_guardian');
  }
  if (decision.includes('tool_schema')) {
    candidates.add('tool_schema_validator');
  }
  if (decision.includes('multimodal_injection')) {
    candidates.add('multimodal_injection_shield');
  }
  if (decision.includes('supply_chain')) {
    candidates.add('supply_chain_validator');
  }
  if (decision.includes('sandbox_enforcer')) {
    candidates.add('sandbox_enforcer');
  }
  if (decision.includes('memory_integrity')) {
    candidates.add('memory_integrity_monitor');
  }
  if (decision.includes('synthetic_poisoning')) {
    candidates.add('synthetic_poisoner');
  }
  if (decision.includes('output_classifier')) {
    candidates.add('output_classifier');
  }
  if (decision.includes('adversarial')) {
    candidates.add('adversarial_robustness');
  }
  if (decision.includes('model_inversion')) {
    candidates.add('model_inversion_guard');
  }
  if (decision.includes('loop')) {
    candidates.add('loop_breaker');
  }
  if (decision.includes('shadow_os')) {
    candidates.add('shadow_os');
  }
  if (decision.includes('omni_shield')) {
    candidates.add('omni_shield');
  }
  if (decision.includes('sandbox')) {
    candidates.add('experimental_sandbox');
  }
  if (decision.includes('swarm')) {
    candidates.add('swarm_protocol');
  }
  if (decision.includes('entropy')) {
    candidates.add('entropy_analyzer');
  }
  if (decision.includes('canary')) {
    candidates.add('canary_tool_trap');
  }

  if (reasons.some((item) => item.startsWith('injection:') || item.includes('prompt_injection'))) {
    candidates.add('injection_scanner');
  }
  if (reasons.some((item) => item.startsWith('prompt_rebuff:'))) {
    candidates.add('prompt_rebuff');
  }
  if (reasons.some((item) => item.startsWith('a2a_card:'))) {
    candidates.add('a2a_card_verifier');
  }
  if (reasons.some((item) => item.startsWith('consensus:'))) {
    candidates.add('consensus_protocol');
  }
  if (reasons.some((item) => item.startsWith('cross_tenant:'))) {
    candidates.add('cross_tenant_isolator');
  }
  if (reasons.some((item) => item.startsWith('cold_start:'))) {
    candidates.add('cold_start_analyzer');
  }
  if (reasons.some((item) => item.startsWith('stego:'))) {
    candidates.add('stego_exfil_detector');
  }
  if (reasons.some((item) => item.startsWith('reasoning:'))) {
    candidates.add('reasoning_trace_monitor');
  }
  if (reasons.some((item) => item.startsWith('hallucination:'))) {
    candidates.add('hallucination_tripwire');
  }
  if (reasons.some((item) => item.startsWith('semantic_drift:'))) {
    candidates.add('semantic_drift_canary');
  }
  if (reasons.some((item) => item.startsWith('mcp_poisoning:'))) {
    candidates.add('mcp_poisoning_detector');
  }
  if (reasons.some((item) => item.startsWith('serialization_firewall:'))) {
    candidates.add('serialization_firewall');
  }
  if (reasons.some((item) => item.startsWith('context_integrity:'))) {
    candidates.add('context_integrity_guardian');
  }
  if (reasons.some((item) => item.startsWith('tool_schema:'))) {
    candidates.add('tool_schema_validator');
  }
  if (reasons.some((item) => item.startsWith('multimodal_injection:'))) {
    candidates.add('multimodal_injection_shield');
  }
  if (reasons.some((item) => item.startsWith('supply_chain:'))) {
    candidates.add('supply_chain_validator');
  }
  if (reasons.some((item) => item.startsWith('sandbox_enforcer:'))) {
    candidates.add('sandbox_enforcer');
  }
  if (reasons.some((item) => item.startsWith('memory_integrity:'))) {
    candidates.add('memory_integrity_monitor');
  }
  if (reasons.some((item) => item.startsWith('synthetic_poisoning:'))) {
    candidates.add('synthetic_poisoner');
  }
  if (reasons.some((item) => item.startsWith('output_classifier:'))) {
    candidates.add('output_classifier');
  }
  if (reasons.some((item) => item.includes('adversarial_example') || item.includes('evasion'))) {
    candidates.add('adversarial_robustness');
  }
  if (reasons.some((item) => item.includes('model_inversion') || item.includes('embedding_reconstruction'))) {
    candidates.add('model_inversion_guard');
  }
  if (reasons.some((item) => item.startsWith('agentic:'))) {
    candidates.add('agentic_threat_shield');
  }
  if (reasons.some((item) => item.startsWith('pii:') || item.includes('egress_pii'))) {
    candidates.add('pii_scanner');
  }
  if (reasons.some((item) => item.includes('entropy'))) {
    candidates.add('entropy_analyzer');
  }
  if (reasons.some((item) => item.startsWith('intent_drift:'))) {
    candidates.add('intent_drift');
  }
  if (reasons.some((item) => item.startsWith('intent_throttle:'))) {
    candidates.add('intent_throttle');
  }
  if (joinedReasons.includes('canary_tool')) {
    candidates.add('canary_tool_trap');
  }
  if (joinedReasons.includes('policy:') || joinedReasons.includes('prompt_injection_detected')) {
    candidates.add('policy_engine');
  }

  return Array.from(candidates);
}

function pickPrimaryEngine(candidates = []) {
  if (!Array.isArray(candidates) || candidates.length === 0) {
    return 'unknown';
  }
  const normalized = candidates.map((item) => normalizeEngineName(item));
  for (const preferred of ENGINE_PRIORITY) {
    if (normalized.includes(preferred)) {
      return preferred;
    }
  }
  return normalized.sort((a, b) => a.localeCompare(b))[0] || 'unknown';
}

function classifyEngine(engineName) {
  const normalized = normalizeEngineName(engineName);
  const mapped = ENGINE_TECHNIQUE_MAP[normalized];
  if (!mapped) {
    return {
      ...UNMAPPED_CLASSIFICATION,
      engine: normalized,
    };
  }
  return {
    mapping_version: MAPPING_VERSION,
    engine: normalized,
    technique_id: mapped.technique_id,
    tactic: mapped.tactic,
    name: mapped.name,
    severity: mapped.severity,
  };
}

function classifyEvent(event = {}) {
  if (event && event.atlas && typeof event.atlas === 'object') {
    const techniqueId = String(event.atlas.technique_id || '');
    if (techniqueId) {
      return {
        mapping_version: String(event.atlas.mapping_version || MAPPING_VERSION),
        engine: normalizeEngineName(event.atlas.engine || event.engine || 'unknown'),
        technique_id: techniqueId,
        tactic: String(event.atlas.tactic || 'UNMAPPED'),
        name: String(event.atlas.name || 'Unmapped Sentinel Detection'),
        severity: String(event.atlas.severity || 'low'),
      };
    }
  }

  const candidates = inferEngineCandidates(event);
  const primaryEngine = pickPrimaryEngine(candidates);
  return classifyEngine(primaryEngine);
}

function aggregateByTechnique(events = []) {
  const bucket = new Map();
  for (const event of events) {
    const classification = classifyEvent(event);
    const key = classification.technique_id || 'UNMAPPED';
    const existing = bucket.get(key) || {
      technique_id: key,
      tactic: classification.tactic || 'UNMAPPED',
      name: classification.name || 'Unmapped Sentinel Detection',
      severity: classification.severity || 'low',
      count: 0,
      engines: new Set(),
    };
    existing.count += 1;
    existing.engines.add(classification.engine || 'unknown');
    bucket.set(key, existing);
  }

  return Array.from(bucket.values())
    .map((item) => ({
      technique_id: item.technique_id,
      tactic: item.tactic,
      name: item.name,
      severity: item.severity,
      count: item.count,
      engines: Array.from(item.engines).sort((a, b) => a.localeCompare(b)),
    }))
    .sort((left, right) => {
      if (right.count !== left.count) {
        return right.count - left.count;
      }
      return String(left.technique_id).localeCompare(String(right.technique_id));
    });
}

function summarizeAtlas(events = [], options = {}) {
  const safeTop = Math.max(1, Math.floor(Number(options.topLimit || 10)));
  const techniques = aggregateByTechnique(events);
  const total = events.length;
  const unmapped = techniques
    .filter((item) => item.technique_id === 'UNMAPPED')
    .reduce((sum, item) => sum + Number(item.count || 0), 0);
  return {
    mapping_version: MAPPING_VERSION,
    total_events: total,
    mapped_events: Math.max(0, total - unmapped),
    unmapped_events: unmapped,
    top_techniques: techniques.slice(0, safeTop),
  };
}

function exportNavigatorPayload(events = [], options = {}) {
  const techniques = aggregateByTechnique(events);
  const payload = {
    schema_version: 'sentinel.atlas.navigator.v1',
    mapping_version: MAPPING_VERSION,
    total_events: events.length,
    techniques,
  };
  if (options && options.source && typeof options.source === 'object') {
    payload.source = {
      audit_path: String(options.source.audit_path || ''),
      limit: Number.isFinite(Number(options.source.limit)) ? Number(options.source.limit) : undefined,
    };
  }
  return payload;
}

class AtlasTracker {
  classifyEngine(engineName) {
    return classifyEngine(engineName);
  }

  classifyEvent(event) {
    return classifyEvent(event);
  }

  aggregateByTechnique(events) {
    return aggregateByTechnique(events);
  }

  summarize(events, options = {}) {
    return summarizeAtlas(events, options);
  }

  exportNavigatorPayload(events, options = {}) {
    return exportNavigatorPayload(events, options);
  }
}

module.exports = {
  MAPPING_VERSION,
  ENGINE_TECHNIQUE_MAP,
  UNMAPPED_CLASSIFICATION,
  AtlasTracker,
  classifyEngine,
  classifyEvent,
  aggregateByTechnique,
  summarizeAtlas,
  exportNavigatorPayload,
};
