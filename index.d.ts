import type { IncomingMessage, Server as HttpServer, ServerResponse } from 'node:http';

export type SentinelMode = 'monitor' | 'warn' | 'enforce' | 'block' | 'active' | (string & {});

export interface SentinelProxyConfig {
  host?: string;
  port?: number;
  timeout_ms?: number;
  max_body_bytes?: number;
  [key: string]: unknown;
}

export interface SentinelConfig {
  version?: number;
  mode?: SentinelMode;
  proxy?: SentinelProxyConfig;
  runtime?: Record<string, unknown>;
  pii?: Record<string, unknown>;
  injection?: Record<string, unknown>;
  rules?: Array<Record<string, unknown>>;
  whitelist?: Record<string, unknown>;
  logging?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface LoadedConfigResult {
  config: SentinelConfig;
  [key: string]: unknown;
}

export interface DoctorCheck {
  id: string;
  status: 'pass' | 'warn' | 'fail';
  message: string;
  [key: string]: unknown;
}

export interface DoctorReport {
  ok: boolean;
  checks: DoctorCheck[];
  summary: {
    pass: number;
    warn: number;
    fail: number;
  };
  [key: string]: unknown;
}

export interface DoctorServerResult {
  loaded: LoadedConfigResult;
  report: DoctorReport;
  formatted: string;
}

export interface EmergencyOverridePayload {
  emergency_open: boolean;
  updated_at: string | null;
}

export interface SentinelStatusPayload {
  service_status: string;
  configured_mode?: string;
  effective_mode?: string;
  emergency_open?: boolean;
  providers?: Record<string, Record<string, unknown>>;
  counters?: Record<string, number>;
  [key: string]: unknown;
}

export interface SentinelBlockDecision {
  statusCode: number;
  body?: unknown;
  headers?: Record<string, string>;
  reason?: string;
}

export interface SentinelPipelineContext {
  req?: IncomingMessage | null;
  res?: ServerResponse | null;
  server?: SentinelServerInstance | null;
  correlationId?: string | null;
  requestStart?: number;
  warnings?: string[];
  shortCircuit?: SentinelBlockDecision | null;
  set(key: string, value: unknown): this;
  get<T = unknown>(key: string, fallback?: T): T;
  setTag(key: string, value: unknown): this;
  warn(message: string): this;
  block(options?: Partial<SentinelBlockDecision>): SentinelBlockDecision;
  isBlocked(): boolean;
}

export interface SentinelPlugin {
  name: string;
  version?: string;
  description?: string;
  priority?: number;
  critical?: boolean;
  hooks?: Record<string, (context: SentinelPipelineContext) => void | Promise<void>>;
  setup?: (deps: { logger?: Console }) => void;
}

export type SentinelMiddleware = (req: IncomingMessage, res: ServerResponse, next?: (error?: Error) => void) => void;

export interface SentinelExpressApp extends SentinelMiddleware {
  use(...args: unknown[]): unknown;
  get(...args: unknown[]): unknown;
  post(...args: unknown[]): unknown;
  all(...args: unknown[]): unknown;
  listen(...args: unknown[]): HttpServer;
}

export interface SentinelServerInstance {
  app: SentinelExpressApp;
  start(): HttpServer;
  stop(): Promise<void>;
  use(plugin: SentinelPlugin): this;
  currentStatusPayload?(): SentinelStatusPayload;
}

export interface EmbeddedScanFinding {
  id: string;
  severity: string;
  value?: string;
  start?: number;
  end?: number;
  [key: string]: unknown;
}

export interface EmbeddedScanResult {
  pii: {
    findings: EmbeddedScanFinding[];
    redactedText: string;
    highestSeverity: string | null;
    scanTruncated: boolean;
    [key: string]: unknown;
  };
  provider: {
    providerMode: string;
    providerUsed: string;
    fallbackUsed: boolean;
    fallbackReason?: string | null;
    [key: string]: unknown;
  };
}

export interface EmbeddedSecureFetchOptions {
  method?: string;
  headers?: Record<string, string> | Array<[string, string]>;
  body?: unknown;
  fetchImpl?: (url: string, options?: unknown) => Promise<unknown>;
  [key: string]: unknown;
}

export interface EmbeddedLangChainCallback {
  handleLLMStart(llm: unknown, prompts?: string[], runId?: string): Promise<void>;
  handleLLMEnd(output: unknown, runId?: string): Promise<void>;
  handleLLMError(error: unknown, runId?: string): Promise<void>;
}

export interface EmbeddedLlamaIndexCallback {
  onStart(meta?: Record<string, unknown>): Promise<void>;
  onComplete(meta?: Record<string, unknown>): Promise<void>;
  onError(error: unknown, meta?: Record<string, unknown>): Promise<void>;
}

export interface EmbeddedFrameworkCallbacks {
  langchainCallback(): EmbeddedLangChainCallback;
  llamaIndexCallback(): EmbeddedLlamaIndexCallback;
}

export interface EmbeddedSentinel {
  app: SentinelExpressApp;
  server: SentinelServerInstance;
  use(plugin: SentinelPlugin): EmbeddedSentinel;
  middleware(): SentinelMiddleware;
  secureFetch(url: string, options?: EmbeddedSecureFetchOptions): Promise<unknown>;
  frameworkCallbacks(): EmbeddedFrameworkCallbacks;
  langchainCallback(): EmbeddedLangChainCallback;
  llamaIndexCallback(): EmbeddedLlamaIndexCallback;
  start(): HttpServer;
  stop(): Promise<void>;
  scan(payload: unknown, requestHeaders?: Record<string, string>): Promise<EmbeddedScanResult>;
}

export interface SentinelEmbedOptions {
  dryRun?: boolean;
  failOpen?: boolean;
  portOverride?: number;
  plugin?: SentinelPlugin;
  plugins?: SentinelPlugin[];
  [key: string]: unknown;
}

export interface StartServerOptions {
  configPath?: string;
  modeOverride?: SentinelMode;
  vcrMode?: string;
  dashboardEnabled?: boolean;
  runDoctor?: boolean;
  dryRun?: boolean;
  failOpen?: boolean;
  port?: number | string;
  installSignalHandlers?: boolean;
  shutdownTimeoutMs?: number;
}

export interface StartServerResult {
  server: SentinelServerInstance;
  loaded: LoadedConfigResult;
  doctor: DoctorReport | null;
}

export type StopServerResult =
  | {
      stopped: true;
      pid: number;
    }
  | {
      stopped: false;
      message: string;
      pid?: number;
    };

export interface PolicyBundlePayload {
  version: number;
  created_at: string;
  issuer: string;
  key_id: string;
  config: Record<string, unknown>;
}

export interface SignedPolicyBundle extends PolicyBundlePayload {
  algorithm: 'ed25519';
  signature: string;
  payload_sha256: string;
}

export interface PolicyBundleVerifyResult {
  valid: boolean;
  reason: string;
  config: Record<string, unknown> | null;
  payload_sha256?: string;
}

export class PolicyBundle {
  static create(
    config: Record<string, unknown>,
    options?: { createdAt?: string; issuer?: string; keyId?: string }
  ): PolicyBundlePayload;
  static payloadForSigning(bundle: PolicyBundlePayload): Buffer;
  static sign(
    configOrBundle: Record<string, unknown> | PolicyBundlePayload,
    privateKey: string | object,
    options?: { createdAt?: string; issuer?: string; keyId?: string }
  ): SignedPolicyBundle;
  static verify(bundle: SignedPolicyBundle, publicKey: string | object): PolicyBundleVerifyResult;
}

export type RedTeamCaseType = 'injection' | 'exfiltration' | string;

export interface RedTeamCaseInput {
  prompt: string;
  vector?: string;
}

export interface RedTeamCaseResult {
  type: RedTeamCaseType;
  vector?: string;
  prompt: string;
  blocked: boolean;
  status_code: number;
  error?: string;
}

export interface RedTeamCampaignSummary {
  total: number;
  blocked: number;
  allowed: number;
  score_percent: number;
  request_errors: number;
  status_codes: Record<string, number>;
  vector_coverage: Record<string, number>;
}

export interface RedTeamCampaignBreakdown {
  injection_total: number;
  exfiltration_total: number;
  injection: RedTeamCampaignSummary;
  exfiltration: RedTeamCampaignSummary;
}

export interface RedTeamEngineConfig {
  targetPath?: string;
  target?: string;
  model?: string;
  timeoutMs?: number;
  maxInjectionCases?: number;
  maxExfilCases?: number;
}

export interface RedTeamSuiteResult {
  generated_at: string;
  total_tests: number;
  blocked_tests: number;
  score_percent: number;
  request_errors?: number;
  status_codes?: Record<string, number>;
  campaigns?: RedTeamCampaignBreakdown;
  results: RedTeamCaseResult[];
}

export class RedTeamEngine {
  constructor(sentinelBaseUrl?: string, config?: RedTeamEngineConfig);
  runInjectionCampaign(cases?: Array<string | RedTeamCaseInput>): Promise<RedTeamCaseResult[]>;
  runExfiltrationCampaign(cases?: Array<string | RedTeamCaseInput>): Promise<RedTeamCaseResult[]>;
  runFullSuite(): Promise<RedTeamSuiteResult>;
}

export interface ComplianceLoadOptions {
  limit?: number;
  maxReadBytes?: number;
  chunkReadBytes?: number;
}

export interface ComplianceReadMetadata {
  limit: number;
  bytes_scanned: number;
  truncated: boolean;
  lines_scanned: number;
  lines_considered: number;
  parsed_events: number;
  malformed_lines: number;
  tail_sha256: string | null;
  window_sha256: string | null;
}

export interface ComplianceLoadResult {
  events: Array<Record<string, unknown>>;
  metadata: ComplianceReadMetadata;
}

export interface ComplianceReasonCount {
  reason: string;
  count: number;
}

export interface ComplianceLatencySummary {
  count: number;
  min: number | null;
  max: number | null;
  avg: number | null;
  p50: number | null;
  p95: number | null;
  p99: number | null;
}

export interface ComplianceSummary {
  total_events: number;
  blocked_events: number;
  upstream_errors: number;
  pii_related_events: number;
  distinct_decisions: Record<string, number>;
  provider_totals: Record<string, number>;
  top_reasons: ComplianceReasonCount[];
  latency_ms: ComplianceLatencySummary;
  budget_charged_usd_total: number;
  window_start: string | null;
  window_end: string | null;
}

export interface ComplianceSampleEvent {
  timestamp?: string;
  correlation_id?: string;
  decision?: string;
  provider?: string;
  response_status?: number;
  reasons?: string[];
  pii_types?: string[];
  duration_ms?: number;
}

export interface ComplianceEvidenceSamples {
  blocked: ComplianceSampleEvent[];
  upstream_errors: ComplianceSampleEvent[];
}

export interface ComplianceReport {
  framework: 'SOC2' | 'GDPR' | 'HIPAA' | string;
  generated_at: string;
  summary: ComplianceSummary;
  sample_size: number;
  source: {
    audit_path: string;
    limit: number;
    bytes_scanned: number;
    truncated: boolean;
    lines_scanned: number;
    lines_considered: number;
    parsed_events: number;
    malformed_lines: number;
  };
  integrity: {
    tail_sha256: string | null;
    window_sha256: string | null;
  };
  samples: ComplianceEvidenceSamples;
  [key: string]: unknown;
}

export interface ComplianceEngineOptions {
  auditPath: string;
  maxReadBytes?: number;
  chunkReadBytes?: number;
  sampleLimit?: number;
}

export class ComplianceEngine {
  constructor(options: ComplianceEngineOptions);
  loadEvents(limit?: number): Array<Record<string, unknown>>;
  loadEventsWithMeta(options?: ComplianceLoadOptions): ComplianceLoadResult;
  generateEvidence(
    framework: string,
    options?: ComplianceLoadOptions & { sampleLimit?: number },
    details?: Record<string, unknown>
  ): ComplianceReport;
  generateSOC2Evidence(options?: ComplianceLoadOptions & { sampleLimit?: number }): ComplianceReport;
  generateGDPREvidence(options?: ComplianceLoadOptions & { sampleLimit?: number }): ComplianceReport;
  generateHIPAAEvidence(options?: ComplianceLoadOptions & { sampleLimit?: number }): ComplianceReport;
  static signReport<T extends Record<string, unknown>>(report: T, privateKeyPem: string): {
    report: T;
    signature: string;
    algorithm: 'ed25519';
    payload_sha256: string;
  };
}

export function createSentinel(config: SentinelConfig, options?: SentinelEmbedOptions): EmbeddedSentinel;
export function loadConfigForStart(options?: StartServerOptions): LoadedConfigResult;
export function installSignalHandlers(
  server: SentinelServerInstance,
  options?: { shutdownTimeoutMs?: number }
): () => void;
export function startServer(options?: StartServerOptions): StartServerResult;
export function stopServer(): StopServerResult;
export function statusServer(asJson: true): SentinelStatusPayload;
export function statusServer(asJson?: false): string;
export function setEmergencyOpen(enabled: boolean): EmergencyOverridePayload;
export function doctorServer(options?: StartServerOptions): DoctorServerResult;
