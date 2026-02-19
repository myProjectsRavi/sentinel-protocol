export interface SentinelPlugin {
  name: string;
  version?: string;
  description?: string;
  priority?: number;
  critical?: boolean;
  hooks?: Record<string, (context: unknown) => void | Promise<void>>;
  setup?: (deps: { logger?: Console }) => void;
}

export interface EmbeddedSentinel {
  app: unknown;
  server: unknown;
  use(plugin: SentinelPlugin): EmbeddedSentinel;
  middleware(): (req: unknown, res: unknown, next?: (error?: unknown) => void) => void;
  start(): unknown;
  stop(): Promise<void>;
  scan(payload: unknown, requestHeaders?: Record<string, string>): Promise<{
    pii: unknown;
    provider: unknown;
  }>;
}

export function createSentinel(config: Record<string, unknown>, options?: Record<string, unknown>): EmbeddedSentinel;

export function startServer(options?: Record<string, unknown>): {
  server: unknown;
  loaded: unknown;
  doctor: unknown;
};
export function stopServer(): { stopped: boolean; message?: string; pid?: number };
export function statusServer(asJson?: boolean): unknown;
export function setEmergencyOpen(enabled: boolean): unknown;
export function doctorServer(options?: Record<string, unknown>): unknown;
