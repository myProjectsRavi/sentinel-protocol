# Integrations

One-line idea: point your provider base URL at Sentinel and add `x-sentinel-target`.

## LangChain (Node)

File: `examples/langchain-integration.ts`

Key change:

```ts
configuration: {
  baseURL: 'http://127.0.0.1:8787/v1',
  defaultHeaders: { 'x-sentinel-target': 'openai' },
}
```

## Vercel AI SDK

File: `examples/vercel-ai-sdk-integration.ts`

Key change:

```ts
const openai = createOpenAI({
  baseURL: 'http://127.0.0.1:8787/v1',
  headers: { 'x-sentinel-target': 'openai' },
});
```

## CrewAI (Python)

File: `examples/crewai-integration.py`

Key change:

```py
llm = LLM(
    base_url="http://127.0.0.1:8787/v1",
    headers={"x-sentinel-target": "openai"},
)
```

## Provider routing quick map

- `x-sentinel-target: openai`
- `x-sentinel-target: anthropic`
- `x-sentinel-target: google`
- `x-sentinel-target: custom` with `x-sentinel-custom-url`

## Zero-Code Passive Mode

Run monitor-first proxy + dashboard + framework hints:

```bash
npx --yes --package sentinel-protocol sentinel watch --profile minimal
```

Then point any SDK base URL at:

```text
http://127.0.0.1:8787/v1
```

Playground UI:

```text
http://127.0.0.1:8787/_sentinel/playground
```

Runtime forensic APIs:

```text
http://127.0.0.1:8787/_sentinel/forensic/snapshots
http://127.0.0.1:8787/_sentinel/forensic/replay
```

## VS Code Extension (Scaffold)

Files:

- `extensions/vscode-sentinel/package.json`
- `extensions/vscode-sentinel/extension.js`

Command:

- `Sentinel: Scan Prompt`

It scans selected editor text via local `/_sentinel/playground/analyze`.

## Python Adapters (Zero Dependency)

Files:

- `python/sentinel_protocol_adapters/callbacks.py`
- `examples/python-adapters-integration.py`

Adapters:

- `LangChainSentinelCallbackHandler`
- `LlamaIndexSentinelCallback`
- `CrewAISentinelHook`

## MCP (Claude Desktop / Cursor)

Run Sentinel MCP server:

```bash
node ./cli/sentinel.js mcp
```

Example Claude Desktop snippet:

```json
{
  "mcpServers": {
    "sentinel": {
      "command": "node",
      "args": ["/Users/ravitejanekkalapu/Documents/sentinel-protocol/cli/sentinel.js", "mcp"]
    }
  }
}
```

### MCP Poisoning Protection

`runtime.mcp_poisoning` protects against:
- poisoned tool descriptions
- malformed tool schemas
- config drift across MCP server calls
- unsafe control/zero-width characters in tool arguments

Example:

```yaml
runtime:
  mcp_poisoning:
    enabled: true
    mode: monitor # monitor | block
    description_threshold: 0.65
    max_tools: 64
    max_drift_snapshot_bytes: 131072
    block_on_config_drift: false
    detect_config_drift: true
    sanitize_arguments: true
```

Promotion path:
- Start `monitor` to collect findings and warning headers.
- Move to `block` only after low false-positive evidence in audit logs.
