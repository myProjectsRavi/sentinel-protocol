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
