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
