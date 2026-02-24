# Sentinel Protocol VS Code Extension

Run local prompt security scans from VS Code against a running Sentinel instance.

## Command

- `Sentinel: Scan Prompt`

Behavior:

1. Uses selected text from the current editor (or full document when no selection).
2. Sends text to `/_sentinel/playground/analyze`.
3. Shows summary in VS Code notifications.
4. Writes full JSON result to the `Sentinel Protocol` output channel.

## Default Endpoint

`http://127.0.0.1:8787/_sentinel/playground/analyze`

## Requirement

Start Sentinel first:

```bash
npx --yes --package sentinel-protocol sentinel watch --profile minimal
```
