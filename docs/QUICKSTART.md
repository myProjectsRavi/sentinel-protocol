# Quickstart

## 1. Install

```bash
npm install
```

## 2. Initialize config

```bash
node ./cli/sentinel.js init
```

This creates:
- `/Users/ravitejanekkalapu/.sentinel/sentinel.yaml`

## 3. Start Sentinel

```bash
node ./cli/sentinel.js start
```

Optional safe startup flags:

```bash
node ./cli/sentinel.js start --dry-run
node ./cli/sentinel.js start --fail-open
```

## 4. Configure agent

Set base URL to:

```text
http://127.0.0.1:8787
```

Route to provider with header:
- `x-sentinel-target: openai`
- `x-sentinel-target: anthropic`
- `x-sentinel-target: google`
- `x-sentinel-target: custom` + `x-sentinel-custom-url`

## 5. Check status

Human output:

```bash
node ./cli/sentinel.js status
```

JSON output:

```bash
node ./cli/sentinel.js status --json
```

## 6. Emergency recovery

Enable emergency pass-through:

```bash
node ./cli/sentinel.js emergency-open on
```

Disable emergency pass-through:

```bash
node ./cli/sentinel.js emergency-open off
```
