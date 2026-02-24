# Try Sentinel Local (Zero Infra Constraint)

This project keeps the try experience local-first and zero-cost by shipping a static page:

- `docs/assets/try-sentinel-local.html`

Use it like this:

1. Start Sentinel:

```bash
npx --yes --package sentinel-protocol sentinel watch --profile minimal
```

2. Open the static page in your browser:

```bash
open ./docs/assets/try-sentinel-local.html
```

3. Click **Analyze** to call:

```text
POST http://127.0.0.1:8787/_sentinel/playground/analyze
```

This gives a `try.sentinel.dev`-style developer demo flow without hosted infrastructure cost.
