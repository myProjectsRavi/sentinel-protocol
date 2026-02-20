# Plugin Tutorial (Minimal)

This walkthrough shows a minimal Sentinel plugin with deterministic blocking/warning behavior.

## 1. Create a Plugin

```js
// examples/minimal-plugin.js
module.exports = {
  name: 'minimal-policy-plugin',
  priority: 50,
  hooks: {
    'request:prepared': async (ctx) => {
      const path = String(ctx.get('path', ''));
      if (path.includes('/v1/private')) {
        ctx.block({
          statusCode: 403,
          body: { error: 'PLUGIN_POLICY_BLOCK' },
          reason: 'plugin_private_path_block',
        });
        return;
      }
      ctx.warn('plugin_checked_path');
    },
  },
};
```

## 2. Register the Plugin

```js
const { createSentinel } = require('sentinel-protocol/embed');
const plugin = require('./examples/minimal-plugin');

const sentinel = createSentinel(config);
sentinel.use(plugin);
```

## 3. Validate Behavior

- In monitor/warn contexts, prefer `ctx.warn(...)` first.
- Move to blocking only when policy confidence is clear and tested.
- Verify audit/status output includes the expected plugin warning/block reason.

## 4. Guardrails

- Do not emit raw secrets/prompts in plugin errors or audit artifacts.
- Avoid non-deterministic logic in hook decisions.
- Keep plugin effects scoped to hook context (do not mutate global process state).
- Use explicit config flags for risky behavior.

## 5. Test Template

```js
test('plugin blocks protected path', async () => {
  // 1) start Sentinel with plugin
  // 2) send request to /v1/private
  // 3) assert 403 + expected error payload
});
```
