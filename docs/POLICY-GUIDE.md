# Policy Guide (Stub)

`sentinel.yaml` policy rules are evaluated in order.

Rule shape:

```yaml
- name: block-delete
  match:
    method: DELETE
    domain: "*.production.com"
  action: block
  message: "Delete blocked"
```

Supported `match` fields in v0.1.0:
- `method`
- `domain`
- `path_contains`
- `body_contains`
- `tool_name`
- `body_size_mb`
- `requests_per_minute`

Actions:
- `allow`
- `warn`
- `block`

More policy examples will be expanded post-v0.1.0.
