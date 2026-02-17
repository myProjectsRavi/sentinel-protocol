import json
import os
import requests

payload = {
    "model": "claude-sonnet-4-5",
    "max_tokens": 256,
    "messages": [{"role": "user", "content": "Hello from Sentinel"}],
}

resp = requests.post(
    "http://127.0.0.1:8787/v1/messages",
    headers={
        "content-type": "application/json",
        "x-api-key": os.environ.get("ANTHROPIC_API_KEY", ""),
        "anthropic-version": "2023-06-01",
        "x-sentinel-target": "anthropic",
    },
    data=json.dumps(payload),
    timeout=30,
)

print("status", resp.status_code)
print(resp.text)
