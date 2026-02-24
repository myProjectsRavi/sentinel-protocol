<div align="center">

# 🛡️ Sentinel Protocol

### The Open-Source AI Security Operating System

**One local firewall. Every LLM provider. 81 security engines. Zero cloud dependency.**<br />
**52,000+ lines of battle-tested security. Only 9 dependencies. Runs entirely on your machine.**<br />
Stop paying $30K+/month for fragmented tools — Sentinel replaces them all.

<br />

<a href="https://www.npmjs.com/package/sentinel-protocol"><img src="https://img.shields.io/npm/v/sentinel-protocol.svg?style=for-the-badge&color=0a7ea4" alt="npm" /></a>
<a href="./LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg?style=for-the-badge" alt="license" /></a>
<a href="./package.json"><img src="https://img.shields.io/badge/node-%3E%3D20-2ea44f.svg?style=for-the-badge" alt="node" /></a>
<a href="./docs/SECURITY_RELIABILITY_EVIDENCE_V4_PHASEA.md"><img src="https://img.shields.io/badge/evidence-release--grade-0a7ea4.svg?style=for-the-badge" alt="evidence" /></a>
<a href="./BENCHMARKS.md"><img src="https://img.shields.io/badge/OWASP-10%2F10-brightgreen.svg?style=for-the-badge" alt="owasp" /></a>

<br />

```
╔══════════════════════════════════════════════════════════════════════╗
║                    SENTINEL PROTOCOL v1.1.0                        ║
║                                                                    ║
║  ┌──────────┐   ┌──────────────────────────┐   ┌──────────────┐    ║
║  │ Your App │──▶│   81 Security Engines     │──▶│  OpenAI      │    ║
║  │  Agent   │   │   PII · Injection · Tools │   │  Anthropic   │    ║
║  │  MCP     │◀──│   Budget · Audit · Mesh   │◀──│  Google      │    ║
║  └──────────┘   └──────────────────────────┘   │  Ollama      │    ║
║                         │                      │  Any LLM     │    ║
║                    Runs 100% on                └──────────────┘    ║
║                    YOUR machine                                    ║
║                    No cloud. No SaaS.                              ║
║                    No data leaves.                                 ║
╚══════════════════════════════════════════════════════════════════════╝
```

</div>

---

## ⚡ The Numbers

<div align="center">

| Metric | Value |
|:---:|:---:|
| **Source Lines of Code** | **52,069** |
| **Security Engines** | **81** |
| **Test Suites** | **139** (567 tests, 0 failures) |
| **Linted Files** | **306** (0 warnings) |
| **Runtime Dependencies** | **9** total |
| **OWASP LLM Top 10** | **10/10** covered |
| **Setup Time** | **90 seconds** |
| **Proxy Overhead** | **< 5ms** (p95) |
| **Cloud Dependency** | **None** — runs 100% on your machine |
| **Data Sent to Cloud** | **Zero** — all processing is local |

</div>

> **🔒 Everything runs on YOUR machine.** Sentinel never phones home, never sends telemetry, and never routes your data through external servers. Clone it, run it, own it.

---

## 📑 Table of Contents

| Section | What You'll Learn |
|---|---|
| [⚡ The Numbers](#-the-numbers) | Codebase metrics at a glance |
| [🤔 Why Does This Exist?](#-why-does-this-exist) | Problems Sentinel solves |
| [🚀 Get Started in 90 Seconds](#-get-started-in-90-seconds) | Copy-paste setup |
| [🛤️ Choose Your Path](#️-choose-your-path) | Beginner vs advanced integration |
| [🌐 Every LLM Provider](#-works-with-every-llm-provider) | Provider compatibility matrix |
| [🏗️ Architecture](#️-architecture) | How Sentinel works internally |
| [🔐 Security Engine Map](#-complete-security-engine-map) | All 81 engines categorized |
| [📊 Profiles](#-profiles--from-laptop-to-enterprise) | Minimal, standard, paranoid |
| [📋 Setup Guide](#-step-by-step-setup-guide) | 4 setup methods explained |
| [🔧 Configuration](#-configuration) | YAML config + env vars |
| [🔌 Integrations](#-integrations) | JS, Python, GitHub Actions, VS Code |
| [🎯 Daily Workflows](#-daily-workflows) | Red team, compliance, forensics |
| [🌐 Control Plane API](#-control-plane-api) | All 15 API endpoints |
| [📈 Benchmarks & Evidence](#-benchmarks--evidence) | OWASP map, performance data |
| [🔬 Formal Verification](#-formal-verification) | TLA+ and Alloy specs |
| [❓ FAQ](#-faq) | Common questions answered |

---

## 🤔 Why Does This Exist?

Every developer using AI faces the same unsolved problems:

| Problem | What Happens Without Sentinel | What Sentinel Does |
|---|---|---|
| **Prompt Injection** | Attackers hijack your LLM via crafted inputs | 5 layered engines detect and block injections in real-time |
| **PII Leakage** | User data (SSN, emails, keys) leaks to model providers | Scans ingress + egress + logs, redacts before it leaves your machine |
| **Tool Abuse** | Agents execute dangerous tools (shell, file delete) | Schema validation, sandbox enforcement, tool anomaly detection |
| **Budget Burn** | Runaway retries, loops, and token waste cost thousands | Budget autopilot, token counter, circuit breaker, rate limiter |
| **No Audit Trail** | Compliance asks "prove it" and you can't | Evidence vault, provenance signing, AIBOM, watermarking |
| **Hallucinations** | LLM fabricates URLs, citations, and code imports | Hallucination tripwire detects dead links, fake references, numeric contradictions |
| **Multi-Agent Chaos** | Agents collude, impersonate, or corrupt shared memory | Swarm protocol, consensus protocol, memory integrity monitor, cascade isolation |

> **🔑 What makes Sentinel different from LLM Guard, Rebuff, NeMo Guardrails, and Lakera?**
>
> | | Sentinel | Competitors (combined) |
> |---|---|---|
> | Security engines | **81** | ~15-25 each |
> | Dependencies | **9** | 50-200+ |
> | OWASP coverage | **10/10** | 3-6/10 |
> | Formal verification | **TLA+ & Alloy** | None |
> | Federated threat mesh | **Yes** | None |
> | Token watermarking | **Yes** | None |
> | Agent consensus protocol | **Yes** | None |
> | Runs 100% local | **Yes** | Most require cloud |
>
> See [full comparison →](docs/benchmarks/COMPETITOR_COMPARISON.md)

**Sentinel sits between your app and the LLM provider.** No code changes required.

```
┌──────────┐     ┌─────────────────────┐     ┌──────────────┐
│ Your App │ ──▶ │  Sentinel Protocol  │ ──▶ │ OpenAI / etc │
│          │ ◀── │  (81 engines, local) │ ◀── │              │
└──────────┘     └─────────────────────┘     └──────────────┘
```

---

## 🚀 Get Started in 90 Seconds

### One Command — Full AI Security Stack

```bash
npx --yes --package sentinel-protocol sentinel bootstrap --profile minimal --dashboard
```

**That's it.** Sentinel is now running with:
- 🔒 Security proxy at `http://127.0.0.1:8787`
- 📊 Live dashboard at `http://127.0.0.1:8788`
- 🎮 Playground at `http://127.0.0.1:8787/_sentinel/playground`

### Choose Your Security Level

```bash
# 🟢 Minimal — lightweight, 8 engines, great for laptops (monitor only)
npx --yes --package sentinel-protocol sentinel bootstrap --profile minimal --dashboard

# 🟡 Standard — balanced, ~20 engines, staging/production ready
npx --yes --package sentinel-protocol sentinel bootstrap --profile standard --dashboard

# 🔴 Paranoid — all 81 engines, enforce mode, maximum security
npx --yes --package sentinel-protocol sentinel bootstrap --profile paranoid --mode enforce --dashboard
```

| | Minimal | Standard | Paranoid |
|---|:---:|:---:|:---:|
| **Engines** | 8 | ~20 | All 81 |
| **Mode** | Monitor (log only) | Monitor | Enforce (blocks threats) |
| **Best for** | Dev laptops, getting started | Staging, production | Security audits, compliance |

### Verify It's Running

```bash
curl -sS http://127.0.0.1:8787/_sentinel/health | python3 -m json.tool
```

### Send Your First Protected Request

```bash
curl -sS http://127.0.0.1:8787/v1/chat/completions \
  -H 'content-type: application/json' \
  -H 'x-sentinel-target: openai' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello from Sentinel!"}]}'
```

### ⚠️ Prerequisites — Set Your Provider API Key

```bash
# Pick the provider(s) you use:
export SENTINEL_OPENAI_API_KEY="sk-..."          # OpenAI
export SENTINEL_ANTHROPIC_API_KEY="sk-ant-..."    # Anthropic
export SENTINEL_GOOGLE_API_KEY="AIza..."          # Google
# Ollama needs no key — auto-detected at 127.0.0.1:11434
```

---

## 🛤️ Choose Your Path

<table>
<tr>
<td width="50%">

### 🟢 Beginner — Zero Code Changes

```bash
# Install and run in passive watch mode
npx --yes --package sentinel-protocol \
  sentinel watch --profile minimal
```

Point your existing SDK at Sentinel:

```javascript
const openai = new OpenAI({
  baseURL: 'http://127.0.0.1:8787/v1',
  defaultHeaders: {
    'x-sentinel-target': 'openai'
  }
});
```

**Zero app code changes. Full protection.**

</td>
<td width="50%">

### 🔵 Advanced — Embed SDK

```javascript
const { createSentinel } = require('sentinel-protocol');

const sentinel = createSentinel(config);
app.use(sentinel.middleware());
sentinel.start();
```

Or use the secure fetch wrapper:

```javascript
const response = await sentinel.secureFetch(
  'https://api.openai.com/v1/chat/completions',
  { method: 'POST', body: payload }
);
```

**Deep integration. Granular control.**

</td>
</tr>
</table>

---

## 🌐 Works With Every LLM Provider

<div align="center">

| Provider | Status | Header Value | Auto-Configured |
|:---:|:---:|:---:|:---:|
| **OpenAI** (GPT-4, GPT-4o, o1, o3) | ✅ Native | `openai` | Yes |
| **Anthropic** (Claude 3.5, Claude 4) | ✅ Native | `anthropic` | Yes |
| **Google** (Gemini 2.0, 2.5) | ✅ Native | `google` | Yes |
| **Ollama** (Llama, Mistral, Qwen) | ✅ Native | `ollama` | Auto-detected |
| **DeepSeek** | ✅ Compatible | `custom` | Via custom URL |
| **Mistral AI** | ✅ Compatible | `custom` | Via custom URL |
| **Groq** | ✅ Compatible | `custom` | Via custom URL |
| **Together AI** | ✅ Compatible | `custom` | Via custom URL |
| **OpenRouter** | ✅ Compatible | `custom` | Via custom URL |
| **Any OpenAI-compatible API** | ✅ Compatible | `custom` | Via custom URL |

</div>

**Switch providers with a single header — no code changes:**

```bash
# OpenAI
curl ... -H 'x-sentinel-target: openai'

# Switch to Anthropic
curl ... -H 'x-sentinel-target: anthropic'

# Switch to local Ollama
curl ... -H 'x-sentinel-target: ollama'

# Switch to any custom endpoint
curl ... -H 'x-sentinel-target: custom' -H 'x-sentinel-custom-url: https://api.deepseek.com'
```

---

## 🏗️ Architecture

```mermaid
flowchart TB
    subgraph INPUT["📥 Your App / Agent / MCP Client"]
        A[Request]
    end

    subgraph SENTINEL["🛡️ Sentinel Protocol (Local)"]
        direction TB
        subgraph INGRESS["Ingress Pipeline"]
            B1[PII Scanner]
            B2[Injection Scanner]
            B3[Policy Engine]
            B4[Rate Limiter]
        end

        subgraph AGENTIC["Agentic Security"]
            C1[Tool Schema Validator]
            C2[Sandbox Enforcer]
            C3[MCP Poisoning Detector]
            C4[Swarm Protocol]
        end

        subgraph ROUTING["Routing & Resilience"]
            D1[Provider Router]
            D2[Circuit Breaker]
            D3[Retry + Failover]
            D4[Budget Autopilot]
        end

        subgraph EGRESS["Egress Pipeline"]
            E1[Output Classifier]
            E2[Hallucination Tripwire]
            E3[Stream Redaction]
            E4[Token Watermark]
        end

        subgraph GOVERNANCE["Governance & Audit"]
            F1[Evidence Vault]
            F2[AIBOM Generator]
            F3[Compliance Engine]
            F4[Forensic Debugger]
        end
    end

    subgraph PROVIDERS["☁️ LLM Providers"]
        G1[OpenAI]
        G2[Anthropic]
        G3[Google]
        G4[Ollama / Custom]
    end

    A --> INGRESS
    INGRESS --> AGENTIC
    AGENTIC --> ROUTING
    ROUTING --> PROVIDERS
    PROVIDERS --> EGRESS
    EGRESS --> A

    INGRESS --> GOVERNANCE
    EGRESS --> GOVERNANCE
```

### Design Principles

| Principle | What It Means |
|---|---|
| **Monitor-first** | Every control starts in observe mode. Promote to enforce only when confident |
| **Deterministic** | Same input → same decision. No probabilistic security. Reproducible in CI |
| **Bounded state** | Every engine has TTL pruning, max caps, and memory limits |
| **Zero silent drift** | Config is schema-validated. Unknown keys are rejected. No magic defaults |
| **Local-first** | Everything runs on your machine. No cloud calls for security decisions |

---

## 🔐 Complete Security Engine Map

<details>
<summary><strong>🛡️ Ingress Security — 18 engines protecting inputs</strong></summary>

| Engine | What It Does | Lines |
|---|---|---|
| `injection-scanner` | Multi-signal heuristic injection detection | Core |
| `neural-injection-classifier` | ML-based injection classification with ONNX runtime | Core |
| `prompt-rebuff` | Canary token + perplexity + multi-layer injection defense | Core |
| `injection-merge` | Unified injection decision across all scanners | Core |
| `pii-scanner` | 40+ PII pattern detection (SSN, email, credit card, etc.) | Core |
| `masking` | Reversible PII masking with format-preserving tokens | Core |
| `policy-engine` | Rule-based request filtering with custom match patterns | Core |
| `rate-limiter` | Per-client, per-endpoint rate limiting with sliding windows | Core |
| `omni-shield` | Unified security decision aggregator across all engines | 441 |
| `parallax-validator` | Multi-path cross-validation of tool outputs | 284 |
| `semantic-scanner` | Semantic similarity-based threat detection | Core |
| `context-integrity-guardian` | Session context manipulation detection | 234 |
| `lfrl-engine` | Custom firewall rule language (`RULE...WHEN...THEN`) | 366 |
| `cold-start-analyzer` | Heightened sensitivity during system warmup | Core |
| `self-healing-immune` | Learns from attacks, auto-generates blocking rules | Core |
| `behavioral-fingerprint` | Welford streaming z-score anomaly detection | Core |
| `deception-engine` | Returns fake responses to detected attackers | 164 |
| `canary-tool-trap` | Honeypot tools that detect unauthorized tool discovery | 153 |

</details>

<details>
<summary><strong>🤖 Agentic & MCP Security — 14 engines for AI agents</strong></summary>

| Engine | What It Does | Lines |
|---|---|---|
| `agentic-threat-shield` | Comprehensive agent behavior analysis | 557 |
| `tool-schema-validator` | Enforces security policies on tool definitions | 278 |
| `sandbox-enforcer` | Restricts agent tool execution environment | 199 |
| `mcp-poisoning-detector` | Detects MCP server poisoning attempts | Core |
| `mcp-shadow-detector` | Identifies unauthorized shadow MCP connections | Core |
| `mcp-certificate-pinning` | TLS cert pinning for MCP server connections | 178 |
| `swarm-protocol` | HMAC-authenticated inter-agent messaging | 428 |
| `consensus-protocol` | N-of-M quorum for high-risk agent actions | Core |
| `cascade-isolator` | Blast radius containment for agent failures | 225 |
| `agent-identity-federation` | Cross-system agent identity verification | 254 |
| `memory-integrity-monitor` | Detects memory corruption in agent state | 201 |
| `memory-poisoning-sentinel` | Prevents deliberate memory poisoning attacks | Core |
| `cross-tenant-isolator` | Multi-tenant data leak prevention | Core |
| `a2a-card-verifier` | Google Agent Card schema + drift verification | 110 |

</details>

<details>
<summary><strong>📤 Egress Security — 9 engines protecting outputs</strong></summary>

| Engine | What It Does | Lines |
|---|---|---|
| `output-classifier` | Response content safety classification | Core |
| `output-schema-validator` | Validates LLM output structure against schema | Core |
| `hallucination-tripwire` | Detects fabricated URLs, citations, imports, contradictions | Core |
| `reasoning-trace-monitor` | Analyzes `<think>` blocks for injection + coherence | Core |
| `stego-exfil-detector` | Detects hidden data via zero-width chars + invisible Unicode | Core |
| `entropy-analyzer` | Statistical entropy analysis of outputs | Core |
| `output-provenance-signer` | HMAC-SHA256 signed output envelopes for audit | Core |
| `token-watermark` | Invisible watermarks with timing-safe verification | 232 |
| `sse-redaction-transform` | Real-time PII redaction in SSE streams | Core |

</details>

<details>
<summary><strong>⚙️ Resilience & Cost — 6 engines protecting your budget</strong></summary>

| Engine | What It Does | Lines |
|---|---|---|
| `circuit-breaker` | Per-provider circuit breaker with half-open recovery | 175 |
| `retry` | Exponential backoff with jitter | 56 |
| `budget-autopilot` | Automatic budget enforcement + alerting | 169 |
| `cost-efficiency-optimizer` | Token usage optimization recommendations | 378 |
| `token-counter` | Real-time token counting per request | Core |
| `budget-store` | Persistent budget tracking per client/team | Core |

</details>

<details>
<summary><strong>🏛️ Governance & Compliance — 17 engines for enterprise audit</strong></summary>

| Engine | What It Does | Lines |
|---|---|---|
| `evidence-vault` | Tamper-evident security event storage | Core |
| `compliance-engine` | SOC2 / GDPR / HIPAA / EU AI Act Article 12 reports | Core |
| `aibom-generator` | AI Bill of Materials generation | Core |
| `adversarial-eval-harness` | Red team evaluation framework | Core |
| `attack-corpus-evolver` | Auto-generates new attack patterns from detections | 122 |
| `forensic-debugger` | Request-level forensic analysis + replay | 148 |
| `owasp-compliance-mapper` | OWASP LLM Top 10 coverage mapping | Core |
| `compute-attestation` | Trusted environment attestation envelopes | Core |
| `policy-gradient-analyzer` | Simulates impact of policy changes | Core |
| `capability-introspection` | Runtime capability + attack surface mapping | Core |
| `threat-propagation-graph` | Attack path visualization | 126 |
| `security-posture` | Overall security health scoring | Core |
| `policy-bundle` | Signed policy package distribution | Core |
| `semantic-drift-canary` | Detects silent model swaps by providers | Core |
| `threat-intel-mesh` | Federated threat intelligence sharing | 636 |
| `red-team` | Automated red team test runner | Core |
| `differential-privacy` | Mathematical ε-differential privacy (Laplace noise) | 372 |

</details>

<details>
<summary><strong>🎯 Adaptive Defense — Things no competitor has built</strong></summary>

| Capability | What It Does | Why It's Unique |
|---|---|---|
| **LFRL Firewall Language** | Write rules: `RULE block_admin WHEN path contains /admin THEN block` | No other tool has a DSL for AI security rules |
| **Self-Healing Immune System** | Learns from detected attacks, auto-generates blocking patterns | Adaptive defense that gets stronger over time |
| **Polymorphic Prompt Defense** | Randomizes prompt structure to prevent injection | Moving target defense — attacker can't predict format |
| **Honeytoken Injection** | Plants canary tokens to detect data exfiltration | If your data appears elsewhere, you know it leaked |
| **Cognitive Rollback** | Undoes agent decisions when anomalies are detected | Kill switch for AI agents gone rogue |
| **Attack Corpus Evolution** | Auto-generates new test payloads from detected patterns | Your test suite evolves with the threat landscape |
| **Deception Engine** | Returns convincing fake data to detected attackers | Wastes attacker time, protects real data |

</details>

---

## 📊 Profiles — From Laptop to Enterprise

<div align="center">

| | `minimal` | `standard` | `paranoid` |
|:---|:---:|:---:|:---:|
| **Best for** | Local dev, 4GB laptops | Staging, production | Security audits |
| **Mode** | Monitor | Monitor | Enforce |
| **Engines active** | 8 | ~20 | All 81 |
| **Memory cap** | 512 MB | No hard cap | No hard cap |
| **Engine shedding** | Auto (drops engines if memory is tight) | Manual | Disabled |
| **Setup** | `--profile minimal` | `--profile standard` | `--profile paranoid` |

</div>

```bash
# Laptop-friendly
npx --yes --package sentinel-protocol sentinel bootstrap --profile minimal --dashboard

# Production balanced
npx --yes --package sentinel-protocol sentinel bootstrap --profile standard --dashboard

# Maximum security
npx --yes --package sentinel-protocol sentinel bootstrap --profile paranoid --dashboard
```

---

## 📋 Step-by-Step Setup Guide

<details>
<summary><strong>Method 1: Bootstrap (Recommended — 90 seconds)</strong></summary>

```bash
# 1. Run bootstrap
npx --yes --package sentinel-protocol sentinel bootstrap --profile minimal --dashboard

# 2. Verify
curl -sS http://127.0.0.1:8787/_sentinel/health

# 3. Open dashboard
open http://127.0.0.1:8788

# Done! Point your SDK at http://127.0.0.1:8787/v1
```

</details>

<details>
<summary><strong>Method 2: Manual Setup (Full control)</strong></summary>

```bash
# 1. Initialize config (creates sentinel.yaml)
npx --yes --package sentinel-protocol sentinel init --force --profile standard

# 2. Set provider keys
export SENTINEL_OPENAI_API_KEY="sk-..."
export SENTINEL_ANTHROPIC_API_KEY="sk-ant-..."

# 3. Run diagnostics
npx --yes --package sentinel-protocol sentinel doctor

# 4. Start Sentinel
npx --yes --package sentinel-protocol sentinel start --dashboard

# 5. Verify
curl -sS http://127.0.0.1:8787/_sentinel/health
```

</details>

<details>
<summary><strong>Method 3: Docker (Ops / Infrastructure teams)</strong></summary>

```bash
# 1. Clone
git clone https://github.com/myProjectsRavi/sentinel-protocol.git
cd sentinel-protocol

# 2. Start containers
docker-compose up -d

# 3. Verify
curl -sS http://127.0.0.1:8787/_sentinel/health
```

</details>

<details>
<summary><strong>Method 4: Passive Watch Mode (Zero code changes to your app)</strong></summary>

```bash
# 1. Start Sentinel in watch mode
npx --yes --package sentinel-protocol sentinel watch --profile minimal

# 2. Change your SDK's base URL to point at Sentinel
#    Before: https://api.openai.com/v1
#    After:  http://127.0.0.1:8787/v1

# That's it. All traffic is now monitored.
```

</details>

---

## 🔧 Configuration

Sentinel config is **strict and schema-validated** — unknown keys are rejected, every value has bounds.

<details>
<summary><strong>Minimal safe config (sentinel.yaml)</strong></summary>

```yaml
version: 1
mode: monitor

proxy:
  host: 127.0.0.1
  port: 8787
  timeout_ms: 30000

runtime:
  fail_open: false
  scanner_error_action: allow

pii:
  enabled: true
  provider_mode: local
```

</details>

<details>
<summary><strong>🛡️ Enhanced PII Protection (Optional — PII Firewall Edge API)</strong></summary>

Sentinel ships with a **free, local PII scanner** that works out of the box with zero dependencies.

For teams that need **enterprise-grade PII detection** with higher accuracy, broader entity coverage, and regulatory-grade redaction, you can optionally enable the [PII Firewall Edge API](https://rapidapi.com/image-zero-trust-security-labs/api/pii-firewall-edge) as an enhanced provider:

```yaml
pii:
  enabled: true
  provider_mode: hybrid      # Uses API when available, falls back to local
  rapidapi:
    endpoint: https://pii-firewall-edge.p.rapidapi.com/redact
    host: pii-firewall-edge.p.rapidapi.com
    fallback_to_local: true   # Always falls back to local if API is unreachable
    api_key: ""               # Set via SENTINEL_RAPIDAPI_KEY env var
```

**Setup:**

```bash
# 1. Subscribe to the API (free tier available)
#    https://rapidapi.com/image-zero-trust-security-labs/api/pii-firewall-edge

# 2. Set your RapidAPI key
export SENTINEL_RAPIDAPI_KEY="your-rapidapi-key-here"

# 3. Update sentinel.yaml to use hybrid mode (shown above)

# 4. Restart Sentinel — enhanced PII detection is now active
```

| Feature | Local (Default) | PII Firewall Edge (Optional) |
|---|:---:|:---:|
| **Cost** | Free | Free tier + paid plans |
| **Setup** | Zero config | 2 minutes |
| **Accuracy** | Good (40+ patterns) | Enterprise-grade |
| **Network** | None | API call to RapidAPI |
| **Fallback** | — | Auto-falls back to local |
| **Best for** | Development, local-only | Production, compliance-critical |

> **💡 Note:** The local PII scanner is production-capable on its own. The API is purely optional for teams that want the highest possible detection accuracy. Sentinel always falls back to local if the API is unavailable.


injection:
  enabled: true
  threshold: 0.8
  action: block
```

</details>

<details>
<summary><strong>Enforce mode with rate limiting</strong></summary>

```yaml
mode: enforce

runtime:
  rate_limiter:
    enabled: true
    default_limit: 60
    default_window_ms: 60000

rules:
  - name: block-admin-export
    match:
      method: POST
      path_contains: /admin/export
    action: block
    message: blocked by sentinel policy
```

</details>

<details>
<summary><strong>Multi-provider with resilience mesh</strong></summary>

```yaml
runtime:
  upstream:
    resilience_mesh:
      targets:
        openai:
          enabled: true
          provider: openai
          contract: openai_chat_v1
          base_url: https://api.openai.com
        anthropic:
          enabled: true
          provider: anthropic
          contract: anthropic_messages_v1
          base_url: https://api.anthropic.com
        ollama:
          enabled: true
          provider: ollama
          contract: ollama_chat_v1
          base_url: http://127.0.0.1:11434
```

</details>

<details>
<summary><strong>Federated threat-intel mesh</strong></summary>

```yaml
runtime:
  threat_intel_mesh:
    enabled: true
    mode: monitor
    node_id: sentinel-dev-a
    shared_secret: ""  # Set via SENTINEL_MESH_SHARED_SECRET env var
    peers: ["http://192.168.1.10:8787"]
    sync_enabled: true
    sync_interval_ms: 90000
    max_peer_signatures: 1000
    allow_unsigned_import: false
```

</details>

<details>
<summary><strong>Environment variables reference</strong></summary>

| Variable | Purpose | Required |
|---|---|---|
| `SENTINEL_OPENAI_API_KEY` | OpenAI API key | For OpenAI target |
| `SENTINEL_ANTHROPIC_API_KEY` | Anthropic API key | For Anthropic target |
| `SENTINEL_GOOGLE_API_KEY` | Google AI API key | For Google target |
| `SENTINEL_OLLAMA_URL` | Custom Ollama endpoint | Optional |
| `SENTINEL_MESH_SHARED_SECRET` | Threat mesh signing secret | For mesh sync |
| `SENTINEL_TOKEN_WATERMARK_SECRET` | Watermark signing secret | For watermarking |
| `SENTINEL_DASHBOARD_AUTH_TOKEN` | Dashboard auth token | For remote access |
| `SENTINEL_RAPIDAPI_KEY` | RapidAPI key for hybrid PII | Optional |

</details>

---

## 🔌 Integrations

<table>
<tr>
<td width="50%">

### JavaScript / Node.js

```javascript
// Proxy mode — zero code changes
const openai = new OpenAI({
  baseURL: 'http://127.0.0.1:8787/v1',
  defaultHeaders: {
    'x-sentinel-target': 'openai'
  }
});
```

</td>
<td width="50%">

### Embed SDK

```javascript
const { createSentinel } = require('sentinel-protocol');
const sentinel = createSentinel(config);

app.use(sentinel.middleware());
sentinel.start();
```

</td>
</tr>
<tr>
<td>

### Python (LangChain)

```python
from sentinel_protocol_adapters import (
    LangChainSentinelCallbackHandler
)

handler = LangChainSentinelCallbackHandler()
llm = ChatOpenAI(callbacks=[handler])
```

</td>
<td>

### GitHub Action (CI/CD)

```yaml
- uses: myProjectsRavi/sentinel-protocol\
    /.github/actions/security-scan@v1
  with:
    threshold: '0.85'
    sarif-output: 'scan.sarif'
```

</td>
</tr>
</table>

### Supported Frameworks

| Framework | Auto-Detected | Snippet Printed |
|---|:---:|:---:|
| Express | ✅ | ✅ |
| Fastify | ✅ | ✅ |
| Next.js | ✅ | ✅ |
| Koa | ✅ | ✅ |
| Hono | ✅ | ✅ |
| NestJS | ✅ | ✅ |

### Python Adapters

| Framework | Adapter |
|---|---|
| LangChain | `LangChainSentinelCallbackHandler` |
| LlamaIndex | `LlamaIndexSentinelCallbackHandler` |
| CrewAI | `CrewAISentinelHandler` |
| AutoGen | `AutoGenSentinelHandler` |
| LangGraph | `LangGraphSentinelCallbackHandler` |

Full adapter source: [`python/sentinel_protocol_adapters.py`](python/sentinel_protocol_adapters.py)

---

## 🎯 Daily Workflows

<details>
<summary><strong>🔴 Red Team Your AI App</strong></summary>

```bash
# Run automated adversarial evaluation
sentinel red-team run \
  --url http://127.0.0.1:8787 \
  --target openai \
  --out ./red-team-report.json

# Generate HTML report
sentinel red-team run \
  --url http://127.0.0.1:8787 \
  --target openai \
  --report html \
  --out ./red-team-report.html
```

</details>

<details>
<summary><strong>📋 Generate Compliance Reports</strong></summary>

```bash
# EU AI Act Article 12
sentinel compliance report \
  --framework eu-ai-act-article-12 \
  --out ./eu-ai-act-evidence.json

# SOC2
sentinel compliance report \
  --framework soc2 \
  --out ./soc2-evidence.json

# GDPR
sentinel compliance report \
  --framework gdpr \
  --out ./gdpr-evidence.json

# HIPAA
sentinel compliance report \
  --framework hipaa \
  --out ./hipaa-evidence.json
```

</details>

<details>
<summary><strong>📊 Run Benchmarks</strong></summary>

```bash
# Overhead benchmark
npm run benchmark -- --duration 3 --connections 16

# Regression gates
npm run benchmark:gate

# Standard adversarial datasets (AdvBench, TrojAI)
npm run benchmark:datasets
```

</details>

<details>
<summary><strong>🔬 Forensic Replay</strong></summary>

```bash
# Replay a decision with different thresholds (what-if analysis)
sentinel forensic replay \
  --snapshot <snapshot-id> \
  --overrides '{"injection_threshold": 0.6}'

# Or use the dashboard at http://127.0.0.1:8788
# Navigate to Forensic Replay panel
```

</details>

---

## 🌐 Control Plane API

All endpoints are local-only by default. Full spec: [`docs/openapi.yaml`](docs/openapi.yaml)

| Endpoint | Method | Purpose |
|---|---|---|
| `/_sentinel/health` | GET | Health check + engine status |
| `/_sentinel/metrics` | GET | Prometheus-compatible metrics |
| `/_sentinel/capabilities` | GET | Runtime capability map |
| `/_sentinel/anomalies` | GET | Anomaly telemetry feed |
| `/_sentinel/threat-intel` | GET | Threat intelligence snapshot |
| `/_sentinel/threat-intel/share` | GET | Export signed threat-intel for mesh sharing |
| `/_sentinel/threat-intel/ingest` | POST | Import threat-intel from peer |
| `/_sentinel/threat-intel/sync` | POST | Trigger mesh sync with all peers |
| `/_sentinel/forensic/snapshots` | GET | List forensic snapshots |
| `/_sentinel/forensic/replay` | POST | Replay decision with what-if overrides |
| `/_sentinel/playground` | GET | Interactive playground UI |
| `/_sentinel/playground/analyze` | POST | Analyze prompt through all engines |
| `/_sentinel/adversarial-eval/run` | POST | Run adversarial evaluation |
| `/_sentinel/zk-config` | GET | Zero-knowledge config validation hash |
| `/_sentinel/watermark/verify` | POST | Verify token watermark envelope |

---

## 📈 Benchmarks & Evidence

### OWASP LLM Top 10 Coverage

| ID | Threat | Sentinel Coverage |
|---|---|---|
| **LLM01** | Prompt Injection | ✅ Full — 5 engines (scanner, neural, rebuff, merge, omni-shield) |
| **LLM02** | Insecure Output | ✅ Full — classifier, schema validator, entropy, stego |
| **LLM03** | Training Data Poisoning | ✅ Full — supply chain validator, memory poisoning sentinel |
| **LLM04** | Model Denial of Service | ✅ Full — rate limiter, circuit breaker, budget autopilot |
| **LLM05** | Supply Chain | ✅ Full — supply chain validator, lock file drift, module audit |
| **LLM06** | Sensitive Info Disclosure | ✅ Full — PII scanner, masking, stego detector, entropy |
| **LLM07** | Insecure Plugin | ✅ Full — tool schema validator, sandbox enforcer, tool anomaly |
| **LLM08** | Excessive Agency | ✅ Full — agentic threat shield, consensus, cascade isolator |
| **LLM09** | Overreliance | ✅ Full — hallucination tripwire, reasoning trace, drift canary |
| **LLM10** | Model Theft | ✅ Full — provenance signer, watermark, compute attestation |

### Performance

| Metric | Value | How Measured |
|---|---|---|
| Proxy overhead (p95) | < 5ms | `npm run benchmark` with autocannon |
| Cold start to ready | < 3s | `minimal` profile on M1 Mac |
| Setup to first protection | 90s | `sentinel bootstrap` on clean machine |
| CI suite runtime | ~11s | 139 suites, 567 tests |

Full methodology: [`docs/benchmarks/METHODOLOGY.md`](docs/benchmarks/METHODOLOGY.md)<br />
Competitor comparison: [`docs/benchmarks/COMPETITOR_COMPARISON.md`](docs/benchmarks/COMPETITOR_COMPARISON.md)<br />
Standard dataset results: [`docs/benchmarks/results/standard-datasets.json`](docs/benchmarks/results/standard-datasets.json)

---

## 🔬 Formal Verification

Sentinel includes TLA+ and Alloy formal specifications for core security invariants:

| Spec | Language | Invariants Proved |
|---|---|---|
| [Serialization Firewall](docs/formal/specs/serialization-firewall.tla) | TLA+ | `NoExploitAllowed`, `DepthBombBlocked`, `UnknownFormatBlocked` |
| [Injection Guard](docs/formal/specs/injection-guard.tla) | TLA+ | `EnforceBlocksHighRisk`, `MonitorNeverBlocks` |
| [Threat-Intel Mesh](docs/formal/specs/threat-intel-mesh.als) | Alloy | `UnsignedImportMustBeDenied`, `SignedImportMayBeAccepted` |

---

## 🏛️ Proof & Evidence

| Document | Purpose |
|---|---|
| [Security & Reliability Evidence](docs/SECURITY_RELIABILITY_EVIDENCE_V4_PHASEA.md) | Release-grade proof of security posture |
| [OWASP LLM Top 10 Map](docs/OWASP_LLM_TOP10_SENTINEL_MAP.md) | Engine-by-engine OWASP coverage |
| [OWASP Submission Pack](docs/owasp/REFERENCE_IMPLEMENTATION_SUBMISSION.md) | Ready-to-submit reference implementation |
| [OWASP Artifact Manifest](docs/owasp/submission-manifest.json) | Immutable hash manifest for submission |
| [Benchmark Methodology](docs/benchmarks/METHODOLOGY.md) | Reproducible benchmark approach |
| [Competitor Comparison](docs/benchmarks/COMPETITOR_COMPARISON.md) | Fair comparison with `not_measured` for unverifiable data |
| [Wizard Validation](docs/evidence/WIZARD_VALIDATION.md) | 9-path init matrix (3 profiles × 3 providers) |
| [Framework Detection](docs/evidence/FRAMEWORK_DETECT_MATRIX.md) | 7-framework detection validation |
| [GitHub Action Demo](docs/evidence/GITHUB_ACTION_DEMO.md) | CI security gate demonstration |
| [VS Code Extension](docs/evidence/VSCODE_EXTENSION_VALIDATION.md) | Extension packaging validation |

---

## 🤖 VS Code Extension

Scan prompts directly from your editor:

```
Cmd + Shift + P → "Sentinel: Scan Prompt"
```

Install from VSIX:
```bash
npm run ci:vscode:package
code --install-extension dist/sentinel-protocol-vscode-*.vsix
```

---

## ❓ FAQ

<details>
<summary><strong>Do I need cloud services?</strong></summary>

No. Sentinel runs entirely on your machine. No accounts, no API keys for Sentinel itself, no telemetry.

</details>

<details>
<summary><strong>Can I keep my existing SDKs?</strong></summary>

Yes. Point your SDK's `baseURL` to `http://127.0.0.1:8787/v1` and add `x-sentinel-target` header. Zero code changes to your app logic.

</details>

<details>
<summary><strong>How much RAM does it need?</strong></summary>

`minimal` profile runs on 4GB laptops with a 512MB memory cap and automatic engine shedding. `standard` and `paranoid` use more.

</details>

<details>
<summary><strong>Is monitor-first supported?</strong></summary>

Yes — it's the **recommended** approach. Start in `monitor`, collect evidence, then selectively promote controls to `enforce`.

</details>

<details>
<summary><strong>What about performance overhead?</strong></summary>

p95 proxy overhead is < 5ms. Measured with autocannon, gated in CI on every commit.

</details>

<details>
<summary><strong>Can I use it with local models (Ollama)?</strong></summary>

Yes. Sentinel auto-detects Ollama at `127.0.0.1:11434`. Set `x-sentinel-target: ollama`.

</details>

<details>
<summary><strong>How is this different from LLM Guard / Rebuff / NeMo Guardrails?</strong></summary>

Sentinel has 81 security engines (more than all competitors combined), runs fully local, uses 9 dependencies (vs hundreds), and includes formal verification specs. See the [competitor comparison](docs/benchmarks/COMPETITOR_COMPARISON.md) for details.

</details>

<details>
<summary><strong>Is it production-ready?</strong></summary>

567 tests, 0 failures, 0 lint warnings, CI regression gates on every commit, circuit breakers, retry with backoff, provider failover, forensic replay. Yes.

</details>

<details>
<summary><strong>Does Sentinel send any data to external servers?</strong></summary>

No. Sentinel runs **entirely on your local machine**. All 81 security engines process data locally. The only outbound network calls are the ones YOUR app already makes to LLM providers (OpenAI, Anthropic, etc.) — Sentinel just sits in the middle, on your machine, inspecting them. No telemetry, no analytics, no phone-home.

</details>

<details>
<summary><strong>Who hosts the endpoints?</strong></summary>

You do. Every endpoint (`/_sentinel/health`, `/_sentinel/playground`, etc.) is served from YOUR local machine on `127.0.0.1`. Nothing is hosted externally. When you `git clone` and run Sentinel, everything runs on your hardware.

</details>

<details>
<summary><strong>Is there any liability for running this?</strong></summary>

Sentinel is MIT-licensed open-source software provided "as is" without warranty. You clone the code, you run it on your machine, you control it entirely. There is no SaaS component, no external dependency for security decisions, and no data ever leaves your device unless you explicitly configure it.

</details>

---

## 🤝 Contributing

We welcome contributions! See:

- [Contributing Guide](CONTRIBUTING.md)
- [Plugin Tutorial](docs/PLUGIN_TUTORIAL.md)
- [Integrations Guide](docs/INTEGRATIONS.md)
- [Triage Runbook](docs/TRIAGE_RUNBOOK.md)
- [Outage Runbook](docs/OUTAGE-RUNBOOK.md)

---

## 🌍 Open Source

Sentinel Protocol is **fully open-source** under the [MIT License](LICENSE).

- ✅ **Free forever** — no paid tiers, no feature gates, no "enterprise edition"
- ✅ **Fork-friendly** — modify, extend, redistribute without restriction
- ✅ **Self-contained** — clone → run → protected. No accounts, no sign-ups
- ✅ **Community-driven** — PRs, issues, and feature requests welcome

---

## 📄 License

[MIT](LICENSE) — free to use, modify, and distribute.

---

<div align="center">

**Built with obsessive engineering discipline.**<br />
**75,000+ lines. 81 engines. 567 tests. 9 dependencies. Zero compromises.**<br />
**Clone it. Run it locally. Own your AI security.**

<br />

⭐ **Star this repo** if you believe AI security should be free, local, and open.

</div>
