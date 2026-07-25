# Design Note — Conversational Threat Intelligence Agent

**Scope:** intent routing + injection defense (per assessment requirements).
**Stack:** LangGraph · Azure OpenAI (structured outputs) · Pydantic · Streamlit.

---

## 1. Architecture Overview

The agent is a **LangGraph `StateGraph`** — a single reasoning orchestrator with
specialized tools, not an autonomous multi-agent swarm. This is a deliberate
*production-judgment* choice: for a security tool, a deterministic control flow
is more **reliable, testable, and debuggable** than an open-ended ReAct loop
(which also makes "consistent behaviour across runs" far easier to guarantee).

```
User → guard → router → tools → synth → answer
         │(blocked: injection / scope / greeting) → END
```

A typed `AgentState` flows through every node. Two memory layers live in it:
- **Entity memory** — `last_ip / last_domain / last_hash / last_actor`, used to
  resolve references like *"that IP"* / *"its ASN"*.
- **History window** — the last 3 exchanges, giving the LLM conversational
  context while capping token spend.

---

## 2. Intent Routing

**How each query reaches the right tool:**

1. **`router` node** sends the message (plus recent history) to Azure OpenAI with
   **structured outputs** — the model is constrained at generation time to a
   Pydantic `RouterDecision` schema:

   ```
   intent ∈ {ioc_lookup, actor_ttp, exposure, pivot, follow_up, unknown}
   entities = {ip, domain, hash, actor, software, version}
   ```

2. Because the schema is **enforced by the API**, the model *cannot* emit an
   invalid intent (e.g. an earlier bug where it returned `ioc_reputation`
   became structurally impossible). A `try/except` fallback to `unknown`
   guarantees the graph never crashes on a routing hiccup.

3. The **`tools` node** dispatches on `intent` to one specialist tool:

   | Intent | Tool | Data source |
   |--------|------|-------------|
   | `ioc_lookup` | `tools/ioc` | VirusTotal + AbuseIPDB + OTX (live) |
   | `actor_ttp`  | `tools/actor` | MITRE ATT&CK (local KB) |
   | `exposure`   | `tools/exposure` | NVD CVE API (live) |
   | `pivot`      | `tools/pivot` | VirusTotal relationships (live) |
   | `follow_up`  | resolved via entity memory |

Deterministic IOC-type detection (regex for IP/hash/domain) is done in-tool, so
the LLM is used only where reasoning is genuinely needed — controlling cost.

---

## 3. Injection Defense (Defense in Depth)

Four independent layers protect the agent; a miss at one layer is caught by the
next.

**Direct injection** (typed in chat):
- **L0 — Platform:** Azure OpenAI content-safety filter (upstream).
- **L1 — Keyword pre-filter:** instant, zero-cost block on known phrases
  ("ignore previous instructions", "reveal your system prompt", "which model
  are you", …).
- **L2 — LLM guard:** a structured-output `GuardVerdict` classifier catches
  paraphrased attacks the keywords miss, and enforces **scope** (off-topic
  requests are refused; greetings get a warm onboarding reply instead of a cold
  block).

**Indirect injection** (hidden inside retrieved threat data):
- **L3 — Untrusted-data sanitizer:** all tool output is wrapped in explicit
  `<<<UNTRUSTED_THREAT_DATA>>>` delimiters before reaching the synthesis LLM,
  which is instructed to treat it strictly as **data, never instructions**.

**Fail-closed principle:** if Azure's content filter rejects an input (raising an
error), the guard treats that rejection as a **block**, never bypasses it. Only
genuine transient errors (network/timeout) degrade gracefully to allow, and only
after the keyword filter has already cleared the input.

---

## 4. Grounding & Reliability

- **No fabricated intel:** synthesis answers *only* from tool data; every finding
  carries its source URL. Missing data is stated explicitly, not invented.
- **Graceful degradation:** each tool isolates failures per-source and returns a
  clean error result rather than crashing.
- **Observability:** every node appends to a `trace`, surfaced live in the UI —
  making tool calls and routing decisions fully inspectable.

