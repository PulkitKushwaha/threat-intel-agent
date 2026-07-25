"""
app.py — Streamlit chat UI for the Conversational Threat-Intelligence Agent.

Professional, readable UI using well-known Streamlit patterns:
  • st.chat_message / st.chat_input        — standard chat layout
  • Semantic verdict banners               — cold blue default, green safe,
                                             amber suspicious, red malicious only
  • Intent + guard "chips"                  — colored by meaning (green greeting)
  • Clean, icon-led execution trace         — readable observability
  • Sidebar: capabilities, memory, quick queries, reset

Memory (in st.session_state):
  1. Entity memory (last_ip / domain / hash / actor) → resolves "that IP"
  2. History window (last 3 exchanges)              → conversational context

Run from the project root:
    streamlit run app.py
"""

import time
import streamlit as st

from agent.graph import agent_app
from agent.state import AgentState

HISTORY_WINDOW = 6  # 3 user + 3 assistant messages


# ===========================================================================
# Page config + light styling
# ===========================================================================
st.set_page_config(
    page_title="Threat Intelligence Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
      /* --- info chips --- */
      .chip {
        display:inline-block; padding:2px 10px; margin:2px 6px 2px 0;
        border-radius:12px; font-size:0.78rem; font-weight:600;
        background:#eef2f7; color:#1f2d3d; border:1px solid #d7dee8;
      }
      .chip-danger  { background:#fdecec; color:#b3261e; border-color:#f5c2c0; }
      .chip-warn    { background:#fff5e6; color:#98590a; border-color:#f5dcae; }
      .chip-ok      { background:#eaf6ec; color:#1e6b32; border-color:#bfe3c6; }
      .chip-info    { background:#e9f1fb; color:#1c4e8a; border-color:#c2d8f2; }
      .step-line    { font-family:ui-monospace,Menlo,Consolas,monospace;
                      font-size:0.82rem; padding:1px 0; }

      /* --- cold light-blue banner for normal bot answers --- */
      .bot-info {
        background:#eef4fc; border:1px solid #cfe0f5; color:#12395f;
        padding:12px 14px; border-radius:10px; line-height:1.5;
      }
    </style>
    """,
    unsafe_allow_html=True,
)


# ===========================================================================
# Session state
# ===========================================================================
if "messages" not in st.session_state:
    st.session_state.messages = []
if "memory" not in st.session_state:
    st.session_state.memory = {}


# ===========================================================================
# Helpers
# ===========================================================================
def build_history() -> str:
    recent = st.session_state.messages[-HISTORY_WINDOW:]
    return "\n".join(
        f"{'Analyst' if m['role']=='user' else 'Assistant'}: {m['content']}"
        for m in recent
    )


def guard_category(trace: list) -> str:
    g = next((s for s in trace if s.get("step") == "guard"), {})
    return g.get("category", "safe")


def verdict_kind(answer: str, trace: list) -> str:
    """
    Choose a banner style. Order matters: BENIGN / negation phrases are checked
    BEFORE danger keywords, so "does not appear malicious" is green, not red.

      greeting  → green (friendly)
      blocked   → red  (injection / scope violations only)
      ok        → green(benign / safe)
      danger    → red  (genuinely malicious / exposed / critical)
      warn      → amber(suspicious / medium)
      info      → cold light blue (default, neutral)
    """
    cat = guard_category(trace)
    if cat == "greeting":
        return "greeting"
    if answer.startswith("⛔") or cat in ("direct_injection", "indirect_injection", "out_of_scope"):
        return "blocked"

    low = answer.lower()

    # 1) BENIGN / negation FIRST — these often contain the word "malicious".
    benign_phrases = [
        "not malicious", "does not appear malicious", "not appear malicious",
        "likely benign", "appears benign", "is benign", "no exposure",
        "not currently indicated", "no known cves", "no known vulnerabilities",
        "likely safe", "not exposed",
    ]
    if any(p in low for p in benign_phrases):
        return "ok"

    # 2) Genuine danger.
    if any(w in low for w in ["exposed", "critical-severity", "patch urgently",
                              "high-severity", "malicious (high", "high confidence"]):
        return "danger"

    # 3) Suspicious / medium.
    if any(w in low for w in ["suspicious", "potentially exposed", "medium-severity"]):
        return "warn"

    # 4) Default: neutral cold blue.
    return "info"


def chips_from_trace(trace: list) -> str:
    chips = []
    guard = next((s for s in trace if s.get("step") == "guard"), {})
    router = next((s for s in trace if s.get("step") == "router"), {})

    if guard:
        cat = guard.get("category", "safe")
        if cat in ("direct_injection", "indirect_injection", "out_of_scope"):
            cls = "chip-danger"
        else:  # safe, greeting
            cls = "chip-ok"
        chips.append(f'<span class="chip {cls}">🛡️ guard: {cat}</span>')
    if router.get("intent"):
        chips.append(f'<span class="chip chip-info">🧭 intent: {router["intent"]}</span>')
    return "".join(chips)


def render_trace(trace: list):
    icons = {"guard": "🛡️", "router": "🧭", "tools": "🔧", "synth": "📝"}
    for step in trace:
        name = step.get("step", "?")
        icon = icons.get(name, "•")
        detail = {k: v for k, v in step.items() if k != "step"}
        st.markdown(
            f'<div class="step-line">{icon} <b>{name}</b> — {detail}</div>',
            unsafe_allow_html=True,
        )


def render_answer(answer: str, trace: list, elapsed: float = None):
    kind = verdict_kind(answer, trace)

    if kind == "blocked":
        st.error(answer)                    # red — security block
    elif kind == "danger":
        st.error(answer)                    # red — genuinely malicious/exposed
    elif kind == "warn":
        st.warning(answer)                  # amber — suspicious
    elif kind in ("ok", "greeting"):
        st.success(answer)                  # green — benign / friendly greeting
    else:
        st.markdown(f'<div class="bot-info">{answer}</div>', unsafe_allow_html=True)  # cold blue

    chip_html = chips_from_trace(trace)
    if elapsed is not None:
        chip_html += f'<span class="chip">⏱️ {elapsed:.1f}s</span>'
    if chip_html:
        st.markdown(chip_html, unsafe_allow_html=True)

    if trace:
        with st.expander("🔍 Execution trace (tool calls & steps)"):
            render_trace(trace)


# ===========================================================================
# Header
# ===========================================================================
st.title("🛡️ Threat Intelligence Agent")
st.caption(
    "Natural-language SOC assistant · IOC reputation · Actor TTPs · "
    "CVE exposure · Entity pivoting — grounded, cited, injection-resistant."
)
st.divider()


# ===========================================================================
# Sidebar
# ===========================================================================
with st.sidebar:
    st.header("🧭 Capabilities")
    st.markdown(
        "- 🔍 **IOC lookup** — IP / domain / hash\n"
        "- 🎭 **Actor & TTP** — e.g. APT29\n"
        "- 🛡️ **Exposure** — software → CVEs\n"
        "- 🔗 **Pivot** — related entities\n"
        "- 💬 **Follow-ups** — “that IP”, “its ASN”"
    )

    st.divider()
    st.subheader("⚡ Quick queries")
    examples = [
        "Is 45.83.122.10 malicious?",
        "What TTPs is APT29 known for?",
        "We run Confluence 7.13 — are we exposed?",
        "Pivot from that IP to related domains",
    ]
    for ex in examples:
        if st.button(ex, use_container_width=True):
            st.session_state.staged_query = ex

    st.divider()
    st.subheader("🧠 Session memory")
    if any(st.session_state.memory.values()):
        for k, v in st.session_state.memory.items():
            if v:
                st.markdown(f"<span class='chip chip-info'>{k}: {v}</span>",
                            unsafe_allow_html=True)
    else:
        st.caption("No entities remembered yet.")
    st.caption(f"History window: last {HISTORY_WINDOW // 2} exchanges")

    st.divider()
    if st.button("🔄 Clear conversation", use_container_width=True, type="primary"):
        st.session_state.messages = []
        st.session_state.memory = {}
        st.rerun()


# ===========================================================================
# Render existing transcript
# ===========================================================================
for msg in st.session_state.messages:
    with st.chat_message(msg["role"], avatar="🧑‍💻" if msg["role"] == "user" else "🛡️"):
        if msg["role"] == "assistant":
            render_answer(msg["content"], msg.get("trace", []), msg.get("elapsed"))
        else:
            st.markdown(msg["content"])   # normal user bubble


# ===========================================================================
# Chat input (typed OR staged from an example button)
# ===========================================================================
typed = st.chat_input("Ask a threat-intelligence question…")
staged = st.session_state.pop("staged_query", None)
prompt = typed or staged

if prompt:
    history = build_history()

    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user", avatar="🧑‍💻"):
        st.markdown(prompt)   # normal user bubble

    with st.chat_message("assistant", avatar="🛡️"):
        with st.spinner("Analyzing threat intelligence…"):
            initial: AgentState = {
                "user_input": prompt,
                "history": history,
                "trace": [],
                "memory": st.session_state.memory,
            }
            start = time.time()
            try:
                final = agent_app.invoke(initial)
                answer = final.get("answer", "_(no answer produced)_")
                trace = final.get("trace", [])
                st.session_state.memory = final.get("memory", st.session_state.memory)
            except Exception as e:
                answer = f"⚠️ Something went wrong: `{str(e)[:200]}`"
                trace = [{"step": "error", "detail": str(e)[:200]}]
            elapsed = time.time() - start

        render_answer(answer, trace, elapsed)

    st.session_state.messages.append(
        {"role": "assistant", "content": answer, "trace": trace, "elapsed": elapsed}
    )
