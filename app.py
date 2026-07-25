"""
app.py — Streamlit chat UI for the Conversational Threat-Intelligence Agent.

Professional, readable UI using well-known Streamlit patterns:
  • st.chat_message / st.chat_input        — standard chat layout
  • Color-coded verdict banners            — st.error/warning/success (scannable)
  • Intent + confidence "chips"            — st.caption + inline badges
  • Clean, icon-led execution trace        — readable observability
  • Sidebar with capabilities, memory,     — orientation + controls
    example one-click queries, and reset

Two memory layers persist in st.session_state:
  1. Entity memory (last_ip / domain / hash / actor)  → resolves "that IP"
  2. History window (last 3 exchanges)                → conversational context

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

# Minimal CSS for a professional feel (chips, spacing) — readability preserved.
st.markdown(
    """
    <style>
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
    """Last HISTORY_WINDOW messages as a readable transcript for the LLM."""
    recent = st.session_state.messages[-HISTORY_WINDOW:]
    return "\n".join(
        f"{'Analyst' if m['role']=='user' else 'Assistant'}: {m['content']}"
        for m in recent
    )


def verdict_kind(answer: str) -> str:
    """Classify the answer text to pick a banner color (scannable at a glance)."""
    low = answer.lower()
    if answer.startswith("⛔"):
        return "blocked"
    if any(w in low for w in ["malicious", "exposed", "critical", "high-severity", "patch urgently"]):
        return "danger"
    if any(w in low for w in ["suspicious", "medium", "potentially"]):
        return "warn"
    if any(w in low for w in ["benign", "not malicious", "no exposure", "likely safe"]):
        return "ok"
    return "info"


def chips_from_trace(trace: list) -> str:
    """Build small HTML chips summarizing intent + confidence + guard category."""
    chips = []
    guard = next((s for s in trace if s.get("step") == "guard"), {})
    router = next((s for s in trace if s.get("step") == "router"), {})

    if guard:
        cat = guard.get("category", "safe")
        cls = "chip-ok" if guard.get("allow") else "chip-danger"
        chips.append(f'<span class="chip {cls}">🛡️ guard: {cat}</span>')
    if router.get("intent"):
        chips.append(f'<span class="chip chip-info">🧭 intent: {router["intent"]}</span>')
    return "".join(chips)


def render_trace(trace: list):
    """Readable, icon-led execution trace."""
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
    """Render an assistant answer with a color banner, chips, and trace."""
    kind = verdict_kind(answer)

    # Color-coded banner for the headline verdict
    if kind == "blocked":
        st.error(answer)
    elif kind == "danger":
        st.error(answer)
    elif kind == "warn":
        st.warning(answer)
    elif kind == "ok":
        st.success(answer)
    else:
        st.markdown(answer)

    # Chips row (intent / guard) + optional timing
    chip_html = chips_from_trace(trace)
    if elapsed is not None:
        chip_html += f'<span class="chip">⏱️ {elapsed:.1f}s</span>'
    if chip_html:
        st.markdown(chip_html, unsafe_allow_html=True)

    # Observability trace
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
    # Clickable example buttons — stage a query for the input loop.
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
            st.markdown(msg["content"])


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
        st.markdown(prompt)

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
