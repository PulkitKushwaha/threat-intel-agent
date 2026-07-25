"""
app.py — Streamlit chat UI for the Conversational Threat-Intelligence Agent.

This is the human-facing front end for the LangGraph agent. It provides:
  • A natural-language chat interface (Conversational UX)
  • TRUE multi-turn memory via st.session_state — two layers:
      1. ENTITY memory  → last_ip / last_domain / last_actor (resolves "that IP")
      2. HISTORY window → the last 3 exchanges of raw conversation, passed to
         the LLM so it has genuine conversational context ("what did we discuss?")
  • A live, per-message execution trace in an expander (observability bonus).

Run it from the project root:
    streamlit run app.py

Why session_state matters:
  Streamlit re-runs this whole script on every interaction. st.session_state
  is the one thing that PERSISTS across those re-runs — so we store both the
  chat history and the agent's entity-memory there.
"""

import streamlit as st

from agent.graph import agent_app
from agent.state import AgentState

# How many recent messages to feed the LLM as context.
# 6 messages = 3 user/assistant exchanges. This is our context-window control
# (also caps token spend → Cost & Rate-Limits bonus).
HISTORY_WINDOW = 6


# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Threat Intelligence Agent",
    page_icon="🛡️",
    layout="centered",
)

st.title("🛡️ Threat Intelligence Agent")
st.caption(
    "Ask about IOCs, threat actors, software exposure, or pivot between entities. "
    "Answers are grounded in live threat-intel sources with citations."
)


# ---------------------------------------------------------------------------
# Session state — persists across Streamlit re-runs (this IS our memory layer)
# ---------------------------------------------------------------------------
if "messages" not in st.session_state:
    # Chat transcript shown in the UI: list of {role, content, trace}
    st.session_state.messages = []

if "memory" not in st.session_state:
    # The agent's entity-memory: last_ip, last_domain, last_hash, last_actor...
    st.session_state.memory = {}


# ---------------------------------------------------------------------------
# Helper: build a short rolling history window from recent turns
# ---------------------------------------------------------------------------
def build_history() -> str:
    """Return the last HISTORY_WINDOW messages as a readable transcript string."""
    recent = st.session_state.messages[-HISTORY_WINDOW:]
    lines = []
    for m in recent:
        role = "Analyst" if m["role"] == "user" else "Assistant"
        lines.append(f"{role}: {m['content']}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Sidebar — helper info + example queries + reset
# ---------------------------------------------------------------------------
with st.sidebar:
    st.header("💡 Try asking")
    st.markdown(
        "- `Is 45.83.122.10 malicious?`\n"
        "- `What TTPs is APT29 known for?`\n"
        "- `We run Confluence 7.13 — are we exposed?`\n"
        "- `Pivot from that IP to related domains`\n"
        "- `And what's its ASN?`"
    )
    st.divider()
    st.subheader("🧠 Session memory")
    if st.session_state.memory:
        for k, v in st.session_state.memory.items():
            if v:
                st.text(f"{k}: {v}")
    else:
        st.caption("No entities remembered yet.")

    st.caption(f"History window: last {HISTORY_WINDOW // 2} exchanges")

    if st.button("🔄 Clear conversation"):
        st.session_state.messages = []
        st.session_state.memory = {}
        st.rerun()


# ---------------------------------------------------------------------------
# Render the existing chat transcript
# ---------------------------------------------------------------------------
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])
        if msg["role"] == "assistant" and msg.get("trace"):
            with st.expander("🔍 Execution trace (tool calls & steps)"):
                for step in msg["trace"]:
                    st.code(str(step), language="python")


# ---------------------------------------------------------------------------
# Chat input — the main interaction loop
# ---------------------------------------------------------------------------
if prompt := st.chat_input("Ask a threat-intelligence question…"):

    # Build the history window BEFORE appending the new message,
    # so it reflects prior turns only.
    history = build_history()

    # 1) Show + store the user's message
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    # 2) Run the agent
    with st.chat_message("assistant"):
        with st.spinner("Analyzing…"):
            initial: AgentState = {
                "user_input": prompt,
                "history": history,                    # ← rolling context window
                "trace": [],
                "memory": st.session_state.memory,     # ← persisted entity memory
            }

            try:
                final = agent_app.invoke(initial)
                answer = final.get("answer", "_(no answer produced)_")
                trace = final.get("trace", [])
                # Persist updated entity memory for the next turn.
                st.session_state.memory = final.get("memory", st.session_state.memory)
            except Exception as e:
                answer = f"⚠️ Something went wrong: `{str(e)[:200]}`"
                trace = [{"step": "error", "detail": str(e)[:200]}]

        # 3) Render the answer + its trace
        st.markdown(answer)
        if trace:
            with st.expander("🔍 Execution trace (tool calls & steps)"):
                for step in trace:
                    st.code(str(step), language="python")

    # 4) Store the assistant turn (with its trace) in the transcript
    st.session_state.messages.append(
        {"role": "assistant", "content": answer, "trace": trace}
    )
