"""
agent/state.py — The shared state that flows through the LangGraph.

In LangGraph, EVERY node receives this state, may read from it, and returns
a dict of updates that LangGraph merges back in. Think of it as a clipboard
that gets passed hand-to-hand down the assembly line — each station adds
something to it.

We use a TypedDict (LangGraph's native state type). It gives us key names
and type hints without the overhead of a full class.
"""

from typing import TypedDict, Optional, List, Dict, Any


class AgentState(TypedDict, total=False):
    # --- Input ---
    user_input: str                      # the analyst's raw message

    # --- Guard node writes this ---
    blocked: bool                        # True if prompt-injection detected
    block_reason: Optional[str]

    # --- Router node writes this ---
    intent: str                          # ioc_lookup | actor_ttp | exposure | pivot | follow_up | unknown
    entities: Dict[str, Any]             # extracted {ip, domain, hash, actor, software, version}

    # --- Tool node writes this ---
    result: Dict[str, Any]               # structured output from the specialist tool

    # --- Synth node writes this ---
    answer: str                          # final grounded, cited answer for the analyst

    # --- Observability (every node appends) ---
    trace: List[Dict[str, Any]]          # step-by-step record → wins the observability bonus

    # --- Multi-turn memory (persists across turns via Streamlit session_state) ---
    memory: Dict[str, Optional[str]]     # {last_ip, last_domain, last_hash, last_actor}
