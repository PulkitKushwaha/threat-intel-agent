"""
tools/actor.py — Threat-actor (Actor & TTP) lookups from a local knowledge base.

Unlike ioc.py (which calls live APIs), this tool reads a curated local
knowledge base (data/actors.json) derived from MITRE ATT&CK. Actor TTPs are
stable reference data, so a local KB is the right design:
  • Demo-safe — no network, can't rate-limit or time out.
  • Grounded — every TTP cites its real MITRE technique ID + the group's
    ATT&CK page, so answers remain attributable (no fabricated intel).
  • Fast — loaded once, searched in-memory.

Resolves actor names AND aliases (case-insensitive), e.g. "Cozy Bear",
"Nobelium", or "Midnight Blizzard" all map to APT29.
"""

import os
import json

# ---------------------------------------------------------------------------
# Load the knowledge base once at import time.
# ---------------------------------------------------------------------------
# data/ lives at the project root; this file is in tools/, so go up one level.
_KB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "actors.json")

try:
    with open(os.path.abspath(_KB_PATH), "r", encoding="utf-8") as f:
        _KB = json.load(f)
    _ACTORS = _KB.get("actors", {})
except FileNotFoundError:
    _KB = {}
    _ACTORS = {}


# ---------------------------------------------------------------------------
# Build a fast alias → canonical-name index (case-insensitive).
# ---------------------------------------------------------------------------
def _build_index() -> dict:
    """Map every canonical name AND alias (lowercased) to the canonical key."""
    index = {}
    for canonical, data in _ACTORS.items():
        index[canonical.lower()] = canonical
        for alias in data.get("aliases", []):
            index[alias.lower()] = canonical
    return index


_INDEX = _build_index()


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def lookup_actor(name: str) -> dict:
    """
    Look up a threat actor by name or alias and return their profile + TTPs.

    Returns (found):
        {
          "actor": "APT29",
          "aliases": [...],
          "attribution": "Russia (SVR)",
          "description": "...",
          "ttps": [ {id, name, tactic}, ... ],
          "notable_campaigns": [...],
          "sources": ["https://attack.mitre.org/groups/G0016/"],
          "errors": []
        }

    Returns (not found):
        { "actor": <name>, "verdict": "...", "sources": [], "errors": [...] }
    """
    if not name or not name.strip():
        return {
            "actor": None,
            "verdict": "No threat-actor name was provided in the query.",
            "ttps": [],
            "sources": [],
            "errors": ["Missing actor name."],
        }

    if not _ACTORS:
        return {
            "actor": name,
            "verdict": "Actor knowledge base could not be loaded.",
            "ttps": [],
            "sources": [],
            "errors": [f"KB not found at {os.path.abspath(_KB_PATH)}"],
        }

    key = _INDEX.get(name.strip().lower())

    if key is None:
        known = ", ".join(sorted(_ACTORS.keys()))
        return {
            "actor": name,
            "verdict": (
                f"'{name}' was not found in the knowledge base. "
                f"Known actors: {known}."
            ),
            "ttps": [],
            "sources": [_KB.get("_meta", {}).get("framework_url", "")],
            "errors": ["Actor not in knowledge base."],
        }

    a = _ACTORS[key]
    return {
        "actor": key,
        "aliases": a.get("aliases", []),
        "attribution": a.get("attribution"),
        "description": a.get("description"),
        "ttps": a.get("ttps", []),
        "notable_campaigns": a.get("notable_campaigns", []),
        "sources": [a.get("source")],
        "errors": [],
    }


# ---------------------------------------------------------------------------
# Quick manual test:  python tools/actor.py "APT29"
#                     python tools/actor.py "Cozy Bear"
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "APT29"
    print(f"\nLooking up actor: {target}\n" + "-" * 40)
    print(json.dumps(lookup_actor(target), indent=2))
