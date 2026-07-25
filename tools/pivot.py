"""
tools/pivot.py — Pivoting: move from one entity to related entities.

Handles queries like:
  "Pivot from that IP to related domains."
  "What domains are related to 45.83.122.10?"

This is where PIVOTING meets MULTI-TURN CONTEXT: the word "that IP" is
resolved upstream (in the graph's tool_node) against conversation memory,
then handed here as a concrete indicator.

Data source: VirusTotal v3 "relationships" endpoints, which expose the
entities connected to an IP or domain:
  • IP     → resolutions (domains that resolved to this IP)
             communicating_files (malware seen talking to it)
  • domain → resolutions (IPs this domain resolved to)
             subdomains

Design principles (same as ioc.py):
  • Live API first, graceful degradation on failure — never crash.
  • Every pivoted entity carries a source URL (no fabricated intel).
  • Returns a predictable structured dict.
"""

import os
import re
import requests
from dotenv import load_dotenv

load_dotenv()

VT_KEY = os.getenv("VT_API_KEY")
TIMEOUT = 15

# Cap how many related entities we return per relationship (focus + cost).
RELATION_LIMIT = 10


# ---------------------------------------------------------------------------
# Entity-type detection (lightweight — pivot only needs ip vs domain)
# ---------------------------------------------------------------------------
def _detect_type(value: str) -> str:
    value = value.strip()
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value):
        return "ip"
    if re.fullmatch(r"(?=.{1,253}$)(?!-)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+", value):
        return "domain"
    return "unknown"


# ---------------------------------------------------------------------------
# VirusTotal relationship query
# ---------------------------------------------------------------------------
def _vt_relationship(entity: str, entity_type: str, relationship: str) -> list:
    """
    Fetch a single relationship collection for an IP or domain from VT.
    Returns a list of related entity identifiers (strings).
    """
    base = "https://www.virustotal.com/api/v3"
    path = "ip_addresses" if entity_type == "ip" else "domains"
    url = f"{base}/{path}/{entity}/{relationship}"

    r = requests.get(
        url,
        headers={"x-apikey": VT_KEY},
        params={"limit": RELATION_LIMIT},
        timeout=TIMEOUT,
    )
    r.raise_for_status()
    items = r.json().get("data", [])

    related = []
    for it in items:
        # For resolutions, the useful id differs by direction; fall back to 'id'.
        attrs = it.get("attributes", {})
        ident = (
            attrs.get("host_name")      # domain for an IP's resolutions
            or attrs.get("ip_address")  # IP for a domain's resolutions
            or it.get("id")             # generic fallback (e.g. file hash)
        )
        if ident:
            related.append(ident)
    return related


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def pivot(entity: str, target: str = "domains") -> dict:
    """
    Pivot from an IP or domain to related entities.

    Args:
        entity: the IP or domain to pivot FROM (already resolved from context).
        target: what to pivot TO — "domains" (default) or "ips".

    Returns:
        {
          "entity": "45.83.122.10",
          "entity_type": "ip",
          "pivot_target": "domains",
          "related": ["evil.com", "bad.net", ...],
          "count": 2,
          "sources": ["https://www.virustotal.com/gui/ip-address/45.83.122.10/relations"],
          "errors": []
        }
    """
    if not entity or not entity.strip():
        return {
            "entity": entity,
            "entity_type": "unknown",
            "pivot_target": target,
            "related": [],
            "count": 0,
            "sources": [],
            "errors": ["No entity provided to pivot from (nothing in context)."],
        }

    entity = entity.strip()
    entity_type = _detect_type(entity)
    if entity_type == "unknown":
        return {
            "entity": entity,
            "entity_type": "unknown",
            "pivot_target": target,
            "related": [],
            "count": 0,
            "sources": [],
            "errors": ["Entity is not a recognizable IP or domain."],
        }

    # Choose which VT relationship(s) to query based on the pivot direction.
    if entity_type == "ip":
        # From an IP, "related domains" = passive-DNS resolutions.
        relationships = ["resolutions"] if target == "domains" else ["communicating_files"]
    else:
        # From a domain, pivot to resolving IPs (or subdomains).
        relationships = ["resolutions"] if target == "ips" else ["subdomains"]

    related, errors = [], []
    for rel in relationships:
        try:
            related.extend(_vt_relationship(entity, entity_type, rel))
        except Exception as e:
            errors.append(f"VirusTotal[{rel}]: {str(e)[:80]}")

    # De-duplicate while preserving order, then cap.
    seen = set()
    deduped = []
    for item in related:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    deduped = deduped[:RELATION_LIMIT]

    gui = "ip-address" if entity_type == "ip" else "domain"
    return {
        "entity": entity,
        "entity_type": entity_type,
        "pivot_target": target,
        "related": deduped,
        "count": len(deduped),
        "sources": [f"https://www.virustotal.com/gui/{gui}/{entity}/relations"],
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# Quick manual test:  python tools/pivot.py 8.8.8.8
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    import json

    target_entity = sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"
    print(f"\nPivoting from: {target_entity}\n" + "-" * 40)
    print(json.dumps(pivot(target_entity), indent=2))
