"""
agent/confidence.py — Confidence scoring for tool findings (BONUS).

Attaches a transparent, rule-based confidence level to each tool result so the
analyst knows how much to trust a verdict. Rule-based (not LLM-guessed) keeps it
explainable and deterministic — which is what a SOC analyst needs.

Usage (in graph.tool_node, right after a tool returns `result`):
    from agent import confidence
    result = confidence.score(intent, result)
"""


def _ioc_confidence(result: dict) -> dict:
    """Confidence from how many independent sources agree an IOC is malicious."""
    findings = result.get("findings", [])
    vt = next((f for f in findings if f["source"] == "VirusTotal"), {})
    abuse = next((f for f in findings if f["source"] == "AbuseIPDB"), {})
    otx = next((f for f in findings if f["source"] == "AlienVault OTX"), {})

    signals = 0
    if vt.get("malicious", 0) >= 3:
        signals += 1
    if abuse.get("abuse_confidence", 0) >= 50:
        signals += 1
    if otx.get("pulse_count", 0) >= 1:
        signals += 1

    sources_ok = len(findings)
    if signals >= 2:
        level, pct = "high", 90
    elif signals == 1:
        level, pct = "medium", 60
    elif sources_ok >= 2:
        level, pct = "high", 85  # multiple sources agree it's clean
    else:
        level, pct = "low", 40

    reason = f"{signals} of 3 sources flagged malicious; {sources_ok} sources responded."
    return {"level": level, "percent": pct, "reason": reason}


def _exposure_confidence(result: dict) -> dict:
    """Confidence from CVE match quality + how many CVEs were found."""
    n = result.get("cve_count", 0)
    if n == 0:
        return {"level": "medium", "percent": 55,
                "reason": "No CVEs matched; absence of results is not proof of safety."}
    has_critical = any(c.get("severity") == "CRITICAL" for c in result.get("cves", []))
    if has_critical and n >= 2:
        return {"level": "high", "percent": 90,
                "reason": f"{n} CVEs incl. critical severity matched from NVD."}
    return {"level": "medium", "percent": 70,
            "reason": f"{n} CVEs matched from NVD."}


def _actor_confidence(result: dict) -> dict:
    """Actor data comes from a curated MITRE KB → high if found."""
    if result.get("ttps"):
        return {"level": "high", "percent": 95,
                "reason": "Sourced from curated MITRE ATT&CK knowledge base."}
    return {"level": "low", "percent": 30, "reason": "Actor not found in knowledge base."}


def _pivot_confidence(result: dict) -> dict:
    """Confidence scales with how many related entities were returned."""
    n = result.get("count", 0)
    if n >= 3:
        return {"level": "high", "percent": 85, "reason": f"{n} related entities from VirusTotal."}
    if n >= 1:
        return {"level": "medium", "percent": 60, "reason": f"{n} related entities from VirusTotal."}
    return {"level": "low", "percent": 30, "reason": "No related entities found."}


def score(intent: str, result: dict) -> dict:
    """Attach a 'confidence' block to a tool result based on its intent type."""
    if not isinstance(result, dict):
        return result
    try:
        if intent == "ioc_lookup" or intent == "follow_up":
            result["confidence"] = _ioc_confidence(result)
        elif intent == "exposure":
            result["confidence"] = _exposure_confidence(result)
        elif intent == "actor_ttp":
            result["confidence"] = _actor_confidence(result)
        elif intent == "pivot":
            result["confidence"] = _pivot_confidence(result)
    except Exception:
        # Confidence is a nice-to-have; never let it break a real answer.
        pass
    return result
