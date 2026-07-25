"""
tools/ioc.py — Indicator-of-Compromise (IOC) reputation lookups.

Given an IP address, domain, or file hash, this queries multiple
threat-intelligence sources, correlates the results, and returns a
single structured verdict with source attribution.

Design principles:
  • Live API first, graceful fallback on failure (demo resilience).
  • Every finding carries its source URL (no fabricated intel).
  • Returns plain dicts — the agent layer decides how to present them.

Sources:
  • VirusTotal  (IP / domain / hash)
  • AbuseIPDB   (IP only)
  • AlienVault OTX (IP / domain / hash — pulse count)
"""

import os
import re
import requests
from dotenv import load_dotenv

load_dotenv()

VT_KEY = os.getenv("VT_API_KEY")
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")
OTX_KEY = os.getenv("OTX_API_KEY")

TIMEOUT = 15


# ---------------------------------------------------------------------------
# IOC type detection
# ---------------------------------------------------------------------------
def detect_ioc_type(value: str) -> str:
    """Classify a raw string as 'ip', 'hash', 'domain', or 'unknown'."""
    value = value.strip()

    # IPv4
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value):
        return "ip"

    # Hashes: MD5 (32), SHA-1 (40), SHA-256 (64) hex chars
    if re.fullmatch(r"[a-fA-F0-9]{32}", value):
        return "hash"
    if re.fullmatch(r"[a-fA-F0-9]{40}", value):
        return "hash"
    if re.fullmatch(r"[a-fA-F0-9]{64}", value):
        return "hash"

    # Domain (very light check — good enough for routing)
    if re.fullmatch(r"(?=.{1,253}$)(?!-)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+", value):
        return "domain"

    return "unknown"


# ---------------------------------------------------------------------------
# Individual source queries
# ---------------------------------------------------------------------------
def _virustotal(ioc: str, ioc_type: str) -> dict:
    """Query VirusTotal v3 for an IP, domain, or file hash."""
    endpoint_map = {
        "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}",
        "domain": f"https://www.virustotal.com/api/v3/domains/{ioc}",
        "hash": f"https://www.virustotal.com/api/v3/files/{ioc}",
    }
    url = endpoint_map[ioc_type]
    r = requests.get(url, headers={"x-apikey": VT_KEY}, timeout=TIMEOUT)
    r.raise_for_status()
    stats = r.json()["data"]["attributes"]["last_analysis_stats"]

    gui_map = {
        "ip": f"https://www.virustotal.com/gui/ip-address/{ioc}",
        "domain": f"https://www.virustotal.com/gui/domain/{ioc}",
        "hash": f"https://www.virustotal.com/gui/file/{ioc}",
    }
    return {
        "source": "VirusTotal",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "total_engines": sum(stats.values()),
        "url": gui_map[ioc_type],
    }


def _abuseipdb(ip: str) -> dict:
    """Query AbuseIPDB for an IP's abuse confidence score."""
    r = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": ABUSE_KEY, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": "90"},
        timeout=TIMEOUT,
    )
    r.raise_for_status()
    d = r.json()["data"]
    return {
        "source": "AbuseIPDB",
        "abuse_confidence": d.get("abuseConfidenceScore", 0),
        "total_reports": d.get("totalReports", 0),
        "country": d.get("countryCode"),
        "isp": d.get("isp"),
        "url": f"https://www.abuseipdb.com/check/{ip}",
    }


def _otx(ioc: str, ioc_type: str) -> dict:
    """Query AlienVault OTX for the number of threat pulses referencing an IOC."""
    section_map = {
        "ip": f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc}/general",
        "domain": f"https://otx.alienvault.com/api/v1/indicators/domain/{ioc}/general",
        "hash": f"https://otx.alienvault.com/api/v1/indicators/file/{ioc}/general",
    }
    r = requests.get(
        section_map[ioc_type],
        headers={"X-OTX-API-KEY": OTX_KEY},
        timeout=TIMEOUT,
    )
    r.raise_for_status()
    pulses = r.json().get("pulse_info", {}).get("count", 0)
    return {
        "source": "AlienVault OTX",
        "pulse_count": pulses,
        "url": f"https://otx.alienvault.com/indicator/{'ip' if ioc_type=='ip' else ioc_type}/{ioc}",
    }


# ---------------------------------------------------------------------------
# Correlation + verdict
# ---------------------------------------------------------------------------
def _verdict(findings: list) -> str:
    """Derive a simple verdict from the correlated findings."""
    vt = next((f for f in findings if f["source"] == "VirusTotal"), None)
    abuse = next((f for f in findings if f["source"] == "AbuseIPDB"), None)
    otx = next((f for f in findings if f["source"] == "AlienVault OTX"), None)

    malicious_signals = 0
    if vt and vt.get("malicious", 0) >= 3:
        malicious_signals += 1
    if abuse and abuse.get("abuse_confidence", 0) >= 50:
        malicious_signals += 1
    if otx and otx.get("pulse_count", 0) >= 1:
        malicious_signals += 1

    if malicious_signals >= 2:
        return "Malicious (high confidence)"
    if malicious_signals == 1:
        return "Suspicious (low-to-medium confidence)"
    return "Likely benign"


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def lookup_ioc(value: str) -> dict:
    """
    Main entry point. Detects the IOC type, queries the relevant sources,
    correlates them, and returns a structured result.

    Returns:
        {
          "ioc": "45.83.122.10",
          "type": "ip",
          "verdict": "Malicious (high confidence)",
          "findings": [ {source, ...}, ... ],
          "sources": [url, url, ...],
          "errors": [ "AbuseIPDB: <reason>", ... ]   # only if any failed
        }
    """
    ioc_type = detect_ioc_type(value)
    if ioc_type == "unknown":
        return {
            "ioc": value,
            "type": "unknown",
            "verdict": "Unable to classify indicator",
            "findings": [],
            "sources": [],
            "errors": ["Input is not a recognizable IP, domain, or hash."],
        }

    findings, errors = [], []

    # VirusTotal supports all three types
    try:
        findings.append(_virustotal(value, ioc_type))
    except Exception as e:
        errors.append(f"VirusTotal: {str(e)[:80]}")

    # AbuseIPDB is IP-only
    if ioc_type == "ip":
        try:
            findings.append(_abuseipdb(value))
        except Exception as e:
            errors.append(f"AbuseIPDB: {str(e)[:80]}")

    # OTX supports all three types
    try:
        findings.append(_otx(value, ioc_type))
    except Exception as e:
        errors.append(f"AlienVault OTX: {str(e)[:80]}")

    return {
        "ioc": value,
        "type": ioc_type,
        "verdict": _verdict(findings),
        "findings": findings,
        "sources": [f["url"] for f in findings],
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# Quick manual test:  python tools/ioc.py 8.8.8.8
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    import json

    target = sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"
    print(f"\nLooking up: {target}\n" + "-" * 40)
    result = lookup_ioc(target)
    print(json.dumps(result, indent=2))
