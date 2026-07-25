"""
tools/exposure.py — Exposure reasoning: map a software + version to known CVEs.

Handles queries like: "We run Confluence 7.13 — are we exposed?"

Flow:
  1. Build a keyword search from product (+ sanitized version) for the NVD CVE API.
  2. Query NVD (National Vulnerability Database) — live, authoritative, free.
  3. Extract each CVE's ID, CVSS severity/score, and description.
  4. Sort by severity and derive an overall exposure verdict.
  5. Return a structured, source-attributed result (no fabricated intel).

Design notes:
  • NVD works keyless (rate-limited); an API key raises the limit.
  • Graceful degradation: on any failure we return a clean error result,
    never a crash — satisfies "graceful handling of API errors".
  • Every CVE carries its canonical NVD URL for attribution.
  • Version strings are sanitized (digits + dots only) so stray punctuation
    from natural-language queries (e.g. "7.13 -") never corrupts the search.
"""

import os
import re
import requests
from dotenv import load_dotenv

load_dotenv()

NVD_KEY = os.getenv("NVD_API_KEY")
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TIMEOUT = 25

# How many CVEs to pull back / report (keeps output focused + controls cost).
RESULTS_LIMIT = 8


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------
_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0, "UNKNOWN": 0}


def _extract_cvss(metrics: dict) -> tuple:
    """
    Pull the best-available CVSS (v3.1 → v3.0 → v2) severity + base score
    from an NVD 'metrics' block. Returns (severity_str, base_score_or_None).
    """
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if metrics.get(key):
            data = metrics[key][0]["cvssData"]
            return data.get("baseSeverity", "UNKNOWN"), data.get("baseScore")
    if metrics.get("cvssMetricV2"):
        m = metrics["cvssMetricV2"][0]
        return m.get("baseSeverity", "UNKNOWN"), m.get("cvssData", {}).get("baseScore")
    return "UNKNOWN", None


def _verdict(cves: list) -> str:
    """Derive an overall exposure verdict from the highest-severity CVE found."""
    if not cves:
        return "No known CVEs matched — no exposure indicated from this source."
    top = max((_SEVERITY_RANK.get(c["severity"], 0) for c in cves), default=0)
    if top >= 4:
        return "EXPOSED — critical-severity vulnerabilities found. Patch urgently."
    if top == 3:
        return "EXPOSED — high-severity vulnerabilities found. Prioritize patching."
    if top == 2:
        return "Potentially exposed — medium-severity vulnerabilities found."
    if top == 1:
        return "Low exposure — only low-severity vulnerabilities found."
    return "CVEs found, but severity could not be determined."


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def check_exposure(software: str, version: str = None) -> dict:
    """
    Query NVD for CVEs affecting a product (+ optional version).

    Returns:
        {
          "software": "Confluence",
          "version": "7.13",
          "verdict": "EXPOSED — critical ...",
          "cve_count": 3,
          "cves": [ {id, severity, score, description, url}, ... ],
          "sources": ["https://nvd.nist.gov/..."],
          "errors": []
        }
    """
    if not software or not software.strip():
        return {
            "software": software,
            "version": version,
            "verdict": "No software product was provided to assess.",
            "cve_count": 0,
            "cves": [],
            "sources": [],
            "errors": ["Missing software name."],
        }

    # Sanitize inputs: strip stray punctuation that can leak in from
    # natural-language queries (e.g. "7.13 -" → "7.13").
    clean_software = software.strip()
    keyword = clean_software
    clean_version = None
    if version:
        clean_version = re.sub(r"[^0-9.]", "", version).strip(".")
        if clean_version:
            keyword = f"{clean_software} {clean_version}"

    headers = {"apiKey": NVD_KEY} if NVD_KEY else {}
    params = {"keywordSearch": keyword, "resultsPerPage": 20}

    try:
        r = requests.get(NVD_URL, headers=headers, params=params, timeout=TIMEOUT)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        return {
            "software": clean_software,
            "version": clean_version,
            "verdict": "Could not complete exposure check (NVD request failed).",
            "cve_count": 0,
            "cves": [],
            "sources": ["https://nvd.nist.gov/"],
            "errors": [f"NVD: {str(e)[:100]}"],
        }

    vulns = data.get("vulnerabilities", [])
    cves = []
    for item in vulns:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")

        # English description
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        severity, score = _extract_cvss(cve.get("metrics", {}))

        cves.append({
            "id": cve_id,
            "severity": severity,
            "score": score,
            "description": (desc[:220] + "…") if len(desc) > 220 else desc,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })

    # Sort by severity (highest first), then trim to the reporting limit.
    cves.sort(key=lambda c: _SEVERITY_RANK.get(c["severity"], 0), reverse=True)
    cves = cves[:RESULTS_LIMIT]

    search_query = keyword.replace(" ", "+")
    return {
        "software": clean_software,
        "version": clean_version,
        "verdict": _verdict(cves),
        "cve_count": len(cves),
        "cves": cves,
        "sources": [f"https://nvd.nist.gov/vuln/search/results?query={search_query}"],
        "errors": [],
    }


# ---------------------------------------------------------------------------
# Quick manual test:  python tools/exposure.py "Confluence" "7.13"
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    import json

    sw = sys.argv[1] if len(sys.argv) > 1 else "Confluence"
    ver = sys.argv[2] if len(sys.argv) > 2 else "7.13"
    print(f"\nChecking exposure: {sw} {ver}\n" + "-" * 40)
    print(json.dumps(check_exposure(sw, ver), indent=2))
