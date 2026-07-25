"""
test_keys.py — One-shot health check for every credential in .env

Run this BEFORE building any tools. It pings each service with a tiny,
quota-friendly request and prints a clear PASS/FAIL per key.

    python test_keys.py

No secrets are printed. A FAIL tells you exactly which key/endpoint to fix.
"""

import os
import sys
import requests
from dotenv import load_dotenv

load_dotenv()

# ANSI colours (fall back gracefully if the terminal doesn't support them)
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

results = []


def record(name, ok, detail=""):
    tag = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
    results.append(ok)
    print(f"[{tag}] {name:<18} {detail}")


# ---------------------------------------------------------------------------
# 1. Azure OpenAI
# ---------------------------------------------------------------------------
def check_azure_openai():
    try:
        from openai import AzureOpenAI

        key = os.getenv("AZURE_OPENAI_API_KEY")
        endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
        deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT")

        if not all([key, endpoint, deployment]):
            return record("Azure OpenAI", False, "missing env var(s)")

        client = AzureOpenAI(
            api_key=key,
            azure_endpoint=endpoint,
            api_version="2024-06-01",
        )
        resp = client.chat.completions.create(
            model=deployment,
            messages=[{"role": "user", "content": "Reply with exactly: OK"}],
            max_tokens=5,
        )
        text = resp.choices[0].message.content.strip()
        record("Azure OpenAI", "OK" in text, f"model replied: '{text}'")
    except Exception as e:
        record("Azure OpenAI", False, str(e)[:80])


# ---------------------------------------------------------------------------
# 2. VirusTotal  (free: 500/day, 4/min)
# ---------------------------------------------------------------------------
def check_virustotal():
    try:
        key = os.getenv("VT_API_KEY")
        if not key:
            return record("VirusTotal", False, "missing VT_API_KEY")
        # Look up a well-known safe IP (Google DNS)
        r = requests.get(
            "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
            headers={"x-apikey": key},
            timeout=15,
        )
        if r.status_code == 200:
            record("VirusTotal", True, "IP lookup succeeded")
        elif r.status_code == 401:
            record("VirusTotal", False, "401 unauthorized (bad key)")
        elif r.status_code == 429:
            record("VirusTotal", True, "429 rate-limited (key is VALID)")
        else:
            record("VirusTotal", False, f"HTTP {r.status_code}")
    except Exception as e:
        record("VirusTotal", False, str(e)[:80])


# ---------------------------------------------------------------------------
# 3. AbuseIPDB  (free: 1000/day)
# ---------------------------------------------------------------------------
def check_abuseipdb():
    try:
        key = os.getenv("ABUSEIPDB_API_KEY")
        if not key:
            return record("AbuseIPDB", False, "missing ABUSEIPDB_API_KEY")
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": "8.8.8.8", "maxAgeInDays": "90"},
            timeout=15,
        )
        if r.status_code == 200:
            score = r.json()["data"]["abuseConfidenceScore"]
            record("AbuseIPDB", True, f"confidence score: {score}")
        elif r.status_code == 401:
            record("AbuseIPDB", False, "401 unauthorized (bad key)")
        elif r.status_code == 429:
            record("AbuseIPDB", True, "429 rate-limited (key is VALID)")
        else:
            record("AbuseIPDB", False, f"HTTP {r.status_code}")
    except Exception as e:
        record("AbuseIPDB", False, str(e)[:80])


# ---------------------------------------------------------------------------
# 4. AlienVault OTX
# ---------------------------------------------------------------------------
def check_otx():
    try:
        key = os.getenv("OTX_API_KEY")
        if not key:
            return record("AlienVault OTX", False, "missing OTX_API_KEY")
        r = requests.get(
            "https://otx.alienvault.com/api/v1/user/me",
            headers={"X-OTX-API-KEY": key},
            timeout=15,
        )
        if r.status_code == 200:
            user = r.json().get("username", "unknown")
            record("AlienVault OTX", True, f"authenticated as: {user}")
        elif r.status_code in (401, 403):
            record("AlienVault OTX", False, f"{r.status_code} (bad key)")
        else:
            record("AlienVault OTX", False, f"HTTP {r.status_code}")
    except Exception as e:
        record("AlienVault OTX", False, str(e)[:80])


# ---------------------------------------------------------------------------
# 5. NVD (NIST)  — works keyless, key raises the rate limit
# ---------------------------------------------------------------------------
def check_nvd():
    try:
        key = os.getenv("NVD_API_KEY")
        headers = {"apiKey": key} if key else {}
        r = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            headers=headers,
            params={"cveId": "CVE-2022-26134"},  # the Confluence RCE
            timeout=20,
        )
        if r.status_code == 200:
            n = r.json().get("totalResults", 0)
            detail = "CVE query succeeded" + ("" if key else " (NO key — keyless mode)")
            record("NVD", n > 0, detail)
        elif r.status_code == 403:
            record("NVD", False, "403 (invalid key)")
        else:
            record("NVD", False, f"HTTP {r.status_code}")
    except Exception as e:
        record("NVD", False, str(e)[:80])


# ---------------------------------------------------------------------------
def main():
    print("\n" + "=" * 55)
    print(" Threat-Intel Agent — Credential Health Check")
    print("=" * 55)

    check_azure_openai()
    check_virustotal()
    check_abuseipdb()
    check_otx()
    check_nvd()

    print("=" * 55)
    passed = sum(results)
    total = len(results)
    if passed == total:
        print(f"{GREEN} ALL {total}/{total} CHECKS PASSED — you're ready to build! {RESET}")
    else:
        print(f"{YELLOW} {passed}/{total} passed. Fix the FAIL(s) above, then re-run. {RESET}")
    print("=" * 55 + "\n")

    # Non-zero exit code if anything failed (handy for CI later)
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
