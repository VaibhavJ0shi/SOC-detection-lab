"""
IOC Enricher — Enriches IPs, hashes, and domains with threat intelligence.
Currently uses mock data. Real API integration (VirusTotal/AbuseIPDB) 
can be added by uncommenting the API functions below.

Author: Vaibhav Joshi
"""

import sys
import re
import json

# --- Mock Threat Intel Database ---
# (In real use, this would call VirusTotal / AbuseIPDB APIs)
MOCK_THREAT_INTEL = {
    "192.168.56.1": {"source": "AbuseIPDB", "score": 100, "verdict": "malicious", "reason": "Known attacker IP (lab)"},
    "192.168.56.101": {"source": "AbuseIPDB", "score": 0, "verdict": "internal", "reason": "Internal lab host"},
    "8.8.8.8": {"source": "AbuseIPDB", "score": 0, "verdict": "clean", "reason": "Google DNS"},
    "5DA0C98136D98DFEC4716ED79C7145F": {"source": "VirusTotal", "score": 0, "verdict": "clean", "reason": "Windows Calculator"},
    "58189CB04E6D0DC7D0EE6B6A6F75652FC9FA4CFC0E0BA7D6D8C3FBED805381F": {"source": "VirusTotal", "score": 0, "verdict": "clean", "reason": "Windows Calculator"},
    "malicious-c2.example.com": {"source": "URLVoid", "score": 85, "verdict": "malicious", "reason": "Known C2 domain"},
}


# --- API Integration Templates (for future use) ---

def check_virustotal_hash(api_key, file_hash):
    """
    UNCOMMENT TO USE REAL API.
    import requests
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    return response.json()
    """
    pass


def check_abuseipdb_ip(api_key, ip):
    """
    UNCOMMENT TO USE REAL API.
    import requests
    url = f"https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    response = requests.get(url, headers=headers, params=params)
    return response.json()
    """
    pass


# --- Enrichment Logic ---

def classify_ioc(value):
    """Classify an IOC by type."""
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value):
        return "IP"
    elif re.match(r"^[a-fA-F0-9]{32}$", value):
        return "MD5"
    elif re.match(r"^[a-fA-F0-9]{40}$", value):
        return "SHA1"
    elif re.match(r"^[a-fA-F0-9]{64}$", value):
        return "SHA256"
    elif re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", value):
        return "Domain"
    else:
        return "Unknown"


def enrich_ioc(value):
    """Enrich a single IOC with threat intel."""
    ioc_type = classify_ioc(value)
    intel = MOCK_THREAT_INTEL.get(value, {"source": "N/A", "score": 0, "verdict": "unknown", "reason": "Not in mock database"})
    return {"value": value, "type": ioc_type, **intel}


def main():
    if len(sys.argv) < 2:
        print("Usage: python ioc_enricher.py <path-to-file>")
        sys.exit(1)

    file_path = sys.argv[1]

    print("=" * 70)
    print("IOC Enricher — SOC Tool (Mock Mode)")
    print("=" * 70)

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            iocs = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
        sys.exit(1)

    print(f"\n[+] Loaded {len(iocs)} IOCs from {file_path}\n")

    results = []
    for ioc in iocs:
        result = enrich_ioc(ioc)
        results.append(result)

        # Color-coded verdict
        verdict_color = {
            "malicious": "\033[91m",   # Red
            "clean": "\033[92m",       # Green
            "internal": "\033[93m",    # Yellow
            "unknown": "\033[90m",     # Gray
        }.get(result["verdict"], "\033[0m")

        reset = "\033[0m"

        print(f"[{result['type']:<8}] {result['value']:<65} -> {verdict_color}{result['verdict'].upper()}{reset}")
        print(f"           Score: {result['score']:>3} | Source: {result['source']:<10} | {result['reason']}")
        print("-" * 70)

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    malicious = sum(1 for r in results if r["verdict"] == "malicious")
    clean = sum(1 for r in results if r["verdict"] == "clean")
    internal = sum(1 for r in results if r["verdict"] == "internal")
    unknown = sum(1 for r in results if r["verdict"] == "unknown")

    print(f"  Total IOCs: {len(results)}")
    print(f"  Malicious:  \033[91m{malicious}\033[0m")
    print(f"  Clean:      \033[92m{clean}\033[0m")
    print(f"  Internal:   \033[93m{internal}\033[0m")
    print(f"  Unknown:    \033[90m{unknown}\033[0m")

    # Save to JSON
    output_file = file_path + ".enriched.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n[+] Full results saved to: {output_file}")


if __name__ == "__main__":
    main()
