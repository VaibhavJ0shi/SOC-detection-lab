# 🛡️ SOC Detection Lab

An end-to-end Security Operations Center (SOC) home lab for simulating real-world attacks, writing custom Splunk detection rules, configuring automated alerts, and documenting full incident investigations mapped to MITRE ATT&CK.

> 🏆 **Status:** Complete — 5 Detection Rules | 5 Alerts | 5 Investigation Reports | 3 Python Automation Scripts

---

## 🎯 Project Overview

This lab was built to practice and demonstrate **blue team / SOC analyst** skills. It covers the full detection lifecycle:

1. **Telemetry** — Collect endpoint logs using Sysmon & Windows Event Logs.
2. **Detection** — Write custom SPL rules in Splunk based on MITRE ATT&CK.
3. **Alerting** — Configure automated scheduled searches.
4. **Investigation** — Perform triage, build timelines, extract IOCs, and write incident reports.
5. **Automation** — Use Python to parse logs, extract IOCs, and enrich threat intel.

---

## 🏗️ Lab Architecture

1. **Attacker:** Kali Linux (Simulates Attack)
2. **Victim:** Windows 10 VM (Generates Sysmon & Event Logs)
3. **Log Shipper:** Splunk Universal Forwarder (Forwards Logs)
4. **SIEM:** Splunk Enterprise (Detects & Alerts)
5. **Output:** Alerts & Investigation Reports

---

## 🎯 Detection Rules & Investigations

I simulated 5 distinct attack scenarios, wrote an SPL rule for each, and documented the investigation.

| # | Investigation | MITRE ATT&CK | Severity | Report |
|---|---|---|---|---|
| 01 | Suspicious Account Creation | T1136.001, T1098 | Medium | [View Report](investigations/01-account-creation.md) |
| 02 | Brute Force Login Attempts | T1110.001 | Medium | [View Report](investigations/02-bruteforce.md) |
| 03 | Encoded PowerShell Command | T1059.001, T1027, T1105 | High | [View Report](investigations/03-powershell-encoded.md) |
| 04 | Startup Folder Persistence | T1547.001, T1036.005 | Medium | [View Report](investigations/04-startup-persistence.md) |
| 05 | Command & Control (C2) Connection | T1071, T1571 | High | [View Report](investigations/05-c2-connection.md) |

👉 **[Click here to view all Detection Rules (SPL)](rules/)**

---

## 🐍 Python Automation Tools

To make investigations faster, I built 3 Python scripts:

1. **Log Parser** (`scripts/parsers/`) — Parses Splunk-exported CSVs and summarizes events.
2. **IOC Extractor** (`scripts/extractors/`) — Uses Regex to automatically pull IPs, hashes, domains, and usernames from raw logs.
3. **IOC Enricher** (`scripts/enrichers/`) — Classifies IOCs and enriches them with threat intel (mock API integration).

👉 **[Click here to view the Scripts Documentation](scripts/)**

---

## 📂 Repository Structure

| Folder | Purpose |
|---|---|
| `rules/` | Custom SPL detection rules mapped to MITRE ATT&CK |
| `alerts/` | Documentation for automated Splunk alerts |
| `investigations/` | Full incident investigation reports |
| `scripts/` | Python automation tools (Parsers, Extractors, Enrichers) |
| `lab-setup/` | Architecture docs, sysmon configs, and 37+ screenshots |

---

## 🛠️ Tech Stack

- **SIEM:** Splunk Enterprise (Free license)
- **Endpoint Telemetry:** Sysmon, Windows Event Logs
- **Attacker:** Kali Linux
- **Frameworks:** MITRE ATT&CK
- **Languages:** Python (pandas, rich), SPL, Bash
- **Tools:** Hydra, Netcat, VirtualBox

---

## 📸 Lab Setup & Screenshots

All screenshots documenting the setup, detection rules firing, and dashboard views are available in the **[`lab-setup/screenshots/`](lab-setup/screenshots/)** directory.

---

## 📬 Contact

- **GitHub:** [@VaibhavJ0shi](https://github.com/VaibhavJ0shi)
