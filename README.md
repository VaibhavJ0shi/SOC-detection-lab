# SOC Detection Lab

A home lab for detecting, investigating, and documenting real-world attacks using Splunk, Sysmon, and MITRE ATT&CK.

> 🚧 **Status:** In progress — building phase by phase.

## 🎯 Project Goals

- Build a working SOC lab with Splunk as the SIEM
- Write custom SPL detection rules mapped to MITRE ATT&CK
- Simulate attacks and document investigations like a real analyst
- Automate log parsing and IOC extraction with Python

## 🏗️ Architecture

[Kali Attacker] → [Windows Victim] → [Splunk SIEM] → [Alerts & Reports]

*(diagram coming soon)*

## 📂 Repo Structure

| Folder | Purpose |
|---|---|
| `rules/` | Custom SPL + Sigma detection rules |
| `investigations/` | Written incident reports |
| `scripts/` | Python automation (IOC extraction, log parsing) |
| `lab-setup/` | Setup docs + screenshots |

## 🛠️ Tech Stack

- **SIEM:** Splunk Enterprise (Free license)
- **Endpoint telemetry:** Sysmon (Windows), auditd (Linux)
- **Attacker:** Kali Linux
- **Frameworks:** MITRE ATT&CK
- **Languages:** Python, SPL, YAML

## 📊 Progress

- [ ] Phase 0 — Repo setup
- [ ] Phase 1 — Splunk installed
- [ ] Phase 2 — Log collection working
- [ ] Phase 3 — First detection rule
- [ ] Phase 4 — First attack + alert
- [ ] Phase 5 — First investigation report
- [ ] Phase 6 — 5 investigations total
- [ ] Phase 7 — Python automation
- [ ] Phase 8 — Publish & polish

## 📬 Contact

- GitHub: [@VaibhavJ0shi](https://github.com/VaibhavJ0shi)
EOF
