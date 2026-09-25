# SOC Detection Lab

A home lab for detecting, investigating, and documenting real-world attacks using Splunk, Sysmon, and MITRE ATT&CK.

> 🚧 **Status:** In progress — 4 of 8 phases complete.

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
| `rules/` | Custom SPL detection rules (4 written) |
| `alerts/` | Splunk scheduled alert documentation |
| `investigations/` | Written incident reports (coming soon) |
| `scripts/` | Python automation (IOC extraction, log parsing) |
| `lab-setup/` | Setup docs + screenshots |

## 🛠️ Tech Stack

- **SIEM:** Splunk Enterprise (Free license)
- **Endpoint telemetry:** Sysmon (Windows)
- **Attacker:** Kali Linux
- **Frameworks:** MITRE ATT&CK
- **Languages:** Python, SPL, YAML

## 🎯 Detection Rules

| Rule | MITRE ID | Technique |
|---|---|---|
| Suspicious Account Creation | T1136.001 | Create Account |
| Brute Force Login Attempts | T1110 | Brute Force |
| Suspicious PowerShell Encoded Command | T1059.001 | PowerShell |
| Startup Folder Persistence | T1547.001 | Registry Run Keys / Startup Folder |

## 📊 Progress

- [x] Phase 0 — Repo setup
- [x] Phase 1 — Splunk installed
- [x] Phase 2 — Log collection working
- [x] Phase 3 — Detection rules (4 rules)
- [x] Phase 4 — Splunk alerts & SOC dashboard
- [ ] Phase 5 — Investigation reports
- [ ] Phase 6 — 5 investigations total
- [ ] Phase 7 — Python automation
- [ ] Phase 8 — Publish & polish

## 📬 Contact

- GitHub: [@VaibhavJ0shi](https://github.com/VaibhavJ0shi)
