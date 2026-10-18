# Python Automation Scripts

SOC tools to automate log parsing, IOC extraction, and threat intel enrichment.

## 🎯 Purpose

These scripts automate common SOC analyst tasks:
- Parsing large log files
- Extracting Indicators of Compromise (IOCs)
- Enriching IOCs with threat intelligence APIs

## 📜 Scripts

### 1. Log Parser (parsers/log_parser.py)

Parses Splunk-exported CSV logs and displays a summary of events grouped by EventCode.

**Usage:**
`python3 parsers/log_parser.py <path-to-csv>`

**Features:**
- Loads CSV logs into pandas DataFrame
- Displays total event count
- Groups events by EventCode
- Shows a formatted table of parsed events

---

### 2. IOC Extractor (extractors/ioc_extractor.py)

Extracts Indicators of Compromise from any log or text file using regex patterns.

**Usage:**
`python3 extractors/ioc_extractor.py <path-to-file>`

**Supported IOC Types:**
| Type | Example |
|---|---|
| IPv4 Address | 192.168.56.1 |
| MD5 Hash | 5DA0C98136D98DFEC4716ED79C7145F |
| SHA1 Hash | da39a3ee5e6b4b0d3255bfef95601890afd80709 |
| SHA256 Hash | 58189CB04E6D0DC7D0EE6B6A6F75652FC9FA4CFC0E0BA7D6D8C3FBED805381F |
| Domain | malicious-c2.example.com |
| URL | http://malicious-c2.example.com/beacon |
| Email | attacker@evil-domain.com |
| Username | hacker (from Account_Name= field) |

**Features:**
- Regex-based extraction (no external APIs needed)
- Handles multiple IOC types in one pass
- Formatted table output with counts
- Works on any text-based log file

---

### 3. IOC Enricher (enrichers/ioc_enricher.py) — Coming Soon

Will enrich extracted IOCs using threat intel APIs:
- VirusTotal (file hashes)
- AbuseIPDB (IP addresses)
- URLVoid (domains)

---

## ⚙️ Setup

### 1. Create virtual environment

`cd scripts`
`python3 -m venv venv`
`source venv/bin/activate`

### 2. Install dependencies

`pip install pandas rich requests`

### 3. Verify installation

`pip list | grep -E "pandas|rich|requests"`

---

## 📂 Folder Structure

scripts/
├── parsers/          # Log parsing scripts
│   └── log_parser.py
├── extractors/       # IOC extraction scripts
│   └── ioc_extractor.py
├── enrichers/        # API enrichment scripts (coming soon)
├── samples/          # Sample data for testing
│   ├── sample_events.csv
│   └── sample_iocs.txt
├── venv/             # Virtual environment (gitignored)
└── README.md

---

## 🧪 Testing

### Log Parser

`python3 parsers/log_parser.py samples/sample_events.csv`

**Expected output:** Table with 5 events grouped by EventCode.

### IOC Extractor

`python3 extractors/ioc_extractor.py samples/sample_iocs.txt`

**Expected output:** Table with 10 unique IOCs (IPs, hashes, domains, emails, usernames).

---

## 🔗 Related

- [Detection Rules](../rules/) — SPL detection rules
- [Investigation Reports](../investigations/) — Incident writeups
- [Lab Setup](../lab-setup/) — Screenshots and configuration

---

## 📸 Screenshots

- Log parser output: ../lab-setup/screenshots/20-log-parser-output.png
- IOC extractor output: ../lab-setup/screenshots/21-ioc-extractor-output.png
