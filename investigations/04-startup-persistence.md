# Investigation #04 — Startup Folder Persistence

**Report ID:** INV-004  
**Date:** 2026-10-06  
**Analyst:** Vaibhav Joshi  
**Severity:** Medium  
**Status:** Closed — True Positive  

---

## 🚨 Alert

**Detection Rule:** T1547_startup_persistence.spl

**Trigger:**
- Sysmon EventCode 11 — FileCreate (file dropped in Startup folder)
- Sysmon EventCode 1 — ProcessCreation (Startup binary executed)

**Host:** Windows10-Victim (DESKTOP-5TRJPSS)

**Time:** 2026-09-29 06:34:44 PM (18:34:44 IST / 13:04:44 UTC)

---

## 🔍 Triage

**What happened:**
A binary named `Updater.exe` was created in the user's Startup folder 
(`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`). The 
Startup folder is a well-known persistence location — any file placed 
here executes automatically on user logon.

**Initial checks performed (Splunk-only):**
- Confirmed file creation: `index=main Updater.exe`
- Total events: 2 (file creation + process execution)
- File path: `C:\Users\varun\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Updater.exe`
- **OriginalFileName:** `CALC.EXE` (Windows Calculator)
- **Description:** Windows Calculator
- **Product:** Microsoft® Windows® Operating System
- **FileVersion:** 10.0.19041.1
- **User:** `DESKTOP-5TRJPSS\varun`
- **Parent process:** `C:\Windows\explorer.exe`
- **Process ID:** 8588

**File hashes:**
- **MD5:** `5DA0C98136D98DFEC4716ED79C7145F`
- **SHA256:** `58189CB04E6D0DC7D0EE6B6A6F75652FC9FA4CFC0E0BA7D6D8C3FBED805381F`

**Why this is suspicious:**
Multiple red flags indicate malicious activity:

1. **File name mismatch:** The file is named `Updater.exe` but its 
   `OriginalFileName` is `CALC.EXE` — classic masquerading.
2. **Persistence location:** The Startup folder is a well-known 
   auto-execution path used by attackers for persistence.
3. **Legitimate software doesn't belong here:** Windows Calculator 
   (`calc.exe`) has no reason to be in the Startup folder.
4. **Naming convention:** `Updater.exe` is a common deceptive name 
   used to blend in with legitimate software.

This behaviour matches **MITRE ATT&CK T1547.001 — Boot or Logon 
Autostart Execution: Registry Run Keys / Startup Folder**.

---

## ⏱️ Timeline

| Time | Event | Source |
|---|---|---|
| 18:34:44.214 | FileCreate: `Updater.exe` dropped in Startup folder | Sysmon EventCode 11 |
| 18:34:44.214 | Parent process: `explorer.exe` (PID 3184) | Sysmon EventCode 11 |
| 18:34:52.815 | ProcessCreation: `Updater.exe` executed (PID 8588) | Sysmon EventCode 1 |

---

## 🎯 Indicators of Compromise (IOCs)

| Type | Value | Source |
|---|---|---|
| File Name | `Updater.exe` | `TargetFilename` field |
| Original File Name | `CALC.EXE` (masquerading) | `OriginalFileName` field |
| File Path | `C:\Users\varun\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Updater.exe` | `TargetFilename` field |
| MD5 Hash | `5DA0C98136D98DFEC4716ED79C7145F` | `Hashes` field |
| SHA256 Hash | `58189CB04E6D0DC7D0EE6B6A6F75652FC9FA4CFC0E0BA7D6D8C3FBED805381F` | `Hashes` field |
| Parent Process | `C:\Windows\explorer.exe` | `ParentImage` field |
| User | `DESKTOP-5TRJPSS\varun` | `User` field |
| Process ID | 8588 | `ProcessId` field |
| Windows Event | Sysmon 11 (FileCreate) | `EventID` field |
| Windows Event | Sysmon 1 (ProcessCreate) | `EventID` field |

---

## ✅ Verdict

**True Positive** — Simulated attack in isolated lab environment.

In a real SOC environment, this would indicate:
- Persistence established via Startup folder
- A masqueraded binary (`Updater.exe` is actually `calc.exe`)
- The binary will execute on every user logon — permanent backdoor

**Recommended Response Actions:**
1. Quarantine the host immediately
2. Delete `Updater.exe` from the Startup folder
3. Check for other files dropped in Startup / Run keys
4. Review the parent process (`explorer.exe`) — was the copy initiated by a script?
5. Verify file hash against known malware databases
6. Check `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` on all 
   affected users
7. Investigate initial access vector (how did the file get here?)
8. Reset credentials for the affected user (`varun`)

---

## 🛡️ MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Persistence | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | T1547.001 |
| Defense Evasion | Masquerading: Match Legitimate Name or Location | T1036.005 |

---

## 💡 Lessons Learned

**What went well:**
- Detection rule correctly identified file creation in Startup folder
- Sysmon EventCode 11 captured full file path, hash, and parent process
- `OriginalFileName` field revealed the masquerading technique — 
  critical for detection

**What could be improved:**
- Add automatic hash lookup (VirusTotal) in the alert
- Correlate file creation with user activity (who copied the file?)
- Flag any file creation in Startup folder regardless of name
- Add specific rule for `OriginalFileName != TargetFilename` (masquerading)
- Track PowerShell / cmd.exe as parent process for file copies

**Analyst notes:**
The Startup folder is a favourite persistence location for attackers 
because:
1. No special permissions required (user-level persistence)
2. Auto-executes on every logon
3. Often overlooked by users

**Masquerading technique observed:**
The file was renamed from `calc.exe` to `Updater.exe`. The 
`OriginalFileName` field in Sysmon Event 11 revealed the true origin. 
This is a classic technique — always check `OriginalFileName` against 
`TargetFilename`.

**Splunk field extraction limitation:**
Sysmon events use `EventID` in raw XML — not `EventCode` as a field. 
Analysts should use raw text search (e.g., `index=main Updater.exe`) 
when field-based searches fail.

**Lab observation:**
The file was placed in the Startup folder via PowerShell `Copy-Item` 
for lab simplicity. In a real-world scenario, this would typically 
be delivered via malware dropper, phishing, or exploit. The detection 
logic remains the same.

---

## 📸 Evidence

- Detection events: `../lab-setup/screenshots/14 Registry_events.png`
- Rule output: `../lab-setup/screenshots/15 Registry_rules.png`
