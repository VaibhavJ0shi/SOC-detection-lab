# Investigation #05 — Command & Control Connection

**Report ID:** INV-005  
**Date:** 2026-10-06  
**Analyst:** Vaibhav Joshi  
**Severity:** High  
**Status:** Closed — True Positive  

---

## 🚨 Alert

**Detection Rule:** T1071_c2_connection.spl

**Trigger:** Sysmon EventID 3 — Network Connection (outbound to non-standard port)

**Host:** Windows10-Victim (DESKTOP-5TRJPSS)

**Time:** 2026-09-26 08:06:37 PM (20:06:37 IST / 14:36:35 UTC)

---

## 🔍 Triage

**What happened:**
An outbound TCP connection was initiated by `powershell.exe` on the 
Windows victim machine to IP `192.168.56.1` on port `4444`. Port 4444 
is a non-standard port commonly associated with Metasploit/C2 
frameworks. The connection was initiated by PowerShell — a classic 
sign of a reverse shell or C2 beacon.

**Initial checks performed (Splunk-only):**
- Confirmed network connection: `index=main 4444 DestinationPort`
- Total events: 1
- Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- User: `DESKTOP-5TRJPSS\varun`
- Protocol: TCP
- Initiated: `true` (outbound connection)
- Source: `192.168.56.101:50335` (Windows VM)
- Destination: `192.168.56.1:4444` (Kali attacker)
- Process ID: 9720

**Why this is suspicious:**
Multiple red flags indicate malicious activity:

1. **PowerShell making network connections:** PowerShell is commonly 
   abused for C2 — legitimate admin scripts rarely open raw TCP 
   connections to external IPs.
2. **Non-standard port (4444):** Port 4444 is a well-known default 
   port for Metasploit handlers and is frequently used by attackers.
3. **Outbound to internal IP:** `192.168.56.1` is the Kali attacker 
   machine in this lab — in a real environment, this would be an 
   external C2 server.
4. **`Initiated=true`:** The victim initiated the connection — 
   indicating a reverse shell or beacon pattern.

This behaviour matches **MITRE ATT&CK T1071 — Application Layer 
Protocol** and **T1571 — Non-Standard Port**.

---

## ⏱️ Timeline

| Time | Event | Source |
|---|---|---|
| 20:06:35.873 | Outbound TCP connection: `powershell.exe` → 192.168.56.1:4444 | Sysmon EventID 3 |
| 20:06:37.942 | Event ingested by Splunk | Splunk `_time` |

---

## 🎯 Indicators of Compromise (IOCs)

| Type | Value | Source |
|---|---|---|
| Process | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | `Image` field |
| User | `DESKTOP-5TRJPSS\varun` | `User` field |
| Protocol | TCP | `Protocol` field |
| Source IP | `192.168.56.101` (Windows victim) | `SourceIp` field |
| Source Port | `50335` | `SourcePort` field |
| Destination IP | `192.168.56.1` (Kali attacker) | `DestinationIp` field |
| Destination Port | `4444` (non-standard) | `DestinationPort` field |
| Process ID | 9720 | `ProcessId` field |
| Windows Event | Sysmon 3 (Network Connection) | `EventID` field |

---

## ✅ Verdict

**True Positive** — Simulated attack in isolated lab environment.

In a real SOC environment, this would indicate:
- A reverse shell or C2 beacon established from the victim
- Active attacker control over the compromised host
- Data exfiltration or command execution likely in progress

**Recommended Response Actions:**
1. Isolate the host from the network immediately
2. Terminate the PowerShell process (PID 9720)
3. Block outbound traffic to `192.168.56.1:4444` at the firewall
4. Check for additional outbound connections from PowerShell processes
5. Look for child processes spawned by PID 9720
6. Review the user (`varun`) account for compromise
7. Check for persistence mechanisms (Run keys, scheduled tasks, Startup folder)
8. Reset credentials for the affected user
9. Scan host for malware / additional IOCs

---

## 🛡️ MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Command and Control | Application Layer Protocol | T1071 |
| Command and Control | Non-Standard Port | T1571 |

---

## 💡 Lessons Learned

**What went well:**
- Detection rule correctly identified outbound connection to port 4444
- Sysmon EventID 3 captured full network details (source, destination, process, user)
- `Initiated=true` clearly indicated outbound connection — reverse shell pattern
- Correlating process (`powershell.exe`) with network activity provided high-fidelity detection

**What could be improved:**
- Add automatic threat intel lookup for destination IP / port
- Flag outbound connections on non-standard ports from PowerShell
- Add baseline of normal PowerShell network activity
- Correlate with process creation events (Sysmon EventID 1) to see the command that spawned the connection
- Monitor for connections to known-bad ports (4444, 1337, 31337, etc.)

**Analyst notes:**
Port 4444 is the default port for Metasploit's `multi/handler` — 
one of the most widely-used penetration testing and attack tools. 
While finding port 4444 is not proof of an attack on its own, when 
combined with:
1. PowerShell as the initiating process
2. Outbound connection (`Initiated=true`)
3. Unusual destination IP

...it becomes a high-confidence indicator of C2 activity.

**Detection methodology:**
- Raw text search (`index=main 4444`) was required because Sysmon 
  network events do not always expose fields like `DestinationPort` 
  for field-based searches
- Process + network correlation is critical for C2 detection

**Lab observation:**
The C2 connection was simulated using Netcat as the listener on Kali 
and PowerShell's `TcpClient` on the victim. In a real-world scenario, 
this would typically be the result of malware executing a reverse 
shell. The detection logic remains the same.

---

## 📸 Evidence

- Detection events: `../lab-setup/screenshots/16 c2_events.png`
- Rule output: `../lab-setup/screenshots/17 c2_rule.png`
