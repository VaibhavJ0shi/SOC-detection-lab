# Investigation #02 — Brute Force Login Attempts

**Report ID:** INV-002  
**Date:** 2026-09-28  
**Analyst:** Vaibhav Joshi  
**Severity:** Medium  
**Status:** Closed — True Positive  

---

## 🚨 Alert

**Detection Rule:** T1110_bruteforce.spl  
**Trigger:** EventCode 4625 — An account failed to log on (10 attempts)  
**Host:** Windows10-Victim (DESKTOP-5TRJPSS)  
**Time:** 2026-09-28 07:20:22 PM  

---

## 🔍 Triage

**What happened:**
10 failed network logon attempts (Logon Type 3) were detected against 
the `varun` account on the Windows victim machine (DESKTOP-5TRJPSS). 
The attempts used NTLM authentication and originated from IP 
192.168.56.1 within a short time window.

**Initial checks performed (Splunk-only):**
- Confirmed failed login events: `index=main EventCode=4625`
- Total failed attempts: 10
- Target account: `varun`
- Source IP: `192.168.56.1` (from `Network Information → Source Network Address` in raw event)
- Host: `DESKTOP-5TRJPSS`
- Logon Type: 3 (Network)
- Authentication Package: NTLM
- Failure Reason: Unknown user name or bad password
- Status: 0xC000006D / Sub Status: 0xC000006A

**Why this is suspicious:**
10 failed network logons against the same account from a single 
external IP within a short window is a classic brute force pattern. 
Legitimate users rarely fail authentication 10 times in rapid 
succession. Logon Type 3 (Network) and NTLM authentication confirm 
remote authentication attempts, not local logins.

**Note on source IP attribution:**
The source IP `192.168.56.1` is identified as the Kali attacker 
machine based on the lab architecture (Kali = attacker, Windows = victim).

---

## ⏱️ Timeline

| Time | Event | Source |
|---|---|---|
| 19:20:22.215 | Failed network logon attempt #1 for `varun` from 192.168.56.1 | Splunk event |
| 19:20:22.229 | Failed network logon attempt #2 | Splunk event |
| 19:20:22.240 | Failed network logon attempt #3 | Splunk event |
| 19:20:22.253 | Failed network logon attempt #4 (remaining 6 within same second) | Splunk event |

---

## 🎯 Indicators of Compromise (IOCs)

| Type | Value | Source |
|---|---|---|
| Target Account | `varun` | `Account_Name` field |
| Source IP | `192.168.56.1` | Network Information (raw XML) |
| Workstation Name | `\\192.168.56.1` | Network Information (raw XML) |
| Hostname | `DESKTOP-5TRJPSS` | `ComputerName` field |
| Logon Type | 3 (Network) | Logon Type |
| Auth Package | NTLM | Authentication Package |
| Failure Status | 0xC000006D | Status |
| Failure Sub Status | 0xC000006A | Sub Status |
| Failed Attempts | 10 | `stats count` |
| Windows Event | 4625 | `EventCode` field |

---

## ✅ Verdict

**True Positive** — Simulated attack in isolated lab environment.

In a real SOC environment, this would indicate:
- An attacker attempting to guess the `varun` account password 
  via network authentication
- Risk of lateral movement if successful

**Recommended Response Actions:**
1. Block source IP `192.168.56.1` at the firewall
2. Lock the `varun` account temporarily
3. Check for successful logins (4624) — was the attack successful?
4. Enforce account lockout policy
5. Restrict network logon access to specific hosts
6. Review all accounts for weak passwords

---

## 🛡️ MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Brute Force | T1110 |
| Credential Access | Brute Force: Password Guessing | T1110.001 |

---

## 💡 Lessons Learned

**What went well:**
- Detection rule correctly identified 10 failed logons
- EventCode 4625 provides rich detail (source IP, auth package, status codes)
- Raw XML contained the source IP that Splunk didn't extract as a field

**What could be improved:**
- Add time-window filter for faster alerting
- Correlate with successful logins (4624) — critical follow-up
- Splunk did not extract `Source Network Address` and `Workstation Name` 
  as fields — analysts must parse raw XML
- Build baseline of normal login patterns

**Analyst notes:**
Brute force attacks are noisy but effective. Always check whether 
the attack eventually succeeded:
`index=main EventCode=4624 Account_Name=varun`

**Lab observation:**
Hydra's SMB module required SMBv1 to be enabled on the Windows victim 
(SMBv2/v3 not supported by Hydra's SMB module). Failure status 
`0xC000006D` / Sub Status `0xC000006A` indicates bad password.

---

## 📸 Evidence

- Detection events: `../lab-setup/screenshots/10-bruteforce-events.png`
- Statistics: `../lab-setup/screenshots/11-bruteforce-rule.png`
