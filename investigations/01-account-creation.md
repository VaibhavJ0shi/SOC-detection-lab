# Investigation #01 - Suspicious Account Creation

**Report ID :** INV-001 | **Date :** 2026-09-27 | **Analyst :** Vaibhav Joshi | **Severity :** Medium | **Status :** Closed - True Positive

---

## 🚨 Alert

**Detection Rule :** T1136_account_creation.spl

**Trigger :** 
 - EventCode 4720 - A user account was created
 - EventCode 4732 - Member added to 'Users' group
 - EventCode 4732 - Member added to 'Administrators' group

**Host :** Windows10-Victim (DESKTOP-5TRJPSS)

**Time :** 
 - Event 4720 : 2026-09-22 07:03:02 PM
 - Event 4732 (Users) : 2026-09-22 07:03:02 PM
 - Event 4732 (Administrators) : 2026-09-22 07:03:30 PM

---

# 🔍 Triage

**What Happened :**
A new local user account named 'hacker' was created on the windows 
victim machine by user 'varun', followed by addition to two groups
within 30 seconds :
1. 'Users' group (immediately at 19:03:02)
2. 'Administrators' group (at 19:03:30)

**Initial checks performed :**
 - Comfirmed the account creation in Splunk : 'index=main EventCode=4720'
 - New account created : 'hacker' (from "New Account" section of event)
 - Account creator : 'varun' (from "Subject" section of event)
 - Confirmed 2 group addition events (EventCode 4732) :
    - Group 'Users' (SID : S-1-5-32-545)
    - Group 'Administrators' (SID : S-1-5-32-544)
 - Both 4732 events showed 'Member → Account Name : -' (blank) - 
   only SID captured, not the resolved username

**SID correlation (Splunk-only methodology) :**
Since Splunk did not resolve the 'Member' account name in EventCode 4732, 
I correlated by SID : 
 - Query : "index-main S-1-5-21-4002199150-3237597154-3309285408-1002"
 - Result : 38 events - SID maps to 'hacker' (from 4720 event)
 - **Conclusion :** 'hacker' was the member added to both groups

**Why this is suspicious :**
The sequence - account creation followed by two group additions (including 'Administrators') 
within 30 seconds - is a classic persistence + privilege escalation pattern. Legitimate IT 
rarely creates a new admin account in such a short time. The name 'hacker' itself 
is a clear red flag.

**Correlation :**
Three events, when correlated togethere, confirm this as malicious :
1. **4720** - 'hacker' created by 'varun'
2. **4732** - 'hacker' (SID ...-1002) added to 'Users' group
3. **4732** - 'hacker' (SID ...-1002) added to 'Administrators' group

Individually, each event may appear benign. Together, they indicate privilege escalation.

---

## ⏱️ Timeline

| Time | Event | Source |
|---|---|---|
| 19:03:02 | EventCode 4720 - Account 'hacker' created by 'varun' | Splunk event |
| 19:03:02 | EventCode 4732 - 'hacker' added to 'Users' group | Splunk event |
| 19:03:30 | EventCode 4732 - 'hacker' added to 'Administrators' group | Splunk event |

---

## 🎯 Indicators of Compromise (IOCs)

| Type | Value | Source |
|---|---|---|
| New Account | 'hacker' | Event 4720 "New Account" Section |
| Account SID | `S-1-5-21-4002199150-3237597154-3309285408-1002` | Event 4720 + 4732 |
| Account Creator | 'varun' | Event "Subject" section |
| Hostname | 'DESKTOP-5TRJPSS' | 'ComputerName' field |
| Group | 'Users' (S-1-5-32-545) | Event 4732 "Group" section |
| Group | 'Administrators' (S-1-5-32-544) | Event 4732 "Group" section |
| Windows Event | 4720 (User Account Creation) | EventCode field |
| Windows Event | 4732 (Member Added to Local Group) | EventCode field |

---

## ✅ Verdict

**True Positive** - Simulated attack in isolated lab environment.

In a real SOC environment, this would indicate :
 - A compromised user account ('varun')
 - An attacker establishing persistence via a backdoor admin account
 - Privilege escalation to administrator level

**Recommended Response Actions :**
1. Immediately disable the 'hacker' account
2. Remove 'hacker' from the 'Administrators' group
3. Isolate the host from the network
4. Investigate how 'varun' credentials were compromised
5. Check for other persistence mechanisms (Run keys, scheduled tasks, services)
6. Reset credentials for all users on the host
7. Review authentication logs for the past 30 days

---

## 🛡️ MITRE ATT&CK Mapping

**What went well :**
 - Detection rule fired correctly on the first event
 - EventCode 4720 and 4732 are high-fidelity detection signals
 - Correlation of 3 events increased confidence sifnificantly
 - SID correlation successfully indentified the unresolved member

**Splunk field extraction limitations observed :**
 - EventCode 4732 showed 'Member → Account Name : -' (blank)
 - Only SID was captured - not the resolved username
 - 'fieldsummary' merged 'TargetUserName' and 'SubjectUserName' into a generic 
   'Account_Name' field

**Analyst methodology applied :**
 - Used raw event view ('_raw') to verify field values
 - Correlated by SID using Splunk search instead of assuming
 - Documented the extraction limitation in the report
 - Never relied on field names alone - verified every claim

**Analyst notes :**
Local account creation is often overlooked in enterprise envirenments. Attackers 
frequently create "shadow" accounts that blend in with legitimate ones. The combination 
of account creation + admin group addition within seconds is a classic persistence 
pattern. Additionally, Splunk's inability to resolve the 'Member' field highlights the 
importance of SID correlation in investigations.

---

## 📸 Evidence

 - Detection event : '../lab-setup/screenshots/08-first-detection-event.png'
 - Rule output : '../lab-setup/screenshots/09-detection-rule-output.png'
