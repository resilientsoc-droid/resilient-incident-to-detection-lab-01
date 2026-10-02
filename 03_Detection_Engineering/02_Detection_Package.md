# Detection Package

**Project:** Incident-to-Detection — Sample Engagement
**Prepared by:** Resilient Cybersecurity
**Date:** 2026-09-29
**Classification:** Public — Training Lab (Controlled Simulation)

---

## 1. Detection Gap Analysis

Before building any rule, each technique from the incident (documented in the DFIR report) was reviewed to answer two questions: Is logging available? Is there an actual alert?

| Technique | MITRE ID | Logging Available? | Alert Before Project? | Gap |
|---|---|---|---|---|
| System Information Discovery | T1082 | ✅ Sysmon Event 1 | ❌ None | Visibility without detection |
| PowerShell Encoded Command | T1059.001 | ✅ Sysmon Event 1 + PowerShell 4104 | ❌ None | Visibility without detection |
| Scheduled Task Persistence | T1053.005 | ✅ Sysmon Event 1 + Security 4698 (after manually enabling Audit Policy) | ❌ None | Partial visibility (required enabling an additional setting) + no detection |

**Conclusion:** The monitoring infrastructure (Sysmon + Splunk) provided sufficient visibility to observe all three stages, but **there was no effective detection mechanism** prior to this project. Two rules were built for the two techniques with the highest behavioral detection value (T1059.001 and T1053.005), while T1082 was left without a dedicated rule in this cycle due to the high expected false-positive rate for any rule relying solely on `systeminfo.exe` invocation (a common, legitimate command). It is recommended to address it through a broader Baseline/UEBA strategy rather than a single signature-based rule.

---

## 2. DET-001 — PowerShell Encoded Command Execution

### SPL (Splunk)

```spl
index=sysmon EventCode=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| regex CommandLine="(?i)\s[-/–—]e[a-z]*\s+[A-Za-z0-9+/=]{20,}"
| eval RealUser=mvfilter(User!="NOT_TRANSLATED")
| table _time, host, RealUser, ParentImage, CommandLine
```

### Sigma Rule

```yaml
title: PowerShell Encoded Command Execution
id: 3f1a9c52-7d64-4b8e-a1c3-5e2b90d47a16
status: experimental
description: >
    Detects powershell.exe or pwsh.exe launched with an encoded command
    switch (-e, -enc, -EncodedCommand and any abbreviation) followed by a
    Base64-like payload. Built from a controlled Atomic Red Team replay
    of T1059.001 (Test 15) in an isolated lab.
date: 2026/09/28
references:
    - https://attack.mitre.org/techniques/T1059/001/
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    selection_cli:
        CommandLine|re: '(?i)\s[-/–—]e[a-z]*\s+[A-Za-z0-9+/=]{20,}'
    condition: selection_img and selection_cli
falsepositives:
    - Legitimate management tools (SCCM, Intune, monitoring agents) that pass encoded commands
level: medium
```

### Alert Logic

- **Trigger:** Number of Results > 0
- **Schedule:** Cron `*/5 * * * *` (every 5 minutes) — during the testing period. **In production, running every minute or via a Real-time Alert is recommended**, depending on data volume.
- **Window:** `earliest=-15m latest=now` (a moving window so events are not missed between runs). **Observed during validation:** because the window (15 min) is wider than the schedule (5 min), a single event matched on three consecutive runs and DET-001 fired three times. Use alert throttling or align the window with the schedule before production.

### Tuning Notes

- It was discovered that the `User` field in Sysmon events, as parsed by Splunk, sometimes holds two values (a Multivalue Field: `NOT_TRANSLATED` + the actual username), which can double the result count in any aggregate (`stats`/`count`). `mvfilter()` was used to isolate the real value only.
- The regex was broadened from a literal match of `-E` only to a general pattern (`[-/–—]e[a-z]*`) covering all accepted PowerShell abbreviations (`-e`, `-enc`, `-ec`, `-EncodedCommand`) as well as alternate forms using a forward slash or an em dash.

### False Positive Analysis

| Test | Result |
|---|---|
| Running the rule against the host's entire history (`index=sysmon ... stats count by Image, ParentImage`) | A single result only, matching the simulated event |

**⚠️ Explicit caveat:** This environment is a near-empty lab with no real users or enterprise management tools. **The absence of False Positives here is weak evidence.** In a real production environment, tools such as SCCM, Intune, and monitoring agents are expected to use `-EncodedCommand` legitimately. **Before production deployment:**
1. Run the rule in Monitor-Only mode for 1–2 weeks to establish a baseline.
2. Build an allowlist of known, legitimate parent processes (`ParentImage`).

---

## 3. DET-002 — Scheduled Task Created with Logon Trigger and Highest Privileges

### SPL (Splunk)

```spl
index=wineventlog EventCode=4698
| regex TaskContent="(?i)<LogonTrigger>"
| regex TaskContent="(?i)<RunLevel>HighestAvailable</RunLevel>"
| table _time, host, Subject_Account_Name, Task_Name, TaskContent
```

### Sigma Rule

```yaml
title: Scheduled Task Created with Logon Trigger and Highest Privileges
id: 8b2d47e1-5c9a-4f36-b0d8-1a7e63c9f254
status: experimental
description: >
    Detects creation of a scheduled task (Security Event 4698) that runs at
    user logon with the highest available privileges, a common persistence
    pattern. Built from a controlled Atomic Red Team replay of T1053.005
    (Test 4) in an isolated lab.
date: 2026/09/28
references:
    - https://attack.mitre.org/techniques/T1053/005/
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1053.005
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4698
    selection_trigger:
        TaskContent|contains: '<LogonTrigger>'
    selection_priv:
        TaskContent|contains: '<RunLevel>HighestAvailable</RunLevel>'
    condition: selection and selection_trigger and selection_priv
falsepositives:
    - Legitimate software installers and updaters that register logon tasks with elevated rights
level: medium
```

### Alert Logic

- **Trigger:** Number of Results > 0
- **Schedule:** Cron `*/5 * * * *` during the testing period
- **Window:** `earliest=-15m latest=now`

### Tuning Notes

- This detection requires enabling the **"Other Object Access Events"** Audit Subcategory (`auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable`), which is **not enabled by default** in Windows. This itself is an independent detection gap that must be documented during any client scoping.
- The detection logic relies on the **behavioral combination** (Logon Trigger + Highest Privileges), not the task name (`AtomicTask`) or executed command (`calc.exe`), both of which are trivial for a real attacker to change.

### False Positive Analysis

| Test | Result |
|---|---|
| `index=wineventlog EventCode=4698 | stats count by Task_Name, Subject_Account_Name` | A single result only (`\AtomicTask`) |

**⚠️ Explicit caveat:** The same caveat from DET-001 applies here even more strongly, since Audit Policy was only enabled for a few hours at test time. In a real production environment, legitimate installers (browsers, update tools) routinely create scheduled tasks with elevated privileges. **Before deployment:** build an allowlist of known, legitimate task names in the client's environment (Task Name Allowlist) by collecting a baseline over at least two weeks.

---

## 4. MITRE ATT&CK Mapping Summary

| Rule | Technique | Tactic |
|---|---|---|
| DET-001 | T1059.001 — PowerShell | Execution |
| DET-002 | T1053.005 — Scheduled Task | Persistence, Privilege Escalation |

(Full details in the attached MITRE ATT&CK Coverage Map.)

---
*End of Detection Package*
