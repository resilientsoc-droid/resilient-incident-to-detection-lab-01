# DFIR Investigation Report

**Project:** Incident-to-Detection — Sample Engagement
**Engagement Track:** Track B — Purple Team Detection Assessment (Controlled Simulation)
**Prepared by:** Resilient Cybersecurity
**Date:** 2026-09-29
**Classification:** Public — Training Lab (Controlled Simulation)
**Document version:** v1.0

> **Mandatory Notice:** This report documents a **Controlled Simulation** executed inside an isolated lab, with full knowledge and ownership by the analyst. **This is NOT a real security incident.** No part of this document is presented as an investigation of an actual breach.

---

## 1. Executive Summary

A three-stage attack behavior simulation (Discovery → Execution → Persistence) was executed on a single Windows 10 host within an isolated lab environment, using the Atomic Red Team framework. Full evidence was collected via Sysmon and Windows Event Logs forwarded to Splunk, a complete timeline of the executed behavior was reconstructed, and reusable IOCs and TTPs were extracted to build detection rules (documented in the attached Detection Package).

## 2. Scope

| Item | Details |
|---|---|
| Target Host | DESKTOP-DI2GMCC (Windows 10 Pro, build 19045) |
| Target IP | `192.168.x.x` (redacted; NAT network, VMware) |
| Environment | Isolated Lab — no production systems involved |
| Account Used | DESKTOP-DI2GMCC\SOC |
| Data Sources | Sysmon (Operational log), Windows Security log, Windows PowerShell Operational log |
| Simulation Tool | Invoke-AtomicTest (Atomic Red Team / Red Canary) |

## 3. Initial Access

**N/A.** This is a self-replay simulation started directly by the analyst from inside the host, and did not involve any real Initial Access step (no phishing, no exploit, no external access). This section would be the subject of actual investigation in any real Track A (Incident-Driven) engagement.

## 4. Timeline (Cairo time, UTC+2)

| # | Time | Source | Event | Parent Process |
|---|---|---|---|---|
| 1 | 2026-09-26 18:36:53 | Sysmon EID 1 | `cmd.exe /c systeminfo & reg query HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum` | powershell.exe |
| 2 | 2026-09-26 18:36:54 | Sysmon EID 1 | `systeminfo.exe` executed (T1082) | cmd.exe |
| 3 | 2026-09-26 18:36:56 | Sysmon EID 1 | `reg.exe query ...\Disk\Enum` executed | cmd.exe |
| 4 | 2026-09-26 19:39:07 | Sysmon EID 1 | `Out-ATHPowerShellCommandLineParameter` launched (simulation builder) | powershell.exe |
| 5 | 2026-09-26 19:39:30 | Sysmon EID 1 | `powershell.exe -NoProfile -E VwByAGkAdABlAC0A...` (T1059.001) | **WmiPrvSE.exe** |
| 6 | 2026-09-28 01:31:13 | Sysmon EID 1 | `AtomicTask` created — first attempt (before Audit Policy enabled) | powershell.exe |
| 7 | 2026-09-28 01:39:49 | Sysmon EID 1 | `AtomicTask` created — second attempt (after Audit Policy enabled) | powershell.exe |
| 8 | 2026-09-28 01:39:50 | Security EID 4698 | Official record of `\AtomicTask` scheduled task creation (T1053.005) | — |

**Timing note:** Sysmon's `UtcTime` field is recorded in UTC, while Splunk displays time in Cairo time (UTC+2) per server configuration. All times in this table have been normalized to Cairo time for consistency.

## 5. Processes Analysis

The governing process in the simulation is `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (version 10.0.19041.3996), hash:
`SHA256=9785001B0DCF755EDDB8AF294A373C0B87B2498660F724E76C4D53F9C217C7A3`

This is the original Microsoft PowerShell binary (not a malicious file); the suspicious behavior was in **how it was used** (Encoded Command via WMI), not the file itself.

**Important technical note:** The parent process of the critical event (row 5 in the Timeline) was `WmiPrvSE.exe`, not `powershell.exe` or `explorer.exe` — a pattern commonly used by attackers to execute commands via WMI rather than launching them directly from an interactive shell, making visual correlation to a user session harder.

## 6. PowerShell & Command Line

| Full Command | Purpose |
|---|---|
| `cmd.exe /c systeminfo & reg query HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum` | System and disk information gathering (Discovery) |
| `powershell.exe -NoProfile -E VwByAGkAdABlAC0ASABvAHMAdAAg...` | Execution of a Base64-encoded command (Defense Evasion / Execution) |
| `"powershell.exe" & {$Action = New-ScheduledTaskAction -Execute "calc.exe"; ... Register-ScheduledTask AtomicTask -InputObject $object}` | Creation of a Persistence mechanism via Scheduled Task |

Decoding the Base64 payload in the second command reveals benign content (a `Write-Host` statement with a test GUID), since the purpose of this specific simulation is to test the **execution pattern** (Encoded Command Switch), not deliver an actual malicious payload.

## 7. Accounts

| Account | Notes |
|---|---|
| `DESKTOP-DI2GMCC\SOC` | The account used to execute all three stages. Runs at `IntegrityLevel: High`. Account privileges were not analyzed at an Active Directory level, as the host is in a `WORKGROUP`, not a Domain. |

**Out of Scope:** There is no Active Directory environment in this lab, so privilege relationships between accounts (Privilege Escalation Paths) or other accounts were not analyzed. This item requires a real AD environment to be fully executed.

## 8. IPs / Domains / Hashes

**IPs / Domains:** **N/A.** The scenario did not involve any external network connection (no C2, no internet download except for the simulation tools themselves, retrieved from well-known official GitHub sources prior to the simulation).

**Relevant Hashes:**

| File | SHA256 |
|---|---|
| powershell.exe | `9785001B0DCF755EDDB8AF294A373C0B87B2498660F724E76C4D53F9C217C7A3` |
| systeminfo.exe | (not recorded in the original event — its Event 1 did not include a Hash field) |

**Note:** These hashes belong to original, signed Windows binaries and are not Indicators of Compromise by themselves. They are listed here for documentation purposes only.

## 9. Persistence

One persistence mechanism was observed: a **Scheduled Task** named `\AtomicTask`, including:
- `LogonTrigger`: fires on every user logon
- `RunLevel: HighestAvailable`
- `GroupId: S-1-5-32-544` (BUILTIN\Administrators group)
- `Action: calc.exe` (in a real production environment, an attacker would replace this with their actual payload)

The task was fully documented via Security Event 4698 (full XML content available in the digital evidence).

## 10. Lateral Movement

**N/A.** The scenario involves a single host (`DESKTOP-DI2GMCC`); there is no multi-device network in this lab. No lateral movement attempt was observed or tested.

## 11. Windows Event Logs

Three primary sources were relied upon:
- **Sysmon Operational Log** (Event ID 1: Process Creation) — the primary source for tracking the process chain.
- **Security Log** (Event ID 4698: Scheduled Task Created) — required manually enabling the `Other Object Access Events` Audit Subcategory, which was not enabled by default.
- **Microsoft-Windows-PowerShell/Operational** (Event ID 4103/4104: Script Block Logging) — available as a supplementary source.

## 12. Disk / Memory Forensics

**❌ Out of scope for this lab.** No disk image or memory dump was collected in this simulation. The technical environment includes a pre-installed `FTK Imager` tool ready for this purpose, but it was not used within the scope of this specific engagement. It is recommended to include this item in any future simulation or investigation requiring deeper memory analysis.

## 13. Root Cause

**Root Cause:** Deliberate self-replay execution by the analyst using Atomic Red Team from the `SOC` account at `High Integrity`, aimed at generating realistic data to test the monitoring environment's (Sysmon + Splunk) detection capability.

There is no "breach" in the traditional sense — no Initial Access occurred from an external party. In a real investigation (Track A), this section would be replaced with identification of the actual entry point and the vulnerability or human error that allowed it.

## 14. IOCs & TTPs

| TTP | MITRE ID | Reuse Note |
|---|---|---|
| System Information Discovery | T1082 | `cmd.exe /c systeminfo & reg query` — a behavioral pattern, stronger than any single named IOC |
| PowerShell Encoded Command | T1059.001 | Any `-e`/`-enc`/`-EncodedCommand` followed by a long Base64 string, especially when the parent process is `WmiPrvSE.exe` |
| Scheduled Task Persistence | T1053.005 | The combination of `LogonTrigger` + `RunLevel: HighestAvailable` in Event 4698 |

**Explicit note:** File and task names (`AtomicTask`, `calc.exe`) are **weak** IOCs easily changed by any attacker. The actual detection rules (see Detection Package) relied on **behavior (Behavioral TTPs)**, not names.

## 15. Impact

There is no actual impact on real data or systems, given that this is an isolated lab. In a real commercial context (Track A), this section would be replaced with an actual damage assessment (affected data, dwell time, compromised systems).

## 16. Remediation Plan

1. Permanently enable `Audit: Other Object Access Events` on all endpoints to ensure Event 4698 is logged.
2. Periodically review newly registered Scheduled Tasks, especially those with `RunLevel: HighestAvailable`.
3. Deploy the detection rules documented in the attached Detection Package to the production environment.
4. Enable PowerShell Script Block Logging (Event 4104) on all machines as a supplementary investigation source.

---
*End of DFIR Investigation Report*
