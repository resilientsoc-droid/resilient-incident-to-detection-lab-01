# Incident Timeline

**Project:** Incident-to-Detection — Sample Engagement
**Host:** DESKTOP-DI2GMCC
**Time zone:** Cairo time (UTC+2) unless noted otherwise

---

| # | Time | Source | Event | Parent Process | MITRE Technique |
|---|---|---|---|---|---|
| 1 | 2026-09-26 18:36:53 | Sysmon EID 1 | `cmd.exe /c systeminfo & reg query HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum` | powershell.exe | T1082 |
| 2 | 2026-09-26 18:36:54 | Sysmon EID 1 | `systeminfo.exe` executed | cmd.exe | T1082 |
| 3 | 2026-09-26 18:36:56 | Sysmon EID 1 | `reg.exe query ...\Disk\Enum` executed | cmd.exe | T1082 |
| 4 | 2026-09-26 19:39:07 | Sysmon EID 1 | `Out-ATHPowerShellCommandLineParameter` launched (simulation builder) | powershell.exe | T1059.001 |
| 5 | 2026-09-26 19:39:30 | Sysmon EID 1 | `powershell.exe -NoProfile -E VwByAGkAdABlAC0A...` | **WmiPrvSE.exe** | T1059.001 |
| 6 | 2026-09-28 01:31:13 | Sysmon EID 1 | `AtomicTask` created — first attempt (before Audit Policy enabled) | powershell.exe | T1053.005 |
| 7 | 2026-09-28 01:39:49 | Sysmon EID 1 | `AtomicTask` created — second attempt (after Audit Policy enabled) | powershell.exe | T1053.005 |
| 8 | 2026-09-28 01:39:50 | Security EID 4698 | Official record of `\AtomicTask` scheduled task creation | — | T1053.005 |
| 9 | 2026-09-29 01:43:55 | Sysmon EID 1 | **Validation Replay** — T1059.001-15 re-executed | WmiPrvSE.exe | T1059.001 |
| 10 | 2026-09-29 01:45:03 | Splunk Alert | DET-001 fired, matched event #9 | — | T1059.001 |
| 11 | 2026-09-29 ~01:5x | Sysmon EID 1 | **Validation Replay** — T1053.005-4 re-executed | powershell.exe | T1053.005 |
| 12 | 2026-09-29 02:05:02 | Splunk Alert | DET-002 fired, matched event #11 | — | T1053.005 |

**Note:** Rows 1–8 constitute Phase 1 (DFIR) and Phase 2 build data. Rows 9–12 constitute the Phase 3 (Validation) replay and detection evidence.

---
*End of Timeline*
